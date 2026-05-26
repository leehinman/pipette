// extensions/models/libvirt-vm.ts
// Manages Linux virtual machines via libvirt (virsh + KVM).
// Mirrors the @leeehinman/multipass interface so elastic-stack, elastic-agent,
// and spigot models work unchanged: ipv4[0] is the VM address used for SSH.
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing";

const GlobalArgsSchema = z.object({
  name: z.string().describe(
    "Name for the libvirt domain. Must be unique on the hypervisor.",
  ),
  baseImage: z.string().describe(
    "Path to a Linux cloud image (qcow2/img) used as the backing store for new VM disks. " +
      "Must be a cloud-init compatible image. " +
      "E.g. '/var/lib/libvirt/images/ubuntu-24.04-server-cloudimg-amd64.img' or " +
      "'/var/lib/libvirt/images/OL8U10_x86_64-kvm-b271.qcow2'.",
  ),
  uri: z.string().default("qemu:///system").describe(
    "Libvirt connection URI. Defaults to qemu:///system.",
  ),
  network: z.string().default("default").describe(
    "Libvirt network name for the VM NIC. Defaults to 'default'.",
  ),
  imageDir: z.string().default("/var/lib/libvirt/images").describe(
    "Directory where VM disk images are stored.",
  ),
  sshUser: z.string().default("ubuntu").describe(
    "Default SSH username for the image. Ubuntu cloud images use 'ubuntu'; " +
      "Oracle Linux cloud images use 'cloud-user'. " +
      "Stored in instance data so consuming models can reference it via CEL.",
  ),
  sshAuthorizedKeys: z.array(z.string()).optional().describe(
    "SSH public keys to inject via cloud-init on first boot.",
  ),
});

const InstanceSchema = z.object({
  name: z.string(),
  state: z.string(),
  ipv4: z.array(z.string()),
  cpuCount: z.string(),
  memoryTotal: z.number(),
  diskPath: z.string(),
  sshUser: z.string(),
  syncedAt: z.string(),
});

type InstanceData = z.infer<typeof InstanceSchema>;

async function runVirsh(
  uri: string,
  args: string[],
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command("virsh", {
    args: ["-c", uri, ...args],
    stdout: "piped",
    stderr: "piped",
  });
  const result = await cmd.output();
  return {
    stdout: new TextDecoder().decode(result.stdout).trim(),
    stderr: new TextDecoder().decode(result.stderr).trim(),
    success: result.success,
  };
}

async function runCommand(
  command: string,
  args: string[],
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command(command, {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const result = await cmd.output();
  return {
    stdout: new TextDecoder().decode(result.stdout).trim(),
    stderr: new TextDecoder().decode(result.stderr).trim(),
    success: result.success,
  };
}

async function getDomainIPs(uri: string, name: string): Promise<string[]> {
  const { stdout, success } = await runVirsh(uri, [
    "domifaddr",
    name,
    "--source",
    "lease",
  ]);
  if (!success) return [];

  const ips: string[] = [];
  for (const line of stdout.split("\n")) {
    // Output format: vnet0  52:54:00:xx:xx:xx  ipv4  192.168.122.100/24
    const match = line.match(/\s+ipv4\s+(\d+\.\d+\.\d+\.\d+)/);
    if (match) ips.push(match[1]);
  }
  return ips;
}

async function fetchInstanceInfo(
  uri: string,
  name: string,
  diskPath: string,
  sshUser: string,
): Promise<InstanceData> {
  const { stdout, stderr, success } = await runVirsh(uri, ["dominfo", name]);
  if (!success) {
    throw new Error(`virsh dominfo failed for "${name}": ${stderr}`);
  }

  let state = "unknown";
  let cpuCount = "0";
  let memoryKiB = 0;

  for (const line of stdout.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const val = line.slice(colonIdx + 1).trim();
    if (key === "State") state = val;
    else if (key === "CPU(s)") cpuCount = val;
    else if (key === "Max memory") memoryKiB = parseInt(val, 10);
  }

  const ipv4 = await getDomainIPs(uri, name);

  return {
    name,
    state,
    ipv4,
    cpuCount,
    memoryTotal: memoryKiB * 1024,
    diskPath,
    sshUser,
    syncedAt: new Date().toISOString(),
  };
}

/** Parse memory string like "2G" or "512M" into MiB. */
function parseMemoryMiB(s: string): number {
  const m = s.match(/^(\d+(?:\.\d+)?)\s*([GM]?)$/i);
  if (!m) throw new Error(`Cannot parse memory spec: "${s}"`);
  const n = parseFloat(m[1]);
  return m[2].toUpperCase() === "G" ? Math.round(n * 1024) : Math.round(n);
}

/** Poll for DHCP IP assignment with a timeout. */
async function waitForIp(
  uri: string,
  name: string,
  timeoutMs: number,
  logger: { info: (msg: string, ctx?: Record<string, unknown>) => void },
): Promise<string[]> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ips = await getDomainIPs(uri, name);
    if (ips.length > 0) return ips;
    logger.info("Waiting for IP assignment for {name}...", { name });
    await new Promise((r) => setTimeout(r, 5000));
  }
  logger.info("Timed out waiting for IP on {name}", { name });
  return [];
}

const LaunchArgsSchema = z.object({
  cpus: z.number().int().min(1).default(1).describe(
    "Number of vCPUs to allocate (default 1)",
  ),
  memory: z.string().default("1G").describe(
    "Memory to allocate, e.g. '2G', '512M' (default 1G)",
  ),
  disk: z.string().default("5G").describe(
    "Disk size to allocate, e.g. '10G' (default 5G)",
  ),
  cloudInit: z.string().optional().describe(
    "Path to a cloud-init user-data file to apply on first boot",
  ),
  waitForIpSeconds: z.number().int().default(120).describe(
    "Seconds to wait for the VM to acquire a DHCP IP address (default 120)",
  ),
});

const StopArgsSchema = z.object({
  force: z.boolean().optional().describe(
    "Force immediate shutdown via virsh destroy (may corrupt in-flight writes)",
  ),
});

const DeleteArgsSchema = z.object({
  purge: z.boolean().optional().describe(
    "Remove all storage associated with the domain (default true)",
  ),
});

export const model = {
  type: "@leeehinman/libvirt-vm",
  version: "2026.05.26.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    instance: {
      description: "State of the libvirt VM domain",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    launch: {
      description:
        "Create and start a new libvirt VM from a cloud image. " +
        "Idempotent — if the domain already exists, syncs and returns current state.",
      arguments: LaunchArgsSchema,
      execute: async (args, context) => {
        const { name, uri, network, imageDir, baseImage, sshUser, sshAuthorizedKeys } =
          context.globalArgs;
        const typedArgs = LaunchArgsSchema.parse(args);
        const diskPath = `${imageDir}/${name}.qcow2`;
        const seedIso = `${imageDir}/${name}-seed.iso`;

        // Idempotent: return existing state if domain already defined
        const { success: domainExists } = await runVirsh(uri, [
          "domstate",
          name,
        ]);
        if (domainExists) {
          context.logger.info(
            "Domain {name} already exists, returning current state",
            { name },
          );
          const existing = await fetchInstanceInfo(uri, name, diskPath, sshUser);
          const handle = await context.writeResource("instance", name, existing);
          return { dataHandles: [handle] };
        }

        const memMiB = parseMemoryMiB(typedArgs.memory);

        // Create a qcow2 disk backed by the base cloud image
        context.logger.info(
          "Creating disk {disk} backed by {image}",
          { disk: diskPath, image: baseImage },
        );
        const { stderr: createErr, success: createOk } = await runCommand(
          "qemu-img",
          ["create", "-F", "qcow2", "-b", baseImage, "-f", "qcow2", diskPath],
        );
        if (!createOk) {
          throw new Error(`qemu-img create failed: ${createErr}`);
        }

        const { stderr: resizeErr, success: resizeOk } = await runCommand(
          "qemu-img",
          ["resize", diskPath, typedArgs.disk],
        );
        if (!resizeOk) {
          context.logger.info("qemu-img resize warning: {err}", { err: resizeErr });
        }

        // Build cloud-init user-data
        let userDataContent: string;
        if (typedArgs.cloudInit) {
          userDataContent = await Deno.readTextFile(typedArgs.cloudInit);
        } else {
          const lines = ["#cloud-config", "ssh_authorized_keys:"];
          for (const key of sshAuthorizedKeys ?? []) lines.push(`  - ${key}`);
          userDataContent = lines.join("\n") + "\n";
        }

        // Write user-data and meta-data to temp files then build a nocloud ISO
        const tmpDir = await Deno.makeTempDir();
        const userDataPath = `${tmpDir}/user-data`;
        const metaDataPath = `${tmpDir}/meta-data`;
        try {
          await Deno.writeTextFile(userDataPath, userDataContent);
          await Deno.writeTextFile(
            metaDataPath,
            `instance-id: ${name}\nlocal-hostname: ${name}\n`,
          );
          const { stderr: isoErr, success: isoOk } = await runCommand(
            "mkisofs",
            [
              "-output", seedIso,
              "-volid", "cidata",
              "-joliet",
              "-rock",
              userDataPath,
              metaDataPath,
            ],
          );
          if (!isoOk) {
            throw new Error(`mkisofs failed for "${name}": ${isoErr}`);
          }
        } finally {
          await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
        }

        // Build domain XML and define + start — avoids virt-install storage pool races
        const xml = `
<domain type='kvm'>
  <name>${name}</name>
  <memory unit='MiB'>${memMiB}</memory>
  <vcpu>${typedArgs.cpus}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/></features>
  <cpu mode='host-model'/>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${diskPath}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${seedIso}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='${network}'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'><target type='isa-serial' port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>`;

        const xmlPath = await Deno.makeTempFile({ suffix: ".xml" });
        try {
          await Deno.writeTextFile(xmlPath, xml);

          context.logger.info(
            "Defining domain {name} ({cpus} vCPUs, {mem}MiB, {disk})",
            { name, cpus: typedArgs.cpus, mem: memMiB, disk: typedArgs.disk },
          );
          const { stderr: defErr, success: defOk } = await runVirsh(uri, [
            "define", xmlPath,
          ]);
          if (!defOk) {
            await runCommand("rm", ["-f", diskPath, seedIso]);
            throw new Error(`virsh define failed for "${name}": ${defErr}`);
          }
        } finally {
          await Deno.remove(xmlPath).catch(() => {});
        }

        const { stderr: startErr, success: startOk } = await runVirsh(uri, [
          "start", name,
        ]);
        if (!startOk) {
          throw new Error(`virsh start failed for "${name}": ${startErr}`);
        }

        context.logger.info(
          "Waiting for {name} to acquire an IP address",
          { name },
        );
        const ipv4 = await waitForIp(
          uri,
          name,
          typedArgs.waitForIpSeconds * 1000,
          context.logger,
        );

        const data = await fetchInstanceInfo(uri, name, diskPath, sshUser);
        if (ipv4.length > 0) data.ipv4 = ipv4;

        context.logger.info(
          "Domain {name} launched, state={state}, ip={ip}",
          { name, state: data.state, ip: data.ipv4[0] ?? "(pending)" },
        );

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description: "Refresh stored state from the live libvirt domain",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name, uri, imageDir, sshUser } = context.globalArgs;
        const diskPath = `${imageDir}/${name}.qcow2`;

        context.logger.info("Syncing state for domain {name}", { name });
        const data = await fetchInstanceInfo(uri, name, diskPath, sshUser);
        context.logger.info("Synced domain {name}, state={state}", {
          name,
          state: data.state,
        });

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    start: {
      description: "Start a stopped libvirt VM domain",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name, uri, imageDir, sshUser } = context.globalArgs;
        const diskPath = `${imageDir}/${name}.qcow2`;

        context.logger.info("Starting domain {name}", { name });
        const { stderr, success } = await runVirsh(uri, ["start", name]);
        if (!success) {
          const alreadyRunning = stderr.toLowerCase().includes("already active");
          if (!alreadyRunning) {
            throw new Error(`virsh start failed for "${name}": ${stderr}`);
          }
        }

        const data = await fetchInstanceInfo(uri, name, diskPath, sshUser);
        context.logger.info("Domain {name} started, state={state}", {
          name,
          state: data.state,
        });
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    stop: {
      description: "Stop a running libvirt VM domain",
      arguments: StopArgsSchema,
      execute: async (args, context) => {
        const { name, uri, imageDir, sshUser } = context.globalArgs;
        const diskPath = `${imageDir}/${name}.qcow2`;
        const typedArgs = StopArgsSchema.parse(args);

        context.logger.info("Stopping domain {name} (force={force})", {
          name,
          force: typedArgs.force ?? false,
        });

        // virsh shutdown asks the OS to halt gracefully; virsh destroy is immediate
        const virshCmd = typedArgs.force ? "destroy" : "shutdown";
        const { stderr, success } = await runVirsh(uri, [virshCmd, name]);
        if (!success) {
          const alreadyStopped =
            stderr.toLowerCase().includes("not running") ||
            stderr.toLowerCase().includes("already shut off");
          if (!alreadyStopped) {
            throw new Error(
              `virsh ${virshCmd} failed for "${name}": ${stderr}`,
            );
          }
        }

        const data = await fetchInstanceInfo(uri, name, diskPath, sshUser);
        context.logger.info("Domain {name} stopped, state={state}", {
          name,
          state: data.state,
        });
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    delete: {
      description:
        "Delete a libvirt VM domain and (by default) its disk image",
      arguments: DeleteArgsSchema,
      execute: async (args, context) => {
        const { name, uri, imageDir } = context.globalArgs;
        const typedArgs = DeleteArgsSchema.parse(args);
        const seedIso = `${imageDir}/${name}-seed.iso`;

        // Force stop if running — undefine requires the domain to be shut off
        const { stdout: stateOut } = await runVirsh(uri, ["domstate", name]);
        if (stateOut.trim() === "running") {
          context.logger.info("Force stopping {name} before delete", { name });
          await runVirsh(uri, ["destroy", name]);
        }

        const undefineArgs = ["undefine", name];
        if (typedArgs.purge !== false) {
          undefineArgs.push("--remove-all-storage");
        }

        context.logger.info("Deleting domain {name}", { name });
        const { stderr, success } = await runVirsh(uri, undefineArgs);

        if (!success) {
          const alreadyGone =
            stderr.toLowerCase().includes("failed to get domain") ||
            stderr.toLowerCase().includes("domain not found") ||
            stderr.toLowerCase().includes("no domain");
          if (!alreadyGone) {
            throw new Error(`virsh undefine failed for "${name}": ${stderr}`);
          }
          context.logger.info("Domain {name} was already gone", { name });
        } else {
          context.logger.info("Domain {name} deleted", { name });
        }

        // Seed ISO is not tracked by libvirt storage — remove it manually
        await runCommand("rm", ["-f", seedIso]);

        return { dataHandles: [] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgsSchema>;
