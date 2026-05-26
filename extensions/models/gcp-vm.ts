// extensions/models/gcp-vm.ts
// Manages GCP Compute Engine VM instances via the gcloud CLI.
// Mirrors the @leeehinman/multipass interface so elastic-stack, elastic-agent,
// and spigot models work unchanged: ipv4[0] is the external IP used for both
// SSH access and inter-service URLs.
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  name: z.string().describe(
    "GCE instance name. Must be lowercase letters, numbers, or hyphens.",
  ),
  zone: z.string().default("us-central1-a").describe(
    "GCP zone, e.g. 'us-central1-a'.",
  ),
  project: z.string().describe("GCP project ID."),
  sshAuthorizedKeys: z.array(z.string()).optional().describe(
    "SSH public keys to inject via instance metadata for the ubuntu user.",
  ),
});

const InstanceSchema = z.object({
  name: z.string(),
  status: z.string(),
  ipv4: z.array(z.string()).describe(
    "External IP(s) — matches multipass attribute shape for CEL compatibility.",
  ),
  internalIp: z.string().optional(),
  zone: z.string(),
  machineType: z.string(),
  syncedAt: z.string(),
});

const CreateArgsSchema = z.object({
  machineType: z.string().default("e2-standard-2").describe(
    "GCE machine type, e.g. 'e2-standard-2', 'n2-standard-4'.",
  ),
  diskSizeGb: z.number().int().min(10).default(20).describe(
    "Boot disk size in GB.",
  ),
  image: z.string().default("ubuntu-2204-lts").describe(
    "Image family, e.g. 'ubuntu-2204-lts', 'ubuntu-2404-lts-amd64'.",
  ),
  imageProject: z.string().default("ubuntu-os-cloud").describe(
    "GCP project hosting the image family.",
  ),
  networkTags: z.array(z.string()).optional().describe(
    "Network tags for firewall rule targeting, e.g. ['elastic-stack'].",
  ),
});

const StopArgsSchema = z.object({
  force: z.boolean().optional().describe(
    "No-op — included for interface parity with multipass.",
  ),
});

// ---------------------------------------------------------------------------
// Injectable types (exported for unit tests)
// ---------------------------------------------------------------------------

export type RunGcloudFn = (
  args: string[],
) => Promise<{ stdout: string; stderr: string; success: boolean }>;

export type ExecuteDeps = {
  runGcloud?: RunGcloudFn;
};

// ---------------------------------------------------------------------------
// gcloud helper (module-level default, overridden in tests via _deps)
// ---------------------------------------------------------------------------

async function defaultRunGcloud(
  args: string[],
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command("gcloud", {
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

export async function fetchInstanceInfo(
  name: string,
  zone: string,
  project: string,
  runGcloud: RunGcloudFn = defaultRunGcloud,
): Promise<z.infer<typeof InstanceSchema>> {
  const { stdout, stderr, success } = await runGcloud([
    "compute", "instances", "describe", name,
    `--zone=${zone}`,
    `--project=${project}`,
    "--format=json",
  ]);
  if (!success) throw new Error(`gcloud describe failed for "${name}": ${stderr}`);

  let info: Record<string, unknown>;
  try {
    info = JSON.parse(stdout);
  } catch {
    throw new Error(
      `gcloud describe returned non-JSON for "${name}": ${stdout.slice(0, 200)}`,
    );
  }

  const networkIface = (info.networkInterfaces as Record<string, unknown>[])?.[0] ?? {};
  const internalIp = (networkIface.networkIP as string) ?? "";
  const accessConfigs = (networkIface.accessConfigs as Record<string, unknown>[])?.[0] ?? {};
  const externalIp = (accessConfigs.natIP as string) ?? "";
  const machineType = ((info.machineType as string) ?? "").split("/").pop() ?? "";
  const zoneName = ((info.zone as string) ?? zone).split("/").pop() ?? zone;

  return {
    name,
    status: (info.status as string) ?? "UNKNOWN",
    // Populate ipv4 with external IP so data.latest().attributes.ipv4[0] CEL
    // expressions work for SSH and service URLs without modification.
    ipv4: externalIp ? [externalIp] : (internalIp ? [internalIp] : []),
    internalIp: internalIp || undefined,
    zone: zoneName,
    machineType,
    syncedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

export const model = {
  type: "@leeehinman/gcp-vm",
  version: "2026.05.21.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    instance: {
      description: "State of the GCE VM instance",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description:
        "Create and start a new GCE VM instance. Idempotent — if the instance " +
        "already exists, syncs and returns current state. Requires firewall rules " +
        "allowing SSH (22) and any inter-service ports (9200, 5601, 8220) to be " +
        "pre-configured on the target network tags.",
      arguments: CreateArgsSchema,
      execute: async (args: { _deps?: ExecuteDeps } & Record<string, unknown>, context) => {
        const runGcloud = args._deps?.runGcloud ?? defaultRunGcloud;
        const { name, zone, project, sshAuthorizedKeys } = context.globalArgs;
        const typedArgs = CreateArgsSchema.parse(args);

        const sshMetadata = sshAuthorizedKeys?.length
          ? sshAuthorizedKeys.map((k) => `ubuntu:${k}`).join("\n")
          : undefined;

        const createArgs = [
          "compute", "instances", "create", name,
          `--zone=${zone}`,
          `--project=${project}`,
          `--machine-type=${typedArgs.machineType}`,
          `--boot-disk-size=${typedArgs.diskSizeGb}GB`,
          `--image-family=${typedArgs.image}`,
          `--image-project=${typedArgs.imageProject}`,
          "--format=json",
        ];

        if (sshMetadata) createArgs.push(`--metadata=ssh-keys=${sshMetadata}`);
        if (typedArgs.networkTags?.length) {
          createArgs.push(`--tags=${typedArgs.networkTags.join(",")}`);
        }

        context.logger.info(
          "Creating GCE instance {name} in {zone} ({machineType}, {disk}GB)",
          { name, zone, machineType: typedArgs.machineType, disk: typedArgs.diskSizeGb },
        );

        const { stderr, success } = await runGcloud(createArgs);

        if (!success) {
          if (stderr.toLowerCase().includes("already exists")) {
            context.logger.info(
              "Instance {name} already exists, returning current state",
              { name },
            );
            const existing = await fetchInstanceInfo(name, zone, project, runGcloud);
            const handle = await context.writeResource("instance", name, existing);
            return { dataHandles: [handle] };
          }
          throw new Error(`gcloud create failed for "${name}": ${stderr}`);
        }

        const data = await fetchInstanceInfo(name, zone, project, runGcloud);
        context.logger.info(
          "Instance {name} created, status={status}, ip={ip}",
          { name, status: data.status, ip: data.ipv4[0] ?? "(none)" },
        );

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description: "Refresh stored state from the live GCE instance.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context) => {
        const runGcloud = args._deps?.runGcloud ?? defaultRunGcloud;
        const { name, zone, project } = context.globalArgs;

        context.logger.info("Syncing state for instance {name}", { name });
        const data = await fetchInstanceInfo(name, zone, project, runGcloud);
        context.logger.info(
          "Synced instance {name}, status={status}",
          { name, status: data.status },
        );

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    start: {
      description: "Start a stopped GCE VM instance.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context) => {
        const runGcloud = args._deps?.runGcloud ?? defaultRunGcloud;
        const { name, zone, project } = context.globalArgs;

        context.logger.info("Starting instance {name}", { name });
        const { stderr, success } = await runGcloud([
          "compute", "instances", "start", name,
          `--zone=${zone}`,
          `--project=${project}`,
        ]);
        if (!success) throw new Error(`gcloud start failed for "${name}": ${stderr}`);

        const data = await fetchInstanceInfo(name, zone, project, runGcloud);
        context.logger.info(
          "Instance {name} started, status={status}",
          { name, status: data.status },
        );
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    stop: {
      description: "Stop a running GCE VM instance.",
      arguments: StopArgsSchema,
      execute: async (args: { _deps?: ExecuteDeps }, context) => {
        const runGcloud = args._deps?.runGcloud ?? defaultRunGcloud;
        const { name, zone, project } = context.globalArgs;

        context.logger.info("Stopping instance {name}", { name });
        const { stderr, success } = await runGcloud([
          "compute", "instances", "stop", name,
          `--zone=${zone}`,
          `--project=${project}`,
        ]);
        if (!success) throw new Error(`gcloud stop failed for "${name}": ${stderr}`);

        const data = await fetchInstanceInfo(name, zone, project, runGcloud);
        context.logger.info(
          "Instance {name} stopped, status={status}",
          { name, status: data.status },
        );
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    delete: {
      description: "Delete a GCE VM instance.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context) => {
        const runGcloud = args._deps?.runGcloud ?? defaultRunGcloud;
        const { name, zone, project } = context.globalArgs;

        context.logger.info("Deleting instance {name}", { name });
        const { stderr, success } = await runGcloud([
          "compute", "instances", "delete", name,
          `--zone=${zone}`,
          `--project=${project}`,
          "--quiet",
        ]);

        if (!success) {
          const alreadyGone =
            stderr.toLowerCase().includes("was not found") ||
            stderr.toLowerCase().includes("does not exist");
          if (!alreadyGone) {
            throw new Error(`gcloud delete failed for "${name}": ${stderr}`);
          }
          context.logger.info(
            "Instance {name} was already gone, treating as success",
            { name },
          );
          return { dataHandles: [] };
        }

        context.logger.info("Instance {name} deleted", { name });
        return { dataHandles: [] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgsSchema>;
