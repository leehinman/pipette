// extensions/models/multipass.ts
// Manages Ubuntu virtual machines via the multipass CLI.
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing";

const GlobalArgsSchema = z.object({
  name: z.string().describe(
    "Name for the multipass instance. Must start with a letter and contain only letters, numbers, or hyphens.",
  ),
});

const InstanceSchema = z.object({
  name: z.string(),
  state: z.string(),
  ipv4: z.array(z.string()),
  imageRelease: z.string(),
  imageHash: z.string(),
  cpuCount: z.string(),
  memoryTotal: z.number(),
  diskTotal: z.number(),
  release: z.string(),
  syncedAt: z.string(),
});

type InstanceData = z.infer<typeof InstanceSchema>;

/** Run a multipass command and return stdout, throwing on failure. */
async function runMultipass(
  args: string[],
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command("multipass", {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const result = await cmd.output();
  const stdout = new TextDecoder().decode(result.stdout).trim();
  const stderr = new TextDecoder().decode(result.stderr).trim();
  return { stdout, stderr, success: result.success };
}

/** Fetch live info for the named instance and return parsed InstanceData. */
async function fetchInstanceInfo(name: string): Promise<InstanceData> {
  const { stdout, stderr, success } = await runMultipass([
    "info",
    "--format",
    "json",
    name,
  ]);
  if (!success) {
    throw new Error(`multipass info failed for "${name}": ${stderr}`);
  }
  const parsed = JSON.parse(stdout);
  const info = parsed.info?.[name];
  if (!info) {
    throw new Error(`No info returned for instance "${name}"`);
  }
  return {
    name,
    state: info.state ?? "Unknown",
    ipv4: info.ipv4 ?? [],
    imageRelease: info.image_release ?? "",
    imageHash: info.image_hash ?? "",
    cpuCount: info.cpu_count ?? "0",
    memoryTotal: info.memory?.total ?? 0,
    diskTotal: Number(info.disks?.["sda1"]?.total ?? 0),
    release: info.release ?? "",
    syncedAt: new Date().toISOString(),
  };
}

const LaunchArgsSchema = z.object({
  image: z.string().optional().describe(
    "Ubuntu image to use (e.g. '22.04', 'jammy', 'lts'). Defaults to the latest LTS.",
  ),
  cpus: z.number().int().min(1).optional().describe(
    "Number of CPUs to allocate (minimum 1, default 1)",
  ),
  memory: z.string().optional().describe(
    "Amount of memory, e.g. '512M', '2G' (default 1G)",
  ),
  disk: z.string().optional().describe(
    "Disk space to allocate, e.g. '10G' (default 5G, minimum 512M)",
  ),
  cloudInit: z.string().optional().describe(
    "Path to a cloud-init user-data file to apply on first boot",
  ),
});

const StopArgsSchema = z.object({
  force: z.boolean().optional().describe(
    "Force immediate shutdown (may corrupt a running instance)",
  ),
});

const DeleteArgsSchema = z.object({
  purge: z.boolean().optional().describe(
    "Permanently purge the instance immediately (cannot be recovered)",
  ),
});

export const model = {
  type: "@leeehinman/multipass",
  version: "2026.05.17.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    instance: {
      description: "State of the multipass virtual machine instance",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    launch: {
      description: "Create and start a new multipass VM instance",
      arguments: LaunchArgsSchema,
      execute: async (args, context) => {
        const { name } = context.globalArgs;
        const typedArgs = LaunchArgsSchema.parse(args);

        const launchArgs = ["launch", "--name", name];
        if (typedArgs.cpus !== undefined) launchArgs.push("--cpus", String(typedArgs.cpus));
        if (typedArgs.memory) launchArgs.push("--memory", typedArgs.memory);
        if (typedArgs.disk) launchArgs.push("--disk", typedArgs.disk);
        if (typedArgs.cloudInit) launchArgs.push("--cloud-init", typedArgs.cloudInit);
        if (typedArgs.image) launchArgs.push(typedArgs.image);

        context.logger.info("Launching multipass instance {name}", { name });
        const { stderr, success } = await runMultipass(launchArgs);

        if (!success) {
          // Treat "already in use" as idempotent — sync and return existing state.
          if (stderr.toLowerCase().includes("already")) {
            context.logger.info(
              "Instance {name} already exists, returning current state",
              { name },
            );
            const existing = await fetchInstanceInfo(name);
            const handle = await context.writeResource(
              "instance",
              name,
              existing,
            );
            return { dataHandles: [handle] };
          }
          throw new Error(`multipass launch failed for "${name}": ${stderr}`);
        }

        const data = await fetchInstanceInfo(name);
        context.logger.info("Instance {name} launched, state={state}", {
          name,
          state: data.state,
        });

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description: "Refresh stored state from the live multipass instance",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name } = context.globalArgs;

        context.logger.info("Syncing state for instance {name}", { name });
        const data = await fetchInstanceInfo(name);
        context.logger.info("Synced instance {name}, state={state}", {
          name,
          state: data.state,
        });

        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    start: {
      description: "Start a stopped multipass VM instance",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name } = context.globalArgs;

        context.logger.info("Starting instance {name}", { name });
        const { stderr, success } = await runMultipass(["start", name]);
        if (!success) {
          throw new Error(`multipass start failed for "${name}": ${stderr}`);
        }

        const data = await fetchInstanceInfo(name);
        context.logger.info("Instance {name} started, state={state}", {
          name,
          state: data.state,
        });
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    stop: {
      description: "Stop a running multipass VM instance",
      arguments: StopArgsSchema,
      execute: async (args, context) => {
        const { name } = context.globalArgs;
        const typedArgs = StopArgsSchema.parse(args);

        const stopArgs = ["stop", name];
        if (typedArgs.force) stopArgs.push("--force");

        context.logger.info("Stopping instance {name}", { name });
        const { stderr, success } = await runMultipass(stopArgs);
        if (!success) {
          throw new Error(`multipass stop failed for "${name}": ${stderr}`);
        }

        const data = await fetchInstanceInfo(name);
        context.logger.info("Instance {name} stopped, state={state}", {
          name,
          state: data.state,
        });
        const handle = await context.writeResource("instance", name, data);
        return { dataHandles: [handle] };
      },
    },

    delete: {
      description: "Delete a multipass VM instance",
      arguments: DeleteArgsSchema,
      execute: async (args, context) => {
        const { name } = context.globalArgs;
        const typedArgs = DeleteArgsSchema.parse(args);

        const existing = await context.readResource!(name) as InstanceData | null;
        if (!existing) {
          throw new Error(
            `No stored data for instance "${name}" — run launch or sync first`,
          );
        }

        const deleteArgs = ["delete", name];
        if (typedArgs.purge) deleteArgs.push("--purge");

        context.logger.info("Deleting instance {name} (purge={purge})", {
          name,
          purge: typedArgs.purge ?? false,
        });
        const { stderr, success } = await runMultipass(deleteArgs);

        if (!success) {
          // Already deleted/purged — treat as success.
          const alreadyGone =
            stderr.toLowerCase().includes("does not exist") ||
            stderr.toLowerCase().includes("not found") ||
            stderr.toLowerCase().includes("already deleted") ||
            stderr.toLowerCase().includes("already purged");
          if (!alreadyGone) {
            throw new Error(
              `multipass delete failed for "${name}": ${stderr}`,
            );
          }
          context.logger.info(
            "Instance {name} was already gone, treating as success",
            { name },
          );
        }

        return { dataHandles: [] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgsSchema>;
