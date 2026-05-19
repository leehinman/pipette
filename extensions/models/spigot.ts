import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  name: z.string().describe("Logical name for this spigot installation"),
  host: z.string().describe("IP or hostname of the target machine"),
  sshUser: z.string().default("ubuntu").describe("SSH username on the target"),
  sshKey: z.string().default("").describe(
    "Absolute path to SSH private key. Empty uses the SSH agent.",
  ),
  arch: z.enum(["x86_64", "aarch64"]).default("aarch64").describe("Target CPU architecture"),
  installPath: z.string().default("/usr/local/bin/spigot").describe(
    "Absolute path where the spigot binary is installed on the target host",
  ),
});

const SpigotRunSchema = z.object({
  name: z.string(),
  outputFile: z.string().describe("Absolute path of the generated log file on the target host"),
  count: z.number().int(),
  generator: z.string(),
  ranAt: z.string(),
});

const SpigotStateSchema = z.object({
  name: z.string(),
  host: z.string(),
  installPath: z.string(),
  commit: z.string().describe("Full git commit hash of the installed build"),
  ref: z.string().describe("Git ref (branch, tag, or commit) that was built"),
  installedAt: z.string(),
  syncedAt: z.string(),
});

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------

function buildSshArgs(host: string, sshUser: string, sshKey: string): string[] {
  const base = ["-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"];
  if (sshKey) base.push("-i", sshKey);
  return [...base, `${sshUser}@${host}`];
}

export async function sshExec(
  host: string,
  sshUser: string,
  sshKey: string,
  cmd: string,
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const proc = new Deno.Command("ssh", {
    args: [...buildSshArgs(host, sshUser, sshKey), cmd],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await proc.output();
  return {
    stdout: new TextDecoder().decode(out.stdout).trim(),
    stderr: new TextDecoder().decode(out.stderr).trim(),
    success: out.success,
  };
}

/** Transfer a local file to the remote host by piping binary content over SSH. */
export async function sshTransferFile(
  localPath: string,
  host: string,
  sshUser: string,
  sshKey: string,
  remotePath: string,
): Promise<void> {
  const content = await Deno.readFile(localPath);
  const proc = new Deno.Command("ssh", {
    args: [...buildSshArgs(host, sshUser, sshKey), `cat > ${remotePath}`],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const writer = proc.stdin.getWriter();
  await writer.write(content);
  await writer.close();
  const result = await proc.output();
  if (!result.success) {
    throw new Error(
      `File transfer to ${host}:${remotePath} failed: ${new TextDecoder().decode(result.stderr)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Local build helpers
// ---------------------------------------------------------------------------

async function runLocalCmd(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<string> {
  const proc = new Deno.Command(cmd, {
    args,
    stdout: "piped",
    stderr: "piped",
    cwd: opts.cwd,
    env: opts.env,
  });
  const out = await proc.output();
  if (!out.success) {
    const stderr = new TextDecoder().decode(out.stderr);
    throw new Error(`${cmd} ${args.join(" ")} failed: ${stderr}`);
  }
  return new TextDecoder().decode(out.stdout).trim();
}

/** Run a bash script over SSH by piping it through stdin. */
export async function sshScript(
  host: string,
  sshUser: string,
  sshKey: string,
  script: string,
  timeoutMs = 120_000,
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const proc = new Deno.Command("ssh", {
    args: [...buildSshArgs(host, sshUser, sshKey), "bash -s"],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const writer = proc.stdin.getWriter();
  await writer.write(new TextEncoder().encode(script));
  await writer.close();
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(`SSH script timed out after ${timeoutMs}ms`)), timeoutMs)
  );
  const result = await Promise.race([proc.output(), timeout]);
  return {
    stdout: new TextDecoder().decode(result.stdout).trim(),
    stderr: new TextDecoder().decode(result.stderr).trim(),
    success: result.success,
  };
}

/** Clone or refresh the spigot repo, build for the target, and return the binary path + commit. */
export async function buildSpigot(
  ref: string,
  goArch: string,
  instanceName?: string,
): Promise<{ binaryPath: string; commit: string }> {
  const buildDir = instanceName ? `/tmp/spigot-src-${instanceName}` : "/tmp/spigot-src";
  const goArchMapped = goArch === "aarch64" ? "arm64" : "amd64";

  // Clone if missing, otherwise fetch latest refs
  try {
    await Deno.stat(`${buildDir}/.git`);
    await runLocalCmd("git", ["-C", buildDir, "fetch", "--all", "--prune"]);
  } catch {
    await runLocalCmd("git", ["clone", "https://github.com/elastic/spigot.git", buildDir]);
  }

  // Checkout the requested ref
  await runLocalCmd("git", ["-C", buildDir, "checkout", ref]);

  // Pull if on a branch (not a detached HEAD / tag / commit hash)
  await runLocalCmd("git", ["-C", buildDir, "pull", "--ff-only"]).catch(() => {});

  const commit = await runLocalCmd("git", ["-C", buildDir, "rev-parse", "HEAD"]);

  // Cache keyed by commit + target so rebuilds are skipped when nothing changed
  const cacheKey = `/tmp/spigot-build-${commit}-linux-${goArchMapped}`;
  try {
    await Deno.stat(cacheKey);
    return { binaryPath: cacheKey, commit };
  } catch { /* not cached — build */ }

  const goEnv: Record<string, string> = {
    ...Deno.env.toObject(),
    GOOS: "linux",
    GOARCH: goArchMapped,
    CGO_ENABLED: "0",
  };
  await runLocalCmd("go", ["build", "-o", cacheKey, "./cmd/spigot"], {
    cwd: buildDir,
    env: goEnv,
  });

  return { binaryPath: cacheKey, commit };
}

// ---------------------------------------------------------------------------
// Injectable deps (for unit tests)
// ---------------------------------------------------------------------------

export interface SpigotDeps {
  sshExec?: typeof sshExec;
  sshScript?: typeof sshScript;
  sshTransferFile?: typeof sshTransferFile;
  buildSpigot?: typeof buildSpigot;
  /** Workaround for swamp-testing bug #371: readResource returns null in test context. */
  currentState?: z.infer<typeof SpigotStateSchema> | null;
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

export const model = {
  type: "@leeehinman/spigot",
  version: "2026.05.19.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    install: {
      description: "Installed spigot binary state",
      schema: SpigotStateSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    run: {
      description: "Last spigot log-generation run",
      schema: SpigotRunSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    install: {
      description:
        "Build spigot from source (github.com/elastic/spigot) and install the binary on the target host.",
      arguments: z.object({
        ref: z.string().default("main").describe(
          "Git branch, tag, or commit to build. Defaults to 'main'.",
        ),
      }),
      execute: async (
        args: { ref: string; _deps?: SpigotDeps },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        },
      ) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;
        const _sshTransferFile = args._deps?.sshTransferFile ?? sshTransferFile;
        const _buildSpigot = args._deps?.buildSpigot ?? buildSpigot;

        const { name, host, sshUser, sshKey, arch, installPath } = context.globalArgs;
        const ref = args.ref ?? "main";

        context.logger.info(
          "Building spigot@{ref} for linux/{arch} and installing on {host}",
          { ref, arch, host },
        );

        // Build locally (use per-instance dir to avoid git lock conflicts on parallel installs)
        const { binaryPath, commit } = await _buildSpigot(ref, arch, name);

        context.logger.info(
          "Built spigot commit {commit}, transferring to {host}",
          { commit: commit.slice(0, 8), host },
        );

        // Transfer to a temp path on the target, then move into place with sudo
        const tmpPath = `/tmp/spigot-${commit.slice(0, 8)}`;
        await _sshTransferFile(binaryPath, host, sshUser, sshKey, tmpPath);
        const r = await _sshExec(
          host, sshUser, sshKey,
          `sudo mv ${tmpPath} ${installPath} && sudo chmod +x ${installPath} && spigot -h 2>&1 | head -1 || true`,
        );
        if (!r.success) {
          throw new Error(`Failed to install spigot on ${host}: ${r.stderr}`);
        }

        context.logger.info(
          "spigot installed at {installPath} on {host} (commit {commit})",
          { installPath, host, commit: commit.slice(0, 8) },
        );

        const handle = await context.writeResource("install", name, {
          name,
          host,
          installPath,
          commit,
          ref,
          installedAt: new Date().toISOString(),
          syncedAt: new Date().toISOString(),
        });

        return { dataHandles: [handle] };
      },
    },

    sync: {
      description: "Check whether spigot is installed on the target host and refresh stored state.",
      arguments: z.object({}),
      execute: async (
        args: { _deps?: SpigotDeps },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
          readResource: (spec: string, name: string) => Promise<unknown>;
        },
      ) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;

        const { name, host, sshUser, sshKey, installPath } = context.globalArgs;

        context.logger.info("Syncing spigot installation state for {name} on {host}", {
          name, host,
        });

        const r = await _sshExec(
          host, sshUser, sshKey,
          `test -x ${installPath} && echo INSTALLED || echo NOT_INSTALLED`,
        );
        const installed = r.success && r.stdout.trim() === "INSTALLED";

        if (!installed) {
          throw new Error(
            `spigot is not installed at ${installPath} on ${host}. Run 'install' first.`,
          );
        }

        // Try to read existing state; reconstruct from globalArgs if unavailable
        const current = (args._deps?.currentState !== undefined
          ? args._deps.currentState
          : await context.readResource("install", name).catch(() => null)) as
          | z.infer<typeof SpigotStateSchema>
          | null;

        const handle = await context.writeResource("install", name, {
          ...(current ?? {
            name,
            host,
            installPath,
            commit: "",
            ref: "",
            installedAt: new Date().toISOString(),
          }),
          syncedAt: new Date().toISOString(),
        });

        context.logger.info("spigot is installed at {installPath} on {host}", {
          installPath, host,
        });

        return { dataHandles: [handle] };
      },
    },

    run: {
      description:
        "Run the spigot binary on the target host to generate synthetic log records. " +
        "Writes a temporary spigot config, executes the binary, then removes the config.",
      arguments: z.object({
        outputFile: z.string().describe(
          "Absolute path on the target host where the log file will be written " +
          "(e.g. /var/log/apache2/access.log).",
        ),
        count: z.number().int().min(1).default(1024).describe("Number of log records to generate."),
        generator: z.string().default("clf").describe(
          "Spigot generator type (e.g. 'clf', 'cisco:asa', 'aws:vpcflow').",
        ),
        combined: z.boolean().default(false).describe(
          "Use Combined Log Format (clf generator only). Adds referer and user-agent fields.",
        ),
      }),
      execute: async (
        args: { outputFile: string; count: number; generator: string; combined: boolean; _deps?: SpigotDeps },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        },
      ) => {
        const _sshScript = args._deps?.sshScript ?? sshScript;
        const { name, host, sshUser, sshKey, installPath } = context.globalArgs;
        const { outputFile, count, generator, combined } = args;
        const outputDir = outputFile.substring(0, outputFile.lastIndexOf("/"));
        const outputBase = outputFile.substring(outputFile.lastIndexOf("/") + 1);

        context.logger.info(
          "Running spigot ({gen}, {count} records) → {dir}/{base}_* on {host}",
          { gen: generator, count, dir: outputDir, base: outputBase, host },
        );

        // Use directory+pattern so each run produces a unique file that filebeat
        // has never seen — avoids re-ingestion skipping on repeated runs.
        const spigotConfig = [
          `runners:`,
          `  - generator:`,
          `      type: "${generator}"`,
          ...(generator === "clf" ? [`      combined: ${combined}`] : []),
          `    output:`,
          `      type: file`,
          `      directory: "${outputDir}"`,
          `      pattern: "${outputBase}_*"`,
          `      delimiter: "\\n"`,
          `    records: ${count}`,
        ].join("\n");

        const script = `
set -euo pipefail
CONFIG_FILE="/tmp/spigot-run-$$.yml"
cat > "$CONFIG_FILE" << 'SPIGOT_CONFIG_EOF'
${spigotConfig}
SPIGOT_CONFIG_EOF
sudo mkdir -p "${outputDir}"
sudo chmod 777 "${outputDir}"
${installPath} -r -c "$CONFIG_FILE"
rm -f "$CONFIG_FILE"
echo "Generated ${count} records in ${outputDir}/${outputBase}_*"
`;

        const r = await _sshScript(host, sshUser, sshKey, script);
        if (!r.success) {
          throw new Error(
            `spigot run failed on ${host}: ${r.stderr}\n${r.stdout}`,
          );
        }

        context.logger.info("{output}", { output: r.stdout });

        const handle = await context.writeResource("run", name, {
          name,
          outputFile,
          count,
          generator,
          ranAt: new Date().toISOString(),
        });

        return { dataHandles: [handle] };
      },
    },

    uninstall: {
      description: "Remove the spigot binary from the target host.",
      arguments: z.object({}),
      checks: {
        "spigot-installed": {
          description: "Verify spigot is installed on the target host before uninstalling.",
          labels: ["live"],
          appliesTo: ["uninstall"],
          execute: async (context: { globalArgs: z.infer<typeof GlobalArgsSchema> }) => {
            const { host, sshUser, sshKey, installPath } = context.globalArgs;
            const r = await sshExec(
              host, sshUser, sshKey,
              `test -x ${installPath} && echo INSTALLED || echo NOT_INSTALLED`,
            );
            if (!r.success || r.stdout.includes("NOT_INSTALLED")) {
              return {
                pass: false,
                errors: [`spigot is not installed at ${installPath} on ${host}.`],
              };
            }
            return { pass: true };
          },
        },
      },
      execute: async (
        args: { _deps?: SpigotDeps },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
          readResource: (spec: string, name: string) => Promise<unknown>;
        },
      ) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;

        const { name, host, sshUser, sshKey, installPath } = context.globalArgs;

        context.logger.info("Uninstalling spigot from {host} at {installPath}", {
          host, installPath,
        });

        const r = await _sshExec(
          host, sshUser, sshKey,
          `sudo rm -f ${installPath} && echo REMOVED`,
        );
        if (!r.success) {
          throw new Error(`Failed to uninstall spigot from ${host}: ${r.stderr}`);
        }

        context.logger.info("spigot removed from {host}", { host });

        const current = (args._deps?.currentState !== undefined
          ? args._deps.currentState
          : await context.readResource("install", name).catch(() => null)) as
          | z.infer<typeof SpigotStateSchema>
          | null;

        if (current) {
          const handle = await context.writeResource("install", name, {
            ...current,
            syncedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        }

        return { dataHandles: [] };
      },
    },
  },
};
