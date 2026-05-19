// extensions/models/elastic-agent.ts
// Installs elastic-agent on a remote host and enrolls it to Fleet.
// Requires an Elastic Stack (elastic-stack model) already provisioned.
// Supports Linux (x86_64, aarch64) initially; macOS and Windows are planned.
// Uses tar.gz on Linux/macOS and .zip on Windows (Windows not yet implemented).
// The agent is enrolled to a Fleet policy that collects system logs and metrics.
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------

function sshArgs(keyPath: string, user: string, host: string): string[] {
  return [
    ...(keyPath ? ["-i", keyPath] : []),
    "-o", "StrictHostKeyChecking=no",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=30",
    `${user}@${host}`,
  ];
}

export async function sshExec(
  host: string,
  user: string,
  keyPath: string,
  command: string,
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command("ssh", {
    args: [...sshArgs(keyPath, user, host), command],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await cmd.output();
  return {
    stdout: new TextDecoder().decode(out.stdout).trim(),
    stderr: new TextDecoder().decode(out.stderr).trim(),
    success: out.success,
  };
}

export async function sshScript(
  host: string,
  user: string,
  keyPath: string,
  script: string,
  timeoutMs = 300_000,
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const cmd = new Deno.Command("ssh", {
    args: [...sshArgs(keyPath, user, host), "bash -s"],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const proc = cmd.spawn();
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

// ---------------------------------------------------------------------------
// Kibana Fleet API helpers
// ---------------------------------------------------------------------------

/** Write the CA cert to a temp file, call fn(caPath), then clean up. */
export async function withCaCert<T>(
  caCertB64: string,
  fn: (caPath: string) => Promise<T>,
): Promise<T> {
  const caPath = `/tmp/ea-ca-${Date.now()}.crt`;
  const caBytes = Uint8Array.from(atob(caCertB64), (c) => c.charCodeAt(0));
  await Deno.writeFile(caPath, caBytes);
  try {
    return await fn(caPath);
  } finally {
    await Deno.remove(caPath).catch(() => {});
  }
}

/** Call Kibana Fleet API using curl with a local CA cert file. */
export async function kibanaFetch(
  kibanaUrl: string,
  path: string,
  elasticPassword: string,
  caPath: string,
  opts: { method?: string; body?: unknown } = {},
): Promise<Record<string, unknown>> {
  const method = opts.method ?? "GET";
  const args = [
    "-s", "--cacert", caPath,
    "-u", `elastic:${elasticPassword}`,
    "-H", "kbn-xsrf: true",
    ...(opts.body
      ? ["-H", "Content-Type: application/json", "-d", JSON.stringify(opts.body)]
      : []),
    "-X", method,
    `${kibanaUrl}${path}`,
  ];
  const cmd = new Deno.Command("curl", { args, stdout: "piped", stderr: "piped" });
  const out = await cmd.output();
  if (!out.success) {
    throw new Error(
      `Kibana ${method} ${path} failed (curl): ${new TextDecoder().decode(out.stderr)}`,
    );
  }
  const text = new TextDecoder().decode(out.stdout);
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`Kibana ${method} ${path} returned non-JSON: ${text.slice(0, 300)}`);
  }
  const statusCode = Number(parsed.statusCode);
  if (statusCode >= 400) {
    throw new Error(
      `Kibana ${method} ${path}: HTTP ${statusCode} — ${parsed.message ?? parsed.error ?? text.slice(0, 300)}`,
    );
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Fleet management helpers
// ---------------------------------------------------------------------------

export type KibanaFetchFn = typeof kibanaFetch;

export async function getSystemPackageVersion(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<string> {
  const resp = await fetch(kibanaUrl, "/api/fleet/epm/packages/system", elasticPassword, caPath);
  const version = (resp.item as Record<string, unknown> | undefined)?.version as string | undefined;
  if (!version) {
    throw new Error("Could not determine installed system package version from Fleet");
  }
  return version;
}

export async function findOrCreatePolicy(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  policyName: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<string> {
  const resp = await fetch(kibanaUrl, "/api/fleet/agent_policies?perPage=100", elasticPassword, caPath);
  const items = (resp.items as Array<Record<string, unknown>>) ?? [];
  const existing = items.find((p) => p.name === policyName);
  if (existing) return existing.id as string;

  await fetch(kibanaUrl, "/api/fleet/agent_policies", elasticPassword, caPath, {
    method: "POST",
    body: {
      name: policyName,
      namespace: "default",
      description: `Policy for ${policyName} — system logs and metrics`,
      monitoring_enabled: ["logs", "metrics"],
    },
  });
  // Re-query to handle race: multiple parallel calls may all create a policy.
  // Return the earliest-created one so all callers converge on the same policy.
  const resp2 = await fetch(kibanaUrl, "/api/fleet/agent_policies?perPage=100", elasticPassword, caPath);
  const all = (resp2.items as Array<Record<string, unknown>>) ?? [];
  const matches = all.filter((p) => p.name === policyName);
  matches.sort((a, b) => String(a.created_at ?? "").localeCompare(String(b.created_at ?? "")));
  if (matches.length === 0) throw new Error(`Failed to find or create policy '${policyName}'`);
  return matches[0].id as string;
}

export async function ensureSystemIntegration(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  policyId: string,
  policyName: string,
  systemVersion: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<void> {
  const resp = await fetch(kibanaUrl, "/api/fleet/package_policies?perPage=200", elasticPassword, caPath);
  const items = (resp.items as Array<Record<string, unknown>>) ?? [];
  const alreadyHasSystem = items.some(
    (p) =>
      p.policy_id === policyId &&
      (p.package as Record<string, unknown> | undefined)?.name === "system",
  );
  if (alreadyHasSystem) return;

  // Omit `inputs` to use package defaults (logs + metrics enabled by default)
  await fetch(kibanaUrl, "/api/fleet/package_policies", elasticPassword, caPath, {
    method: "POST",
    body: {
      name: `system-${policyName}`,
      namespace: "default",
      policy_id: policyId,
      package: { name: "system", version: systemVersion },
    },
  });
}

export async function createEnrollmentToken(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  policyId: string,
  tokenName: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<string> {
  // Check for an existing token with this name first
  const existing = await fetch(
    kibanaUrl,
    `/api/fleet/enrollment_api_keys?perPage=100`,
    elasticPassword,
    caPath,
  );
  const items = (existing.items as Array<Record<string, unknown>>) ?? [];
  // Fleet appends " (id)" to token names in list responses; match by prefix
  const found = items.find(
    (t) => (t.name as string)?.startsWith(tokenName) && t.policy_id === policyId && t.active,
  );
  if (found?.api_key) return found.api_key as string;

  // Try creating with the base name; if a 409 (name conflict with an inactive token),
  // fall back to a timestamped name so stale inactive tokens don't block re-enrollment.
  const namesToTry = [tokenName, `${tokenName}-${Date.now()}`];
  for (const name of namesToTry) {
    try {
      const resp = await fetch(kibanaUrl, "/api/fleet/enrollment_api_keys", elasticPassword, caPath, {
        method: "POST",
        body: { name, policy_id: policyId },
      });
      const apiKey = (resp.item as Record<string, unknown>)?.api_key as string | undefined;
      if (!apiKey) {
        throw new Error(`Failed to create enrollment token — no api_key in response: ${JSON.stringify(resp)}`);
      }
      return apiKey;
    } catch (err) {
      if (name === namesToTry[namesToTry.length - 1]) throw err; // rethrow on last attempt
      // 409 conflict — try timestamped fallback
    }
  }
  throw new Error("createEnrollmentToken: exhausted name attempts");
}

export async function getPackageVersion(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  packageName: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<string> {
  const resp = await fetch(kibanaUrl, `/api/fleet/epm/packages/${packageName}`, elasticPassword, caPath);
  const version = (resp.item as Record<string, unknown> | undefined)?.version as string | undefined;
  if (!version) {
    throw new Error(
      `Package '${packageName}' is not installed in Fleet. ` +
      `Upload it via POST /api/fleet/epm/packages before adding the integration.`,
    );
  }
  return version;
}

export async function ensureIntegration(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  policyId: string,
  policyName: string,
  packageName: string,
  packageVersion: string,
  logPaths: string[] | undefined,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<void> {
  const resp = await fetch(kibanaUrl, "/api/fleet/package_policies?perPage=200", elasticPassword, caPath);
  const items = (resp.items as Array<Record<string, unknown>>) ?? [];
  const exists = items.some(
    (p) => p.policy_id === policyId && (p.package as Record<string, unknown> | undefined)?.name === packageName,
  );
  if (exists) return;

  const body: Record<string, unknown> = {
    name: `${packageName}-${policyName}`,
    namespace: "default",
    policy_id: policyId,
    package: { name: packageName, version: packageVersion },
  };

  // If explicit log paths provided, override the logfile input streams
  if (logPaths && logPaths.length > 0) {
    body.inputs = [{
      type: "logfile",
      policy_template: packageName,
      enabled: true,
      streams: [{
        data_stream: { type: "logs", dataset: `${packageName}.access` },
        enabled: true,
        vars: { paths: { value: logPaths } },
      }],
    }];
  }

  await fetch(kibanaUrl, "/api/fleet/package_policies", elasticPassword, caPath, {
    method: "POST",
    body,
  });
}

/** Query Fleet for the Fleet agent ID by matching the target host IP.
 * The Fleet agents endpoint may return results under `list` or `agents`
 * depending on the Kibana/Fleet version. */
export async function findAgentId(
  kibanaUrl: string,
  elasticPassword: string,
  caPath: string,
  targetIp: string,
  fetch: KibanaFetchFn = kibanaFetch,
): Promise<string> {
  const resp = await fetch(
    kibanaUrl,
    "/api/fleet/agents?perPage=200&sortField=enrolled_at&sortOrder=desc",
    elasticPassword,
    caPath,
  );
  // Field name changed across Fleet versions: older = `list`, 9.x = `items`, interim = `agents`
  const agents = ((resp.list ?? resp.agents ?? resp.items) as Array<Record<string, unknown>>) ?? [];
  for (const agent of agents) {
    const localMeta = agent.local_metadata as Record<string, unknown> | undefined;
    const hostMeta = localMeta?.host as Record<string, unknown> | undefined;
    const ips = (hostMeta?.ip as string[] | undefined) ?? [];
    // IPs may include CIDR notation (e.g. "192.168.2.108/24") — match by prefix
    if (ips.some((ip) => ip === targetIp || ip.startsWith(`${targetIp}/`))) {
      return agent.id as string;
    }
  }
  return "";
}

// ---------------------------------------------------------------------------
// Install script builder — Linux only for now
// ---------------------------------------------------------------------------

export function buildLinuxInstallScript(p: {
  installDir: string;
  version: string;
  arch: string;  // "x86_64" | "aarch64"
  fleetServerUrl: string;
  enrollmentToken: string;
  caCertB64: string;
}): string {
  // elastic-agent download uses "arm64" for aarch64 hosts
  const dlArch = p.arch === "aarch64" ? "arm64" : "x86_64";
  return `
#!/bin/bash
set -euo pipefail
INSTALL_DIR="${p.installDir}"
VERSION="${p.version}"
DL_DIR="$INSTALL_DIR/agent-tmp-$$"
sudo mkdir -p "$INSTALL_DIR/certs" "$DL_DIR"
sudo chmod 755 "$INSTALL_DIR/certs"
sudo chown "$(id -u):$(id -g)" "$DL_DIR"
trap 'sudo rm -rf "$DL_DIR"' EXIT

# Write CA cert — use the same filename the Fleet Elasticsearch output expects
echo "${p.caCertB64}" | base64 -d | sudo tee "$INSTALL_DIR/certs/http_ca.crt" > /dev/null
sudo chmod 644 "$INSTALL_DIR/certs/http_ca.crt"
# Also write as ca.crt for Fleet Server enrollment
sudo cp "$INSTALL_DIR/certs/http_ca.crt" "$INSTALL_DIR/certs/ca.crt"

# Uninstall any existing agent first (idempotent).
# Check both the install dir binary AND the /usr/bin wrapper (created by install).
# An 'elastic-agent uninstall' removes /opt/Elastic/Agent/ but may leave the
# wrapper and systemd service, which causes the next install to say "already installed".
EA_INSTALLED=false
# Use sudo for /opt/Elastic/Agent — it is root:root drwxrwx--- and not accessible to ubuntu without sudo.
sudo test -d "/opt/Elastic/Agent" 2>/dev/null && EA_INSTALLED=true
[ -f "/usr/bin/elastic-agent" ] && EA_INSTALLED=true
[ -f "/usr/local/bin/elastic-agent" ] && EA_INSTALLED=true
sudo systemctl is-active elastic-agent >/dev/null 2>&1 && EA_INSTALLED=true
# Also catch "activating" (service starting but is-active returns non-zero)
sudo systemctl is-active elastic-agent 2>&1 | grep -q activating && EA_INSTALLED=true
if [ "$EA_INSTALLED" = "true" ]; then
  echo "[EA] Uninstalling existing elastic-agent..."
  sudo elastic-agent uninstall --force 2>/dev/null || \
    sudo /opt/Elastic/Agent/elastic-agent uninstall --force 2>/dev/null || true
  # Kill any remaining elastic-agent processes and clean up wrapper/service
  sudo pkill -9 -x elastic-agent 2>/dev/null || true
  sudo systemctl stop elastic-agent 2>/dev/null || true
  sudo systemctl disable elastic-agent 2>/dev/null || true
  sudo rm -f /usr/bin/elastic-agent /usr/local/bin/elastic-agent
  sudo rm -f /etc/systemd/system/elastic-agent.service
  sudo systemctl daemon-reload 2>/dev/null || true
  sudo rm -rf /opt/Elastic/Agent
  sleep 3
fi

# Download (use pre-staged tarball if available)
STAGED="/tmp/elastic-agent-${p.version}-linux-${dlArch}.tar.gz"
if [ -f "$STAGED" ]; then
  echo "[EA] Using pre-staged tarball: $STAGED"
  cp "$STAGED" "$DL_DIR/elastic-agent.tar.gz"
else
  echo "[EA] Downloading elastic-agent $VERSION (linux-${dlArch})..."
  curl -fsSL -o "$DL_DIR/elastic-agent.tar.gz" \\
    "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${p.version}-linux-${dlArch}.tar.gz"
fi
tar -C "$DL_DIR" -xzf "$DL_DIR/elastic-agent.tar.gz"

# Install as a systemd service and enroll to Fleet
echo "[EA] Installing and enrolling to Fleet..."
cd "$DL_DIR/elastic-agent-${p.version}-linux-${dlArch}"
sudo ./elastic-agent install \\
  --url="${p.fleetServerUrl}" \\
  --enrollment-token="${p.enrollmentToken}" \\
  --certificate-authorities="$INSTALL_DIR/certs/ca.crt" \\
  --non-interactive

echo "[EA] Waiting for agent to become healthy (up to 300s)..."
for i in $(seq 1 60); do
  STATUS_OUT=$(sudo elastic-agent status 2>&1; true)
  # Extract the elastic-agent component status (last match = elastic-agent component)
  STATUS=$(echo "$STATUS_OUT" | grep -oP '(?<=\\()[A-Z]+(?=\\))' | tail -1 || echo "UNKNOWN")
  echo "[EA] Status: $STATUS (attempt $i/60)"
  if [ "$STATUS" = "HEALTHY" ] || [ "$STATUS" = "DEGRADED" ]; then echo "[EA] Agent is running (status: $STATUS)."; exit 0; fi
  sleep 5
done
echo "[EA] Agent did not become healthy within 300s." >&2
sudo elastic-agent status >&2 || true
exit 1
`;
}

// ---------------------------------------------------------------------------
// Agent status probe via SSH
// ---------------------------------------------------------------------------

export async function fetchAgentStatus(
  host: string,
  sshUser: string,
  sshKey: string,
  execFn: typeof sshExec = sshExec,
): Promise<{ running: boolean; status: string }> {
  // Use `|| true` so exit code 70 (DEGRADED) doesn't mask the output.
  // SSH failure (r.success=false) is the real "not running" signal.
  const r = await execFn(host, sshUser, sshKey, "sudo elastic-agent status 2>&1 || true");
  if (!r.success || !r.stdout.trim() || r.stdout.includes("command not found") || r.stdout.includes("No such file")) {
    return { running: false, status: "not_installed" };
  }
  const match = r.stdout.match(/\(([A-Z]+)\)/);
  if (!match) return { running: false, status: "not_installed" };
  const status = match[1].toLowerCase();
  return { running: true, status };
}

// ---------------------------------------------------------------------------
// Injectable deps type (used by execute functions + tests)
// ---------------------------------------------------------------------------

export interface ExecuteDeps {
  sshExec?: typeof sshExec;
  sshScript?: typeof sshScript;
  kibanaFetch?: KibanaFetchFn;
  withCaCert?: typeof withCaCert;
  // currentState: injectable stored agent state for unit tests.
  // Workaround for swamp-testing bug #371 where readResource always returns null.
  currentState?: z.infer<typeof AgentStateSchema> | null;
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  name: z.string().describe("Logical name for this agent instance"),
  host: z.string().describe("IP or hostname of the target machine"),
  sshUser: z.string().default("ubuntu").describe("SSH username on the target"),
  sshKey: z.string().default("").describe(
    "Absolute path to SSH private key. Empty uses the SSH agent (e.g. YubiKey).",
  ),
  os: z.enum(["linux", "macos", "windows"]).default("linux").describe(
    "Target OS. Only 'linux' is currently implemented.",
  ),
  arch: z.enum(["x86_64", "aarch64"]).default("aarch64").describe(
    "Target CPU architecture.",
  ),
  elasticsearchUrl: z.string().describe(
    "Elasticsearch URL, e.g. https://192.168.2.105:9200",
  ),
  kibanaUrl: z.string().describe(
    "Kibana URL, e.g. https://192.168.2.106:5601",
  ),
  fleetServerUrl: z.string().describe(
    "Fleet Server URL, e.g. https://192.168.2.107:8220",
  ),
  elasticPassword: z.string().meta({ sensitive: true }).describe(
    "Password for the 'elastic' superuser on the Elastic Stack.",
  ),
  caCertB64: z.string().describe(
    "Base64-encoded Elasticsearch HTTP CA certificate (http_ca.crt). " +
    "Available via data.latest(stackName, stackName).attributes.caCertB64 after a sync.",
  ),
  version: z.string().default("").describe(
    "elastic-agent version to install. Empty string defaults to the Elastic Stack version.",
  ),
  installDir: z.string().default("/opt/elastic").describe(
    "Directory on the target host where certs are written.",
  ),
  policyName: z.string().default("").describe(
    "Fleet agent policy name. Empty auto-generates '<name>-policy'.",
  ),
});

const AgentStateSchema = z.object({
  name: z.string(),
  host: z.string(),
  os: z.string(),
  arch: z.string(),
  version: z.string(),
  installDir: z.string(),
  policyId: z.string(),
  policyName: z.string(),
  agentId: z.string().optional().describe(
    "Fleet agent ID — populated on first sync after install.",
  ),
  running: z.boolean(),
  status: z.string(),
  enrolledAt: z.string(),
  syncedAt: z.string(),
});

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

export const model = {
  type: "@leeehinman/elastic-agent",
  version: "2026.05.19.8",
  globalArguments: GlobalArgsSchema,
  resources: {
    agent: {
      description: "Installed and enrolled elastic-agent instance",
      schema: AgentStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  checks: {
    "agent-installed": {
      description:
        "Verify elastic-agent is installed on the target host before uninstalling. " +
        "Skip with --skip-check-label live if the host is unreachable.",
      labels: ["live"],
      appliesTo: ["uninstall"],
      execute: async (context: { globalArgs: z.infer<typeof GlobalArgsSchema> }) => {
        const { host, sshUser, sshKey } = context.globalArgs;
        const r = await sshExec(
          host, sshUser, sshKey,
          "sudo elastic-agent status > /dev/null 2>&1 && echo INSTALLED || echo NOT_INSTALLED",
        );
        if (!r.success || r.stdout.trim() === "NOT_INSTALLED") {
          return {
            pass: false,
            errors: [`elastic-agent is not installed on ${host}. Nothing to uninstall.`],
          };
        }
        return { pass: true };
      },
    },
  },
  methods: {
    install: {
      description:
        "Download and install elastic-agent on the target host via SSH, enroll it to " +
        "Fleet under a system-logs-and-metrics policy, and verify the agent is healthy.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context: {
        globalArgs: z.infer<typeof GlobalArgsSchema>;
        logger: { info: (msg: string, args: Record<string, unknown>) => void };
        writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
      }) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;
        const _sshScript = args._deps?.sshScript ?? sshScript;
        const _kibanaFetch = args._deps?.kibanaFetch ?? kibanaFetch;
        const _withCaCert = args._deps?.withCaCert ?? withCaCert;

        const {
          name, host, sshUser, sshKey, os, arch,
          elasticsearchUrl, kibanaUrl, fleetServerUrl,
          elasticPassword, caCertB64, installDir,
        } = context.globalArgs;

        if (os !== "linux") {
          throw new Error(
            `OS '${os}' is not yet supported. Only 'linux' is currently implemented.`,
          );
        }

        const policyName = context.globalArgs.policyName || `${name}-policy`;
        const tokenName = `${name}-enrollment-token`;

        // Resolve version: if empty, query Elasticsearch
        let version = context.globalArgs.version;
        if (!version) {
          context.logger.info("Resolving version from Elasticsearch at {url}", { url: elasticsearchUrl });
          await _withCaCert(caCertB64, async (caPath) => {
            const resp = await _kibanaFetch(elasticsearchUrl, "/", elasticPassword, caPath);
            const esVersion =
              (resp.version as Record<string, unknown> | undefined)?.number as string | undefined;
            if (!esVersion) {
              throw new Error(`Could not read version from Elasticsearch at ${elasticsearchUrl}`);
            }
            version = esVersion;
          });
          context.logger.info("Using version {version}", { version });
        }

        context.logger.info(
          "Installing elastic-agent {version} on {host} (os={os} arch={arch})",
          { version, host, os, arch },
        );

        let policyId = "";
        await _withCaCert(caCertB64, async (caPath) => {
          context.logger.info("Preparing Fleet policy '{policy}'", { policy: policyName });
          const sysVersion = await getSystemPackageVersion(kibanaUrl, elasticPassword, caPath, _kibanaFetch);
          policyId = await findOrCreatePolicy(kibanaUrl, elasticPassword, caPath, policyName, _kibanaFetch);
          await ensureSystemIntegration(kibanaUrl, elasticPassword, caPath, policyId, policyName, sysVersion, _kibanaFetch);
          const enrollmentToken = await createEnrollmentToken(
            kibanaUrl, elasticPassword, caPath, policyId, tokenName, _kibanaFetch,
          );

          context.logger.info("Running install script on {host}", { host });
          const result = await _sshScript(
            host, sshUser, sshKey,
            buildLinuxInstallScript({ installDir, version, arch, fleetServerUrl, enrollmentToken, caCertB64 }),
            600_000,
          );
          if (!result.success) {
            throw new Error(`elastic-agent install failed on ${host}:\n${result.stderr}\n${result.stdout}`);
          }
          context.logger.info("{output}", { output: result.stdout });
        });

        const handle = await context.writeResource("agent", name, {
          name, host, os, arch, version, installDir,
          policyId, policyName,
          agentId: "",
          running: true,
          status: "healthy",
          enrolledAt: new Date().toISOString(),
          syncedAt: new Date().toISOString(),
        });

        context.logger.info(
          "elastic-agent {version} installed and healthy on {host}, policy='{policy}'",
          { version, host, policy: policyName },
        );
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description: "Refresh agent status from the target host and update the Fleet agent ID.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context: {
        globalArgs: z.infer<typeof GlobalArgsSchema>;
        logger: { info: (msg: string, args: Record<string, unknown>) => void };
        writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        readResource: (spec: string, name: string) => Promise<unknown>;
      }) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;
        const _kibanaFetch = args._deps?.kibanaFetch ?? kibanaFetch;
        const _withCaCert = args._deps?.withCaCert ?? withCaCert;

        const { name, host, sshUser, sshKey, kibanaUrl, elasticPassword, caCertB64 } =
          context.globalArgs;

        context.logger.info("Syncing elastic-agent status for {name} on {host}", { name, host });

        // readResource workaround: swamp-testing bug #371 (readResource always null in tests)
        const current = (
          args._deps?.currentState !== undefined
            ? args._deps.currentState
            : await context.readResource("agent", name)
        ) as z.infer<typeof AgentStateSchema> | null;

        const { os, arch, version, installDir, policyName: configuredPolicyName } = context.globalArgs;
        const agentStatus = await fetchAgentStatus(host, sshUser, sshKey, _sshExec);
        if (!agentStatus.running) {
          throw new Error(`elastic-agent is not running on ${host}. Run 'install' first.`);
        }

        // Resolve policy and agent ID from Fleet
        const policyName = configuredPolicyName || `${name}-policy`;
        let policyId = current?.policyId ?? "";
        let agentId = current?.agentId ?? "";
        await _withCaCert(caCertB64, async (caPath) => {
          if (!policyId) {
            policyId = await findOrCreatePolicy(kibanaUrl, elasticPassword, caPath, policyName, _kibanaFetch);
          }
          if (!agentId) {
            agentId = await findAgentId(kibanaUrl, elasticPassword, caPath, host, _kibanaFetch);
          }
        }).catch(() => {});

        const handle = await context.writeResource("agent", name, {
          ...(current ?? {
            name, host, os, arch,
            version: version || "unknown",
            installDir,
            policyId,
            policyName,
            enrolledAt: new Date().toISOString(),
          }),
          policyId: policyId || current?.policyId || "",
          agentId,
          running: agentStatus.running,
          status: agentStatus.status,
          syncedAt: new Date().toISOString(),
        });

        context.logger.info(
          "Synced {name}: running={running} status={status}",
          { name, running: agentStatus.running, status: agentStatus.status },
        );
        return { dataHandles: [handle] };
      },
    },

    uninstall: {
      description: "Uninstall elastic-agent from the target host.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context: {
        globalArgs: z.infer<typeof GlobalArgsSchema>;
        logger: { info: (msg: string, args: Record<string, unknown>) => void };
        writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        readResource: (spec: string, name: string) => Promise<unknown>;
      }) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;

        const { name, host, sshUser, sshKey } = context.globalArgs;

        context.logger.info("Uninstalling elastic-agent from {host}", { host });
        const r = await _sshExec(
          host, sshUser, sshKey,
          "sudo elastic-agent uninstall --non-interactive 2>&1 || echo 'Not installed, nothing to do'",
        );
        context.logger.info("{output}", { output: r.stdout });

        // readResource workaround: swamp-testing bug #371 (readResource always null in tests)
        const current = (
          args._deps?.currentState !== undefined
            ? args._deps.currentState
            : await context.readResource("agent", name).catch(() => null)
        ) as z.infer<typeof AgentStateSchema> | null;

        if (current) {
          const handle = await context.writeResource("agent", name, {
            ...current,
            running: false,
            status: "uninstalled",
            syncedAt: new Date().toISOString(),
          });
          context.logger.info("elastic-agent uninstalled from {host}", { host });
          return { dataHandles: [handle] };
        }

        context.logger.info("No stored state found for {name}; nothing to update", { name });
        return { dataHandles: [] };
      },
    },

    stop: {
      description: "Stop the elastic-agent systemd service on the target host.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context: {
        globalArgs: z.infer<typeof GlobalArgsSchema>;
        logger: { info: (msg: string, args: Record<string, unknown>) => void };
        writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        readResource: (spec: string, name: string) => Promise<unknown>;
      }) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;
        const { name, host, sshUser, sshKey } = context.globalArgs;

        context.logger.info("Stopping elastic-agent on {host}", { host });
        const r = await _sshExec(host, sshUser, sshKey, "sudo systemctl stop elastic-agent");
        if (!r.success) {
          throw new Error(`Failed to stop elastic-agent on ${host}: ${r.stderr}`);
        }

        const current = (args._deps?.currentState !== undefined
          ? args._deps.currentState
          : await context.readResource("agent", name).catch(() => null)) as
          z.infer<typeof AgentStateSchema> | null;

        if (current) {
          const handle = await context.writeResource("agent", name, {
            ...current,
            running: false,
            status: "stopped",
            syncedAt: new Date().toISOString(),
          });
          context.logger.info("elastic-agent stopped on {host}", { host });
          return { dataHandles: [handle] };
        }
        return { dataHandles: [] };
      },
    },

    start: {
      description: "Start the elastic-agent systemd service on the target host.",
      arguments: z.object({}),
      execute: async (args: { _deps?: ExecuteDeps }, context: {
        globalArgs: z.infer<typeof GlobalArgsSchema>;
        logger: { info: (msg: string, args: Record<string, unknown>) => void };
        writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        readResource: (spec: string, name: string) => Promise<unknown>;
      }) => {
        const _sshExec = args._deps?.sshExec ?? sshExec;
        const { name, host, sshUser, sshKey } = context.globalArgs;

        context.logger.info("Starting elastic-agent on {host}", { host });
        const r = await _sshExec(host, sshUser, sshKey, "sudo systemctl start elastic-agent");
        if (!r.success) {
          throw new Error(`Failed to start elastic-agent on ${host}: ${r.stderr}`);
        }

        const current = (args._deps?.currentState !== undefined
          ? args._deps.currentState
          : await context.readResource("agent", name).catch(() => null)) as
          z.infer<typeof AgentStateSchema> | null;

        if (current) {
          const handle = await context.writeResource("agent", name, {
            ...current,
            running: true,
            status: "starting",
            syncedAt: new Date().toISOString(),
          });
          context.logger.info("elastic-agent started on {host}", { host });
          return { dataHandles: [handle] };
        }
        return { dataHandles: [] };
      },
    },

    addIntegration: {
      description:
        "Add a Fleet package integration to this agent's policy. " +
        "The package must already be installed in Fleet (upload it first if the stack has no internet).",
      arguments: z.object({
        packageName: z.string().describe("Fleet package name, e.g. 'apache'"),
        packageVersion: z.string().default("").describe(
          "Package version. If empty, reads the installed version from Fleet.",
        ),
        logPaths: z.array(z.string()).optional().describe(
          "Override log file paths for logfile inputs. Uses package defaults if omitted.",
        ),
      }),
      execute: async (
        args: { packageName: string; packageVersion: string; logPaths?: string[]; _deps?: ExecuteDeps },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
          readResource: (spec: string, name: string) => Promise<unknown>;
        },
      ) => {
        const _kibanaFetch = args._deps?.kibanaFetch ?? kibanaFetch;
        const _withCaCert = args._deps?.withCaCert ?? withCaCert;

        const { name, kibanaUrl, elasticPassword, caCertB64 } = context.globalArgs;
        const policyName = context.globalArgs.policyName || `${name}-policy`;
        const { packageName, logPaths } = args;

        context.logger.info(
          "Adding '{pkg}' integration to policy '{policy}' on {name}",
          { pkg: packageName, policy: policyName, name },
        );

        await _withCaCert(caCertB64, async (caPath) => {
          const policyId = await findOrCreatePolicy(kibanaUrl, elasticPassword, caPath, policyName, _kibanaFetch);
          const packageVersion = args.packageVersion ||
            await getPackageVersion(kibanaUrl, elasticPassword, caPath, packageName, _kibanaFetch);
          await ensureIntegration(
            kibanaUrl, elasticPassword, caPath,
            policyId, policyName, packageName, packageVersion, logPaths,
            _kibanaFetch,
          );
        });

        context.logger.info(
          "Integration '{pkg}' added to policy '{policy}'",
          { pkg: packageName, policy: policyName },
        );
        return { dataHandles: [] };
      },
    },
  },
};
