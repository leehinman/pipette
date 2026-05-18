// extensions/models/elastic-stack.ts
// Installs and manages the Elastic Stack across three dedicated hosts:
//   - elasticsearchHost: Elasticsearch node
//   - kibanaHost: Kibana UI
//   - fleetServerHost: Fleet Server (elastic-agent)
// Uses official tar.gz archives; TLS is auto-configured by Elasticsearch 8.x.
// The CA cert is distributed from Elasticsearch to the other two hosts.
// Sensitive credentials are routed through the swamp vault automatically.
// sshKey is optional — leave empty to rely on the SSH agent (e.g. YubiKey).
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing";

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------

/** Build the SSH argument list, omitting -i when keyPath is empty. */
function sshArgs(keyPath: string, user: string, host: string): string[] {
  return [
    ...(keyPath ? ["-i", keyPath] : []),
    "-o", "StrictHostKeyChecking=no",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=30",
    `${user}@${host}`,
  ];
}

async function sshExec(
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

async function sshScript(
  host: string,
  user: string,
  keyPath: string,
  script: string,
  timeoutMs = 600_000,
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
  const timeoutId = setTimeout(() => proc.kill(), timeoutMs);
  const out = await proc.output();
  clearTimeout(timeoutId);
  return {
    stdout: new TextDecoder().decode(out.stdout).trim(),
    stderr: new TextDecoder().decode(out.stderr).trim(),
    success: out.success,
  };
}

// ---------------------------------------------------------------------------
// Credential generation
// ---------------------------------------------------------------------------

function generatePassword(length = 24): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

function generateHexKey(): string {
  const arr = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  name: z.string().describe("Name for this Elastic Stack installation."),
  elasticsearchHost: z.string().describe(
    "IP or hostname of the Elasticsearch VM.",
  ),
  kibanaHost: z.string().describe(
    "IP or hostname of the Kibana VM.",
  ),
  fleetServerHost: z.string().describe(
    "IP or hostname of the Fleet Server VM.",
  ),
  version: z.string().default("9.4.1").describe(
    "Elastic Stack version (e.g. '9.4.1' or '8.17.6').",
  ),
  sshUser: z.string().default("ubuntu").describe(
    "SSH username on all three VMs.",
  ),
  sshKey: z.string().default("").describe(
    "Absolute path to the SSH private key. Leave empty to use the SSH agent " +
    "(required for hardware keys such as YubiKey).",
  ),
  installDir: z.string().default("/opt/elastic").describe(
    "Base installation directory on each VM.",
  ),
  arch: z.enum(["x86_64", "aarch64"]).default("x86_64").describe(
    "CPU architecture of the target VMs.",
  ),
});

const ServiceStatusSchema = z.object({
  host: z.string(),
  installed: z.boolean(),
  running: z.boolean(),
  pid: z.number().optional(),
  installPath: z.string().optional(),
});

const StackStateSchema = z.object({
  version: z.string(),
  installDir: z.string(),
  elasticsearch: ServiceStatusSchema,
  kibana: ServiceStatusSchema,
  fleetServer: ServiceStatusSchema,
  elasticsearchUrl: z.string().optional(),
  kibanaUrl: z.string().optional(),
  fleetServerUrl: z.string().optional(),
  httpsCertFingerprint: z.string().optional().describe(
    "SHA-256 fingerprint of the Elasticsearch HTTP CA (hex, no colons).",
  ),
  caCertB64: z.string().optional().describe(
    "Base64-encoded Elasticsearch HTTP CA certificate (http_ca.crt). " +
    "Referenced by elastic-agent models via CEL to enroll agents.",
  ),
  syncedAt: z.string(),
});

const CredentialsSchema = z.object({
  elasticPassword: z.string().meta({ sensitive: true }).describe(
    "Password for the 'elastic' superuser.",
  ),
  kibanaSystemPassword: z.string().meta({ sensitive: true }).describe(
    "Password for the 'kibana_system' service account.",
  ),
  kibanaEncryptionKey: z.string().meta({ sensitive: true }).describe(
    "32-byte hex key for Kibana saved-object encryption.",
  ),
  fleetServiceToken: z.string().meta({ sensitive: true }).describe(
    "Fleet Server service token (elastic/fleet-server).",
  ),
});

type StackState = z.infer<typeof StackStateSchema>;

// ---------------------------------------------------------------------------
// Service status probe (one host, one service)
// ---------------------------------------------------------------------------

async function probeService(
  host: string,
  user: string,
  keyPath: string,
  installDir: string,
  serviceSubdir: string,
  pidFileName: string,
): Promise<z.infer<typeof ServiceStatusSchema>> {
  const script = `
set -uo pipefail
dir="${installDir}/${serviceSubdir}"
pidfile="$dir/${pidFileName}"
installed=false; running=false; pid=""
[ -d "$dir" ] && installed=true
if [ -f "$pidfile" ]; then
  p=$(cat "$pidfile" 2>/dev/null || echo "")
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
    running=true; pid=$p
  fi
fi
echo "{\\"installed\\":$installed,\\"running\\":$running,\\"pid\\":\\"$pid\\"}"
`;
  const { stdout, success } = await sshScript(host, user, keyPath, script);
  if (!success) return { host, installed: false, running: false };
  const d = JSON.parse(stdout);
  return {
    host,
    installed: d.installed,
    running: d.running,
    pid: d.pid ? Number(d.pid) : undefined,
    installPath: d.installed ? `${installDir}/${serviceSubdir}` : undefined,
  };
}

async function fetchStackState(
  esHost: string,
  kibanaHost: string,
  fleetHost: string,
  user: string,
  keyPath: string,
  version: string,
  installDir: string,
): Promise<StackState> {
  const [esStatus, kibanaStatus, fleetStatus] = await Promise.all([
    probeService(esHost, user, keyPath, installDir, "elasticsearch", "elasticsearch.pid"),
    probeService(kibanaHost, user, keyPath, installDir, "kibana", "kibana.pid"),
    probeService(fleetHost, user, keyPath, installDir, "elastic-agent", "fleet-server.pid"),
  ]);

  // Try to get the cert fingerprint and CA cert from the ES host if installed
  let fingerprint: string | undefined;
  let caCertB64: string | undefined;
  if (esStatus.installed) {
    const [fp, ca] = await Promise.all([
      sshExec(esHost, user, keyPath,
        `openssl x509 -fingerprint -sha256 -noout -in "${installDir}/elasticsearch/config/certs/http_ca.crt" 2>/dev/null | sed 's/.*=//;s/://g' || echo ""`
      ),
      sshExec(esHost, user, keyPath,
        `base64 -w 0 "${installDir}/elasticsearch/config/certs/http_ca.crt" 2>/dev/null || echo ""`
      ),
    ]);
    fingerprint = fp.stdout || undefined;
    caCertB64 = ca.stdout || undefined;
  }

  return {
    version,
    installDir,
    elasticsearch: esStatus,
    kibana: kibanaStatus,
    fleetServer: fleetStatus,
    elasticsearchUrl: `https://${esHost}:9200`,
    kibanaUrl: `https://${kibanaHost}:5601`,
    fleetServerUrl: `https://${fleetHost}:8220`,
    httpsCertFingerprint: fingerprint,
    caCertB64,
    syncedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Install scripts — one per component
// All TypeScript variables are interpolated directly; bash-only vars use $VAR.
// ---------------------------------------------------------------------------

function buildEsInstallScript(p: {
  installDir: string;
  version: string;
  arch: string;
  elasticPassword: string;
  kibanaSystemPassword: string;
}): string {
  return `
#!/bin/bash
set -euo pipefail
INSTALL_DIR="${p.installDir}"
ES_HOME="$INSTALL_DIR/elasticsearch"
DL_DIR="/tmp/elastic-dl-$$"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
mkdir -p "$DL_DIR"
trap 'rm -rf "$DL_DIR"' EXIT

if [ ! -d "$ES_HOME" ]; then
  echo "[ES] Downloading elasticsearch-${p.version}-linux-${p.arch}.tar.gz..."
  curl -fsSL "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${p.version}-linux-${p.arch}.tar.gz" \
    -o "$DL_DIR/elasticsearch.tar.gz"
  tar -xzf "$DL_DIR/elasticsearch.tar.gz" -C "$INSTALL_DIR"
  mv "$INSTALL_DIR/elasticsearch-${p.version}" "$ES_HOME"
else
  echo "[ES] Already installed."
fi

mkdir -p "$ES_HOME/config/jvm.options.d" "$ES_HOME/logs"

if [ ! -f "$ES_HOME/config/certs/http_ca.crt" ]; then
  echo "[ES] Generating TLS certificates..."
  MY_IP=$(hostname -I | awk '{print $1}')
  mkdir -p "$ES_HOME/config/certs"
  "$ES_HOME/bin/elasticsearch-certutil" ca --silent --pem \
    --out "$ES_HOME/config/certs/ca.zip"
  python3 -c "import zipfile; zipfile.ZipFile('$ES_HOME/config/certs/ca.zip').extractall('$ES_HOME/config/certs/')"
  "$ES_HOME/bin/elasticsearch-certutil" cert --silent --pem \
    --ca-cert "$ES_HOME/config/certs/ca/ca.crt" \
    --ca-key "$ES_HOME/config/certs/ca/ca.key" \
    --ip 127.0.0.1 --ip "$MY_IP" \
    --dns localhost --dns "$(hostname)" \
    --out "$ES_HOME/config/certs/cert.zip"
  python3 -c "import zipfile; zipfile.ZipFile('$ES_HOME/config/certs/cert.zip').extractall('$ES_HOME/config/certs/')"
  cp "$ES_HOME/config/certs/ca/ca.crt" "$ES_HOME/config/certs/http_ca.crt"
  echo "[ES] TLS certificates generated."
fi

cat > "$ES_HOME/config/elasticsearch.yml" << 'ESEOF'
cluster.name: elastic-stack
node.name: node-1
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.certificate_authorities: ${p.installDir}/elasticsearch/config/certs/ca/ca.crt
xpack.security.http.ssl.certificate: ${p.installDir}/elasticsearch/config/certs/instance/instance.crt
xpack.security.http.ssl.key: ${p.installDir}/elasticsearch/config/certs/instance/instance.key
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.certificate_authorities: ${p.installDir}/elasticsearch/config/certs/ca/ca.crt
xpack.security.transport.ssl.certificate: ${p.installDir}/elasticsearch/config/certs/instance/instance.crt
xpack.security.transport.ssl.key: ${p.installDir}/elasticsearch/config/certs/instance/instance.key
ESEOF

cat > "$ES_HOME/config/jvm.options.d/heap.options" << 'JVMEOF'
-Xms1g
-Xmx1g
JVMEOF

if [ ! -f "$ES_HOME/elasticsearch.pid" ] || \
   ! kill -0 "$(cat "$ES_HOME/elasticsearch.pid" 2>/dev/null)" 2>/dev/null; then
  echo "[ES] Starting..."
  ES_PATH_CONF="$ES_HOME/config" "$ES_HOME/bin/elasticsearch" \
    -d -p "$ES_HOME/elasticsearch.pid" >> "$ES_HOME/logs/stdout.log" 2>&1
fi

echo "[ES] Waiting for readiness..."
for idx in $(seq 1 60); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:9200/" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ] || [ "$CODE" = "401" ]; then echo "[ES] Ready ($CODE)"; break; fi
  if [ "$idx" = "60" ]; then echo "[ES] Timed out" >&2; exit 1; fi
  sleep 2
done

echo "[ES] Resetting elastic password..."
TMPOUT=$("$ES_HOME/bin/elasticsearch-reset-password" -u elastic --auto --batch 2>&1 || true)
TMPPASS=$(echo "$TMPOUT" | grep -oP '(?<=New value: )\\S+' || echo "")
if [ -z "$TMPPASS" ]; then echo "[ES] No temp password: $TMPOUT" >&2; exit 1; fi

curl -fsk -u "elastic:$TMPPASS" --cacert "$ES_HOME/config/certs/http_ca.crt" \
  -X POST "https://localhost:9200/_security/user/elastic/_password" \
  -H "Content-Type: application/json" \
  -d '{"password":"${p.elasticPassword}"}' > /dev/null
echo "[ES] elastic password set."

curl -fsk -u "elastic:${p.elasticPassword}" --cacert "$ES_HOME/config/certs/http_ca.crt" \
  -X POST "https://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d '{"password":"${p.kibanaSystemPassword}"}' > /dev/null
echo "[ES] kibana_system password set."

FINGERPRINT=$(openssl x509 -fingerprint -sha256 -noout \
  -in "$ES_HOME/config/certs/http_ca.crt" 2>/dev/null | sed 's/.*=//;s/://g' || echo "")

FLEET_RESP=$(curl -fsk -u "elastic:${p.elasticPassword}" --cacert "$ES_HOME/config/certs/http_ca.crt" \
  -X POST "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-1" \
  -H "Content-Type: application/json" 2>&1 || echo "")
FLEET_TOKEN=$(echo "$FLEET_RESP" | grep -oP '(?<="value":")[^"]+' || echo "")
if [ -z "$FLEET_TOKEN" ]; then
  curl -sk -u "elastic:${p.elasticPassword}" --cacert "$ES_HOME/config/certs/http_ca.crt" \
    -X DELETE "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-1" \
    > /dev/null 2>&1 || true
  FLEET_RESP=$(curl -fsk -u "elastic:${p.elasticPassword}" --cacert "$ES_HOME/config/certs/http_ca.crt" \
    -X POST "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-1" \
    -H "Content-Type: application/json" || echo "")
  FLEET_TOKEN=$(echo "$FLEET_RESP" | grep -oP '(?<="value":")[^"]+' || echo "")
fi
if [ -z "$FLEET_TOKEN" ]; then echo "[ES] Fleet token failed" >&2; exit 1; fi

echo "RESULT_JSON_START"
printf '{"fingerprint":"%s","fleetServiceToken":"%s"}\\n' "$FINGERPRINT" "$FLEET_TOKEN"
echo "RESULT_JSON_END"
`;
}

function buildKibanaInstallScript(p: {
  installDir: string;
  version: string;
  arch: string;
  elasticsearchHost: string;
  kibanaSystemPassword: string;
  kibanaEncryptionKey: string;
  caCertB64: string;
  caKeyB64: string;
}): string {
  return `
#!/bin/bash
set -euo pipefail
INSTALL_DIR="${p.installDir}"
KN_HOME="$INSTALL_DIR/kibana"
DL_DIR="/tmp/elastic-dl-$$"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/certs" "$DL_DIR"
trap 'rm -rf "$DL_DIR"' EXIT

echo "${p.caCertB64}" | base64 -d > "$INSTALL_DIR/certs/http_ca.crt"
echo "${p.caCertB64}" | base64 -d > "$INSTALL_DIR/certs/ca.crt"
echo "${p.caKeyB64}"  | base64 -d > "$INSTALL_DIR/certs/ca.key"
chmod 600 "$INSTALL_DIR/certs/ca.key"

if [ ! -f "$INSTALL_DIR/certs/kibana.crt" ]; then
  echo "[KN] Generating TLS certificate for Kibana..."
  MY_IP=$(hostname -I | awk '{print $1}')
  openssl genrsa -out "$INSTALL_DIR/certs/kibana.key" 2048
  openssl req -new -key "$INSTALL_DIR/certs/kibana.key" \
    -subj "/CN=$(hostname)" \
    -out "$INSTALL_DIR/certs/kibana.csr"
  printf 'subjectAltName=IP:127.0.0.1,IP:%s,DNS:localhost,DNS:%s\n' \
    "$MY_IP" "$(hostname)" > "/tmp/kibana-san-$$.ext"
  openssl x509 -req -in "$INSTALL_DIR/certs/kibana.csr" \
    -CA "$INSTALL_DIR/certs/ca.crt" \
    -CAkey "$INSTALL_DIR/certs/ca.key" \
    -CAcreateserial \
    -out "$INSTALL_DIR/certs/kibana.crt" \
    -days 3650 -sha256 \
    -extfile "/tmp/kibana-san-$$.ext"
  rm -f "/tmp/kibana-san-$$.ext" "$INSTALL_DIR/certs/kibana.csr"
  echo "[KN] TLS certificate generated."
fi

if [ ! -d "$KN_HOME" ]; then
  echo "[KN] Downloading kibana-${p.version}-linux-${p.arch}.tar.gz..."
  curl -fsSL "https://artifacts.elastic.co/downloads/kibana/kibana-${p.version}-linux-${p.arch}.tar.gz" \
    -o "$DL_DIR/kibana.tar.gz"
  tar -xzf "$DL_DIR/kibana.tar.gz" -C "$INSTALL_DIR"
  mv "$INSTALL_DIR/kibana-${p.version}" "$KN_HOME"
else
  echo "[KN] Already installed."
fi

mkdir -p "$KN_HOME/config" "$KN_HOME/logs" "$KN_HOME/data"

# Single-quoted heredoc: bash won't expand $-vars; all values already injected by TypeScript.
cat > "$KN_HOME/config/kibana.yml" << 'KNEOF'
server.host: "0.0.0.0"
server.port: 5601
server.ssl.enabled: true
server.ssl.certificate: ${p.installDir}/certs/kibana.crt
server.ssl.key: ${p.installDir}/certs/kibana.key
elasticsearch.hosts: ["https://${p.elasticsearchHost}:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${p.kibanaSystemPassword}"
elasticsearch.ssl.certificateAuthorities: ["${p.installDir}/certs/http_ca.crt"]
xpack.encryptedSavedObjects.encryptionKey: "${p.kibanaEncryptionKey}"
xpack.security.encryptionKey: "${p.kibanaEncryptionKey}"
xpack.reporting.encryptionKey: "${p.kibanaEncryptionKey}"
path.data: "${p.installDir}/kibana/data"

# Pre-configure Fleet output so Fleet setup uses the correct ES URL (not http://localhost:9200)
xpack.fleet.packages:
  - name: fleet_server
    version: latest
xpack.fleet.agentPolicies:
  - name: Fleet Server Policy
    id: fleet-server-policy
    is_default_fleet_server: true
    namespace: default
    package_policies:
      - package:
          name: fleet_server
        name: fleet_server-1
xpack.fleet.outputs:
  - id: fleet-default-output
    name: default
    type: elasticsearch
    hosts: ["https://${p.elasticsearchHost}:9200"]
    is_default: true
    is_default_monitoring: true
    ssl:
      certificate_authorities: ["${p.installDir}/certs/http_ca.crt"]
KNEOF

# Kill stale process if config changed
if [ -f "$KN_HOME/kibana.pid" ]; then
  OLD_PID=$(cat "$KN_HOME/kibana.pid" 2>/dev/null || echo "")
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[KN] Stopping existing Kibana (pid $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 3
  fi
  rm -f "$KN_HOME/kibana.pid"
fi

echo "[KN] Starting..."
nohup "$KN_HOME/bin/kibana" >> "$KN_HOME/logs/stdout.log" 2>&1 &
echo $! > "$KN_HOME/kibana.pid"

echo "[KN] Waiting for readiness (up to 3 min)..."
for idx in $(seq 1 90); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:5601/api/status" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ] || [ "$CODE" = "401" ]; then echo "[KN] Ready ($CODE)"; break; fi
  # Check if process died
  KN_PID=$(cat "$KN_HOME/kibana.pid" 2>/dev/null || echo "")
  if [ -n "$KN_PID" ] && ! kill -0 "$KN_PID" 2>/dev/null; then
    echo "[KN] Process died. Last log:" >&2
    tail -20 "$KN_HOME/logs/stdout.log" >&2
    exit 1
  fi
  if [ "$idx" = "90" ]; then echo "[KN] Timed out waiting for Kibana" >&2; exit 1; fi
  sleep 2
done
echo "[KN] Done."
`;
}

function buildFleetInstallScript(p: {
  installDir: string;
  version: string;
  arch: string;
  elasticsearchHost: string;
  fleetServiceToken: string;
  caCertB64: string;
  caKeyB64: string;
}): string {
  return `
#!/bin/bash
set -euo pipefail
INSTALL_DIR="${p.installDir}"
AGENT_HOME="$INSTALL_DIR/elastic-agent"
DL_DIR="/tmp/elastic-dl-$$"
# Elastic Agent uses arm64 where ES/Kibana use aarch64
AGENT_ARCH="${p.arch}"
if [ "$AGENT_ARCH" = "aarch64" ]; then AGENT_ARCH="arm64"; fi
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/certs" "$DL_DIR"
trap 'rm -rf "$DL_DIR"' EXIT

echo "${p.caCertB64}" | base64 -d > "$INSTALL_DIR/certs/http_ca.crt"
echo "${p.caCertB64}" | base64 -d > "$INSTALL_DIR/certs/ca.crt"
echo "${p.caKeyB64}"  | base64 -d > "$INSTALL_DIR/certs/ca.key"
chmod 600 "$INSTALL_DIR/certs/ca.key"

if [ ! -f "$INSTALL_DIR/certs/fleet-server.crt" ]; then
  echo "[FL] Generating TLS certificate for Fleet Server..."
  MY_IP=$(hostname -I | awk '{print $1}')
  openssl genrsa -out "$INSTALL_DIR/certs/fleet-server.key" 2048
  openssl req -new -key "$INSTALL_DIR/certs/fleet-server.key" \
    -subj "/CN=$(hostname)" \
    -out "$INSTALL_DIR/certs/fleet-server.csr"
  printf 'subjectAltName=IP:127.0.0.1,IP:%s,DNS:localhost,DNS:%s\n' \
    "$MY_IP" "$(hostname)" > "/tmp/fleet-san-$$.ext"
  openssl x509 -req -in "$INSTALL_DIR/certs/fleet-server.csr" \
    -CA "$INSTALL_DIR/certs/ca.crt" \
    -CAkey "$INSTALL_DIR/certs/ca.key" \
    -CAcreateserial \
    -out "$INSTALL_DIR/certs/fleet-server.crt" \
    -days 3650 -sha256 \
    -extfile "/tmp/fleet-san-$$.ext"
  rm -f "/tmp/fleet-san-$$.ext" "$INSTALL_DIR/certs/fleet-server.csr"
  echo "[FL] TLS certificate generated."
fi

if [ ! -d "$AGENT_HOME" ]; then
  echo "[FL] Downloading elastic-agent-${p.version}-linux-$AGENT_ARCH.tar.gz..."
  curl -fsSL "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${p.version}-linux-$AGENT_ARCH.tar.gz" \
    -o "$DL_DIR/elastic-agent.tar.gz"
  tar -xzf "$DL_DIR/elastic-agent.tar.gz" -C "$INSTALL_DIR"
  mv "$INSTALL_DIR/elastic-agent-${p.version}-linux-$AGENT_ARCH" "$AGENT_HOME"
else
  echo "[FL] Already installed."
fi

mkdir -p "$AGENT_HOME/logs"

# Kill stale process if exists
if [ -f "$AGENT_HOME/fleet-server.pid" ]; then
  OLD_PID=$(cat "$AGENT_HOME/fleet-server.pid" 2>/dev/null || echo "")
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[FL] Stopping existing Fleet Server (pid $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 3
  fi
  rm -f "$AGENT_HOME/fleet-server.pid"
fi

# fleet-server flags belong to 'enroll', not 'run'.
# enroll bootstraps fleet server using our CA-signed cert, writes config to fleet.enc, then exits.
# run then starts the agent (and fleet server) using that saved config.
echo "[FL] Enrolling as Fleet Server (bootstrap)..."
"$AGENT_HOME/elastic-agent" enroll \
  --force \
  --url="https://localhost:8220" \
  --fleet-server-es="https://${p.elasticsearchHost}:9200" \
  --fleet-server-service-token="${p.fleetServiceToken}" \
  --fleet-server-es-ca="$INSTALL_DIR/certs/http_ca.crt" \
  --fleet-server-cert="$INSTALL_DIR/certs/fleet-server.crt" \
  --fleet-server-cert-key="$INSTALL_DIR/certs/fleet-server.key" \
  --certificate-authorities="$INSTALL_DIR/certs/ca.crt" \
  --fleet-server-port=8220 \
  --fleet-server-timeout=300s
echo "[FL] Enrollment complete, starting agent..."

echo "[FL] Starting Fleet Server..."
nohup "$AGENT_HOME/elastic-agent" run >> "$AGENT_HOME/logs/stdout.log" 2>&1 &
echo $! > "$AGENT_HOME/fleet-server.pid"

echo "[FL] Waiting for readiness (up to 3 min)..."
for idx in $(seq 1 90); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8220/api/status" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ] || [ "$CODE" = "401" ]; then echo "[FL] Ready ($CODE)"; break; fi
  FL_PID=$(cat "$AGENT_HOME/fleet-server.pid" 2>/dev/null || echo "")
  if [ -n "$FL_PID" ] && ! kill -0 "$FL_PID" 2>/dev/null; then
    echo "[FL] Process died. Last log:" >&2
    tail -20 "$AGENT_HOME/logs/stdout.log" >&2
    exit 1
  fi
  if [ "$idx" = "90" ]; then echo "[FL] Timed out waiting for Fleet Server" >&2; exit 1; fi
  sleep 2
done
echo "[FL] Done."
`;
}

// ---------------------------------------------------------------------------
// Start / stop scripts (per-host, per-service)
// ---------------------------------------------------------------------------

function buildEsStartScript(installDir: string): string {
  return `
set -euo pipefail
ES_HOME="${installDir}/elasticsearch"
if [ ! -f "$ES_HOME/elasticsearch.pid" ] || \
   ! kill -0 "$(cat "$ES_HOME/elasticsearch.pid" 2>/dev/null)" 2>/dev/null; then
  echo "Starting Elasticsearch..."
  ES_PATH_CONF="$ES_HOME/config" "$ES_HOME/bin/elasticsearch" \
    -d -p "$ES_HOME/elasticsearch.pid" >> "$ES_HOME/logs/stdout.log" 2>&1
else
  echo "Elasticsearch already running."
fi
`;
}

function buildKibanaStartScript(installDir: string): string {
  return `
set -euo pipefail
KN_HOME="${installDir}/kibana"
if [ ! -f "$KN_HOME/kibana.pid" ] || \
   ! kill -0 "$(cat "$KN_HOME/kibana.pid" 2>/dev/null)" 2>/dev/null; then
  echo "Starting Kibana..."
  nohup "$KN_HOME/bin/kibana" >> "$KN_HOME/logs/stdout.log" 2>&1 &
  echo $! > "$KN_HOME/kibana.pid"
else
  echo "Kibana already running."
fi
`;
}

function buildFleetStartScript(installDir: string): string {
  return `
set -euo pipefail
AGENT_HOME="${installDir}/elastic-agent"
if [ ! -f "$AGENT_HOME/fleet.enc" ]; then
  echo "Fleet enrollment config not found: $AGENT_HOME/fleet.enc" >&2
  echo "Run the install method first to enroll the agent." >&2
  exit 1
fi
if [ ! -f "$AGENT_HOME/fleet-server.pid" ] || \
   ! kill -0 "$(cat "$AGENT_HOME/fleet-server.pid" 2>/dev/null)" 2>/dev/null; then
  echo "Starting Fleet Server..."
  nohup "$AGENT_HOME/elastic-agent" run >> "$AGENT_HOME/logs/stdout.log" 2>&1 &
  echo $! > "$AGENT_HOME/fleet-server.pid"
else
  echo "Fleet Server already running."
fi
`;
}

function buildStopScript(installDir: string, serviceSubdir: string, pidFile: string): string {
  return `
set -uo pipefail
pidfile="${installDir}/${serviceSubdir}/${pidFile}"
if [ -f "$pidfile" ]; then
  p=$(cat "$pidfile" 2>/dev/null || echo "")
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
    echo "Stopping (pid $p)..."
    kill "$p" && sleep 2
  else
    echo "Not running."
  fi
  rm -f "$pidfile"
else
  echo "Pidfile not found."
fi
`;
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

export const model = {
  type: "@leeehinman/elastic-stack",
  version: "2026.05.18.13",
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "Installation and runtime state across all three hosts",
      schema: StackStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    credentials: {
      description: "Stack credentials (stored in vault via sensitive fields)",
      schema: CredentialsSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    install: {
      description:
        "Install Elasticsearch, Kibana, and Fleet Server on their respective hosts " +
        "using tar.gz archives. Orchestrates: ES install → CA cert distribution → " +
        "Kibana install → Fleet Server install. Idempotent.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const {
          name, elasticsearchHost, kibanaHost, fleetServerHost,
          version, sshUser, sshKey, installDir, arch,
        } = context.globalArgs;

        const elasticPassword = generatePassword();
        const kibanaSystemPassword = generatePassword();
        const kibanaEncryptionKey = generateHexKey();

        context.logger.info(
          "Installing Elastic Stack v{version}: ES={es} KN={kn} FL={fl}",
          { version, es: elasticsearchHost, kn: kibanaHost, fl: fleetServerHost },
        );

        // Step 1: Install Elasticsearch
        context.logger.info("Installing Elasticsearch on {host}", { host: elasticsearchHost });
        const esResult = await sshScript(
          elasticsearchHost, sshUser, sshKey,
          buildEsInstallScript({ installDir, version, arch, elasticPassword, kibanaSystemPassword }),
          900_000,
        );
        if (!esResult.success) {
          throw new Error(`Elasticsearch install failed on ${elasticsearchHost}: ${esResult.stderr}`);
        }

        const jsonMatch = esResult.stdout.match(
          /RESULT_JSON_START\s*([\s\S]*?)\s*RESULT_JSON_END/,
        );
        if (!jsonMatch) {
          throw new Error(`ES install missing result JSON.\nOutput:\n${esResult.stdout}`);
        }
        const esOutput = JSON.parse(jsonMatch[1]);
        const fleetServiceToken: string = esOutput.fleetServiceToken ?? "";
        const httpsCertFingerprint: string = esOutput.fingerprint ?? "";

        // Step 2: Get CA cert and key from ES host (base64 for safe transfer)
        context.logger.info("Retrieving CA certificate from {host}", { host: elasticsearchHost });
        const [certResult, keyResult] = await Promise.all([
          sshExec(elasticsearchHost, sshUser, sshKey,
            `base64 -w 0 "${installDir}/elasticsearch/config/certs/http_ca.crt"`),
          sshExec(elasticsearchHost, sshUser, sshKey,
            `base64 -w 0 "${installDir}/elasticsearch/config/certs/ca/ca.key"`),
        ]);
        if (!certResult.success || !certResult.stdout) {
          throw new Error(`Failed to retrieve CA cert from ${elasticsearchHost}: ${certResult.stderr}`);
        }
        if (!keyResult.success || !keyResult.stdout) {
          throw new Error(`Failed to retrieve CA key from ${elasticsearchHost}: ${keyResult.stderr}`);
        }
        const caCertB64 = certResult.stdout;
        const caKeyB64 = keyResult.stdout;

        // Step 3: Install Kibana
        context.logger.info("Installing Kibana on {host}", { host: kibanaHost });
        const knResult = await sshScript(
          kibanaHost, sshUser, sshKey,
          buildKibanaInstallScript({
            installDir, version, arch,
            elasticsearchHost, kibanaSystemPassword, kibanaEncryptionKey,
            caCertB64, caKeyB64,
          }),
          600_000,
        );
        if (!knResult.success) {
          throw new Error(`Kibana install failed on ${kibanaHost}: ${knResult.stderr}`);
        }

        // Step 3.5: Ensure Kibana Fleet setup is complete (kibana.yml pre-configures fleet packages
        // and policies, so Kibana handles setup on startup; we just confirm it finished).
        context.logger.info("Confirming Kibana Fleet setup on {host}", { host: kibanaHost });
        const fleetSetupScript = `
#!/bin/bash
set -euo pipefail
echo "[FS] Waiting for Kibana Fleet setup to complete..."
for idx in $(seq 1 60); do
  RESP=$(curl -sk -u "elastic:${elasticPassword}" \
    -X POST "https://localhost:5601/api/fleet/setup" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" 2>/dev/null || echo "")
  INIT=$(echo "$RESP" | grep -o '"isInitialized":true' || echo "")
  if [ -n "$INIT" ]; then echo "[FS] Fleet setup done."; break; fi
  if [ "$idx" = "60" ]; then
    echo "[FS] Fleet setup timed out. Last response: $RESP" >&2
    exit 1
  fi
  sleep 5
done
`;
        const fsSetupResult = await sshScript(kibanaHost, sshUser, sshKey, fleetSetupScript, 320_000);
        if (!fsSetupResult.success) {
          throw new Error(`Kibana Fleet setup failed on ${kibanaHost}: ${fsSetupResult.stderr}\n${fsSetupResult.stdout}`);
        }

        // Step 4: Install Fleet Server
        context.logger.info("Installing Fleet Server on {host}", { host: fleetServerHost });
        const flResult = await sshScript(
          fleetServerHost, sshUser, sshKey,
          buildFleetInstallScript({
            installDir, version, arch,
            elasticsearchHost, fleetServiceToken, caCertB64, caKeyB64,
          }),
          600_000,
        );
        if (!flResult.success) {
          throw new Error(`Fleet Server install failed on ${fleetServerHost}: ${flResult.stderr}`);
        }

        const stackState = await fetchStackState(
          elasticsearchHost, kibanaHost, fleetServerHost,
          sshUser, sshKey, version, installDir,
        );
        stackState.httpsCertFingerprint = httpsCertFingerprint;

        // Verify all services are running before declaring success
        const notRunning = [
          !stackState.elasticsearch.running && `Elasticsearch (${elasticsearchHost})`,
          !stackState.kibana.running && `Kibana (${kibanaHost})`,
          !stackState.fleetServer.running && `Fleet Server (${fleetServerHost})`,
        ].filter(Boolean);
        if (notRunning.length > 0) {
          throw new Error(`Install completed but services not running: ${notRunning.join(", ")}. Check logs on each VM.`);
        }

        const stateHandle = await context.writeResource("state", `state-${name}`, stackState);
        const credHandle = await context.writeResource("credentials", `credentials-${name}`, {
          elasticPassword,
          kibanaSystemPassword,
          kibanaEncryptionKey,
          fleetServiceToken,
        });

        context.logger.info(
          "Install complete. ES={es} KN={kn} FL={fl}",
          {
            es: stackState.elasticsearch.running,
            kn: stackState.kibana.running,
            fl: stackState.fleetServer.running,
          },
        );

        return { dataHandles: [stateHandle, credHandle] };
      },
    },

    sync: {
      description: "Refresh stored state by probing all three hosts.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name, elasticsearchHost, kibanaHost, fleetServerHost, version, sshUser, sshKey, installDir } =
          context.globalArgs;

        context.logger.info("Syncing Elastic Stack state across three hosts", {});
        const stackState = await fetchStackState(
          elasticsearchHost, kibanaHost, fleetServerHost,
          sshUser, sshKey, version, installDir,
        );
        const handle = await context.writeResource("state", `state-${name}`, stackState);
        context.logger.info(
          "Synced. ES={es} KN={kn} FL={fl}",
          {
            es: stackState.elasticsearch.running,
            kn: stackState.kibana.running,
            fl: stackState.fleetServer.running,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    start: {
      description: "Start all Elastic Stack services if not already running.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { name, elasticsearchHost, kibanaHost, fleetServerHost, version, sshUser, sshKey, installDir } =
          context.globalArgs;

        context.logger.info("Starting all Elastic Stack services", {});

        const esR = await sshScript(elasticsearchHost, sshUser, sshKey, buildEsStartScript(installDir));
        if (!esR.success) throw new Error(`ES start failed: ${esR.stderr}`);

        const knR = await sshScript(kibanaHost, sshUser, sshKey, buildKibanaStartScript(installDir));
        if (!knR.success) throw new Error(`Kibana start failed: ${knR.stderr}`);

        const flR = await sshScript(fleetServerHost, sshUser, sshKey, buildFleetStartScript(installDir));
        if (!flR.success) throw new Error(`Fleet Server start failed: ${flR.stderr}`);

        const stackState = await fetchStackState(
          elasticsearchHost, kibanaHost, fleetServerHost,
          sshUser, sshKey, version, installDir,
        );
        const handle = await context.writeResource("state", `state-${name}`, stackState);
        return { dataHandles: [handle] };
      },
    },

    stop: {
      description: "Stop all Elastic Stack services in order (Fleet → Kibana → ES).",
      arguments: z.object({
        force: z.boolean().optional().describe("SIGKILL instead of SIGTERM."),
      }),
      execute: async (args, context) => {
        const { name, elasticsearchHost, kibanaHost, fleetServerHost, version, sshUser, sshKey, installDir } =
          context.globalArgs;
        const { force } = z.object({ force: z.boolean().optional() }).parse(args);

        context.logger.info("Stopping all Elastic Stack services", {});

        const kill = force ? "kill -9" : "kill";
        const stopFn = (s: string, p: string) =>
          buildStopScript(installDir, s, p).replace('kill "$p"', `${kill} "$p"`);

        await sshScript(fleetServerHost, sshUser, sshKey, stopFn("elastic-agent", "fleet-server.pid"));
        await sshScript(kibanaHost, sshUser, sshKey, stopFn("kibana", "kibana.pid"));
        await sshScript(elasticsearchHost, sshUser, sshKey, stopFn("elasticsearch", "elasticsearch.pid"));

        const stackState = await fetchStackState(
          elasticsearchHost, kibanaHost, fleetServerHost,
          sshUser, sshKey, version, installDir,
        );
        const handle = await context.writeResource("state", `state-${name}`, stackState);
        return { dataHandles: [handle] };
      },
    },

    uninstall: {
      description: "Stop all services and delete the installation directory on all three hosts.",
      arguments: z.object({
        confirm: z.literal(true).describe("Must be true to confirm the destructive operation."),
      }),
      execute: async (args, context) => {
        const { elasticsearchHost, kibanaHost, fleetServerHost, sshUser, sshKey, installDir } =
          context.globalArgs;
        z.object({ confirm: z.literal(true) }).parse(args);

        context.logger.info(
          "Uninstalling Elastic Stack from three hosts ({installDir})",
          { installDir },
        );

        for (const [host, svc, pid] of [
          [fleetServerHost, "elastic-agent", "fleet-server.pid"],
          [kibanaHost, "kibana", "kibana.pid"],
          [elasticsearchHost, "elasticsearch", "elasticsearch.pid"],
        ] as [string, string, string][]) {
          await sshScript(host, sshUser, sshKey, buildStopScript(installDir, svc, pid));
          const { stderr, success } = await sshExec(host, sshUser, sshKey, `rm -rf "${installDir}"`);
          if (!success) {
            throw new Error(`Failed to remove ${installDir} on ${host}: ${stderr}`);
          }
        }

        context.logger.info("Elastic Stack uninstalled from all hosts", {});
        return { dataHandles: [] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgsSchema>;
