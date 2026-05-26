import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

async function withCaCert<T>(
  caCertB64: string,
  fn: (caPath: string) => Promise<T>,
): Promise<T> {
  const caPath = `/tmp/churn-ca-${Date.now()}.crt`;
  const caBytes = Uint8Array.from(atob(caCertB64), (c) => c.charCodeAt(0));
  await Deno.writeFile(caPath, caBytes);
  try {
    return await fn(caPath);
  } finally {
    await Deno.remove(caPath).catch(() => {});
  }
}

async function apiFetch(
  baseUrl: string,
  path: string,
  password: string,
  caPath: string,
  opts: { method?: string; body?: unknown } = {},
): Promise<Record<string, unknown>> {
  const method = opts.method ?? "GET";
  const args = [
    "-s", "--cacert", caPath,
    "-u", `elastic:${password}`,
    "-H", "kbn-xsrf: true",
    ...(opts.body
      ? ["-H", "Content-Type: application/json", "-d", JSON.stringify(opts.body)]
      : []),
    "-X", method,
    `${baseUrl}${path}`,
  ];
  const cmd = new Deno.Command("curl", { args, stdout: "piped", stderr: "piped" });
  const out = await cmd.output();
  if (!out.success) {
    throw new Error(`${method} ${baseUrl}${path} (curl): ${new TextDecoder().decode(out.stderr)}`);
  }
  const text = new TextDecoder().decode(out.stdout);
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error(`${method} ${baseUrl}${path} returned non-JSON: ${text.slice(0, 300)}`);
  }
  const statusCode = Number(parsed.statusCode);
  if (statusCode >= 400) {
    throw new Error(
      `${method} ${baseUrl}${path}: HTTP ${statusCode} — ${parsed.message ?? parsed.error ?? text.slice(0, 300)}`,
    );
  }
  return parsed;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withRetry<T>(
  fn: () => Promise<T>,
  label: string,
  logger: { info: (msg: string, args: Record<string, unknown>) => void },
  maxAttempts = 3,
  delayMs = 5000,
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        logger.info("Transient error on {label} (attempt {attempt}/{max}), retrying in {delay}ms: {err}", {
          label, attempt, max: maxAttempts, delay: delayMs,
          err: err instanceof Error ? err.message : String(err),
        });
        await sleep(delayMs);
      }
    }
  }
  throw lastErr;
}

// ---------------------------------------------------------------------------
// Fleet helpers
// ---------------------------------------------------------------------------

async function resolveIntegrationId(
  kibanaUrl: string,
  password: string,
  caPath: string,
  agentPolicyId: string,
  name: string,
): Promise<string> {
  const resp = await apiFetch(kibanaUrl, `/api/fleet/package_policies?perPage=100`, password, caPath);
  const items = resp.items as Array<Record<string, unknown>> | undefined;
  if (!items) throw new Error(`No package policies returned from Fleet`);
  const inPolicy = items.filter((it) => {
    const ids = it.policy_ids as string[] | undefined;
    return ids ? ids.includes(agentPolicyId) : it.policy_id === agentPolicyId;
  });
  const match = inPolicy.find((it) => (it.name as string) === name);
  if (!match) {
    throw new Error(
      `No package policy named '${name}' found in agent policy ${agentPolicyId}. ` +
      `Available: ${inPolicy.map((it) => it.name).join(", ")}`,
    );
  }
  return match.id as string;
}

async function getAgentPolicyRevision(
  kibanaUrl: string,
  password: string,
  caPath: string,
  agentPolicyId: string,
): Promise<number> {
  const resp = await apiFetch(
    kibanaUrl,
    `/api/fleet/agents?kuery=policy_id:${agentPolicyId}&perPage=1`,
    password,
    caPath,
  );
  const items = resp.items as Array<Record<string, unknown>> | undefined;
  if (!items || items.length === 0) {
    throw new Error(`No agent found for policy ${agentPolicyId}`);
  }
  return items[0].policy_revision as number;
}

async function waitForPolicyRevisionChange(
  kibanaUrl: string,
  password: string,
  caPath: string,
  agentPolicyId: string,
  fromRevision: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rev = await getAgentPolicyRevision(kibanaUrl, password, caPath, agentPolicyId);
    if (rev > fromRevision) return true;
    await sleep(2000);
  }
  return false;
}

type Logger = { info: (msg: string, args: Record<string, unknown>) => void };

async function fetchPackagePolicy(
  kibanaUrl: string,
  password: string,
  caPath: string,
  policyId: string,
  logger: Logger,
): Promise<Record<string, unknown>> {
  const resp = await withRetry(
    () => apiFetch(kibanaUrl, `/api/fleet/package_policies/${policyId}`, password, caPath),
    `GET package_policy/${policyId}`,
    logger,
  );
  return resp.item as Record<string, unknown>;
}

// Strip server-managed fields before PUT. id goes in the URL, not the body.
const STRIP_FIELDS = ["id", "version", "revision", "created_at", "created_by", "updated_at", "updated_by", "elasticsearch"];

async function updatePackagePolicy(
  kibanaUrl: string,
  password: string,
  caPath: string,
  policyId: string,
  config: Record<string, unknown>,
  logger: Logger,
): Promise<void> {
  const body: Record<string, unknown> = { ...config };
  for (const f of STRIP_FIELDS) delete body[f];
  await withRetry(
    () => apiFetch(kibanaUrl, `/api/fleet/package_policies/${policyId}`, password, caPath, { method: "PUT", body }),
    `PUT package_policy/${policyId}`,
    logger,
  );
}

// Toggle tagName in inputs[0].streams[0].vars.tags.value.
// Returns the patched config and whether the tag was added or removed.
function toggleTag(
  config: Record<string, unknown>,
  tagName: string,
): { updated: Record<string, unknown>; action: "add-tag" | "remove-tag" } {
  const updated = JSON.parse(JSON.stringify(config)) as Record<string, unknown>;
  const inputs = updated.inputs as Array<Record<string, unknown>>;
  const vars = (inputs[0].streams as Array<Record<string, unknown>>)[0].vars as Record<string, unknown>;
  const tagsVar = vars.tags as { value: string[]; type: string };
  const current: string[] = Array.isArray(tagsVar.value) ? tagsVar.value : [];
  const idx = current.indexOf(tagName);
  if (idx === -1) {
    tagsVar.value = [...current, tagName];
    return { updated, action: "add-tag" };
  } else {
    tagsVar.value = current.filter((t) => t !== tagName);
    return { updated, action: "remove-tag" };
  }
}

// ---------------------------------------------------------------------------
// ES helpers
// ---------------------------------------------------------------------------

async function hasRecentTcpEvents(
  esUrl: string,
  password: string,
  caPath: string,
  label: string,
  windowSecs: number,
): Promise<boolean> {
  const resp = await apiFetch(esUrl, "/logs-tcp.generic-*/_search", password, caPath, {
    method: "POST",
    body: {
      size: 1,
      query: {
        bool: {
          filter: [
            { range: { "@timestamp": { gte: `now-${windowSecs}s` } } },
            { match_phrase: { message: label } },
          ],
        },
      },
    },
  });
  const total = (resp.hits as Record<string, unknown> | undefined)?.total;
  if (typeof total === "number") return total > 0;
  if (typeof total === "object" && total !== null) return ((total as Record<string, unknown>).value as number) > 0;
  return false;
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const IntegrationSchema = z.object({
  label: z.string().describe("Package policy name, e.g. 'tcp-1'"),
  port: z.number().int().describe("TCP port this integration listens on"),
});

const GlobalArgsSchema = z.object({
  kibanaUrl: z.string().describe("Kibana URL, e.g. https://192.168.2.122:5601"),
  elasticsearchUrl: z.string().describe("Elasticsearch URL, e.g. https://192.168.2.121:9200"),
  elasticPassword: z.string().meta({ sensitive: true }).describe("Password for the 'elastic' superuser"),
  caCertB64: z.string().describe("Base64-encoded Elasticsearch HTTP CA certificate"),
  agentPolicyId: z.string().describe("Fleet agent policy ID that owns the TCP integrations"),
  integrations: z.array(IntegrationSchema).min(2).describe(
    "The TCP package policies to toggle (at least 2 required); IDs are resolved from Fleet at startup",
  ),
});

const IterationResultSchema = z.object({
  iteration: z.number().int(),
  targetLabel: z.string(),
  action: z.enum(["add-tag", "remove-tag"]),
  passed: z.boolean(),
  durationMs: z.number(),
  failureReason: z.string().optional(),
});

const ChurnResultSchema = z.object({
  iterationsCompleted: z.number().int(),
  result: z.enum(["passed", "failed"]),
  failureReason: z.string().optional(),
  failedIteration: z.number().int().optional(),
  failedIntegration: z.string().optional(),
  perIterationResults: z.array(IterationResultSchema),
});

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export const model = {
  type: "@leeehinman/tcp-churn-test",
  version: "2026.05.22.3",
  globalArguments: GlobalArgsSchema,
  resources: {
    "churn-results": {
      description: "Results of the TCP integration churn test loop",
      schema: ChurnResultSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    run: {
      description:
        "Repeatedly pick one TCP integration at random and toggle a 'churn-test' tag on it " +
        "(add if absent, remove if present). After each toggle, verify all integrations still " +
        "deliver events to ES (up to 60s grace). Stops after maxIterations or on first failure.",
      arguments: z.object({
        maxIterations: z.number().int().min(1).default(100).describe(
          "Maximum tag-toggle cycles to run",
        ),
      }),
      execute: async (
        args: { maxIterations: number },
        context: {
          globalArgs: z.infer<typeof GlobalArgsSchema>;
          logger: { info: (msg: string, args: Record<string, unknown>) => void };
          writeResource: (spec: string, name: string, data: unknown) => Promise<unknown>;
        },
      ) => {
        const {
          kibanaUrl, elasticsearchUrl, elasticPassword, caCertB64, agentPolicyId,
          integrations: initIntegrations,
        } = context.globalArgs;
        const { maxIterations } = args;

        type IntegrationWithId = z.infer<typeof IntegrationSchema> & { id: string };

        const handle = await withCaCert(caCertB64, async (caPath) => {
          const perIterationResults: z.infer<typeof IterationResultSchema>[] = [];

          // ------------------------------------------------------------------
          // Pre-flight: resolve IDs by name from Fleet, verify baseline event flow
          // ------------------------------------------------------------------
          context.logger.info("Pre-flight: resolving IDs for {n} integrations from Fleet", {
            n: initIntegrations.length,
          });
          const integrations: IntegrationWithId[] = await Promise.all(
            initIntegrations.map(async (i) => {
              const id = await resolveIntegrationId(
                kibanaUrl, elasticPassword, caPath, agentPolicyId, i.label,
              );
              return { ...i, id };
            }),
          );

          for (const integ of integrations) {
            context.logger.info("Resolved [{label}] port={port} id={id}", {
              label: integ.label, port: integ.port, id: integ.id,
            });
          }

          context.logger.info("Pre-flight: verifying baseline event flow (20s window)", {});
          for (const integ of integrations) {
            const ok = await hasRecentTcpEvents(
              elasticsearchUrl, elasticPassword, caPath, `[${integ.label}]`, 20,
            );
            if (!ok) {
              throw new Error(
                `Pre-flight failed: no recent events from [${integ.label}] in the last 20s. ` +
                "Ensure senders are running on agent-vm-3 before starting.",
              );
            }
            context.logger.info("Baseline OK: [{label}] has recent events", { label: integ.label });
          }

          // ------------------------------------------------------------------
          // Main loop
          // ------------------------------------------------------------------
          let finalResult: "passed" | "failed" = "passed";
          let failureReason: string | undefined;
          let failedIteration: number | undefined;
          let failedIntegration: string | undefined;

          for (let i = 1; i <= maxIterations; i++) {
            const iterStart = Date.now();
            const targetIdx = Math.floor(Math.random() * integrations.length);
            const target = integrations[targetIdx];

            // Step 1: GET fresh config and determine tag toggle direction
            const currentConfig = await fetchPackagePolicy(
              kibanaUrl, elasticPassword, caPath, target.id, context.logger,
            );
            const { updated: newConfig, action } = toggleTag(currentConfig, "churn-test");

            context.logger.info(
              "Iteration {i}/{max}: [{target}] (port {port}) action={action}",
              { i, max: maxIterations, target: target.label, port: target.port, action },
            );

            // Step 2: snapshot revision, then PUT the toggled config
            const revBefore = await getAgentPolicyRevision(
              kibanaUrl, elasticPassword, caPath, agentPolicyId,
            );
            await updatePackagePolicy(kibanaUrl, elasticPassword, caPath, target.id, newConfig, context.logger);
            context.logger.info(
              "PUT [{label}] ({action}); polling for agent policy revision > {rev} (30s timeout)",
              { label: target.label, action, rev: revBefore },
            );

            // Step 3: wait for agent to pick up the change
            const applied = await waitForPolicyRevisionChange(
              kibanaUrl, elasticPassword, caPath, agentPolicyId, revBefore, 30_000,
            );
            if (!applied) {
              const reason =
                `Iteration ${i}: agent did not pick up policy change within 30s ` +
                `after toggling [${target.label}]`;
              context.logger.info("ALERT: {reason}", { reason });
              finalResult = "failed";
              failureReason = reason;
              failedIteration = i;
              failedIntegration = target.label;
              perIterationResults.push({
                iteration: i, targetLabel: target.label, action, passed: false,
                durationMs: Date.now() - iterStart, failureReason: reason,
              });
              break;
            }

            // Step 4: poll ES for ALL integrations for up to 60s
            context.logger.info(
              "Policy applied. Checking event flow from all {n} integrations (up to 60s)",
              { n: integrations.length },
            );

            let iterFailed = false;
            let iterFailReason = "";
            let iterFailInteg = "";
            const esDeadline = Date.now() + 60_000;

            while (Date.now() < esDeadline) {
              const checks = await Promise.all(
                integrations.map((s) =>
                  hasRecentTcpEvents(
                    elasticsearchUrl, elasticPassword, caPath, `[${s.label}]`, 15,
                  )
                ),
              );
              if (checks.every(Boolean)) break;

              if (Date.now() + 3000 >= esDeadline) {
                const failedInteg = integrations.find((_, idx) => !checks[idx]);
                iterFailInteg = failedInteg?.label ?? "unknown";
                iterFailReason =
                  `Iteration ${i}: no events from [${iterFailInteg}] for 60s ` +
                  `after toggling [${target.label}] (${action})`;
                iterFailed = true;
                break;
              }
              await sleep(3000);
            }

            if (iterFailed) {
              context.logger.info("ALERT: {reason}", { reason: iterFailReason });
              finalResult = "failed";
              failureReason = iterFailReason;
              failedIteration = i;
              failedIntegration = iterFailInteg;
              perIterationResults.push({
                iteration: i, targetLabel: target.label, action, passed: false,
                durationMs: Date.now() - iterStart, failureReason: iterFailReason,
              });
              break;
            }

            await sleep(3000);
            const durationMs = Date.now() - iterStart;
            context.logger.info("Iteration {i}/{max} PASSED in {ms}ms", {
              i, max: maxIterations, ms: durationMs,
            });
            perIterationResults.push({
              iteration: i, targetLabel: target.label, action, passed: true, durationMs,
            });
          }

          const result: z.infer<typeof ChurnResultSchema> = {
            iterationsCompleted: perIterationResults.length,
            result: finalResult,
            ...(failureReason !== undefined ? { failureReason } : {}),
            ...(failedIteration !== undefined ? { failedIteration } : {}),
            ...(failedIntegration !== undefined ? { failedIntegration } : {}),
            perIterationResults,
          };

          context.logger.info(
            "Done: {completed} iterations, result={result}",
            { completed: result.iterationsCompleted, result: result.result },
          );

          return await context.writeResource("churn-results", "output", result);
        });

        return { dataHandles: [handle] };
      },
    },
  },
};
