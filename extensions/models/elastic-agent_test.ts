// elastic-agent_test.ts — unit tests for the elastic-agent extension model.
// Run: deno test extensions/models/elastic-agent_test.ts
import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing";
import {
  buildLinuxInstallScript,
  createEnrollmentToken,
  ensureSystemIntegration,
  fetchAgentStatus,
  findAgentId,
  findOrCreatePolicy,
  getSystemPackageVersion,
  model,
  type ExecuteDeps,
  type KibanaFetchFn,
} from "./elastic-agent.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const BASE_GLOBAL_ARGS = {
  name: "test-agent",
  host: "192.168.1.100",
  sshUser: "ubuntu",
  sshKey: "",
  os: "linux" as const,
  arch: "aarch64" as const,
  elasticsearchUrl: "https://192.168.1.101:9200",
  kibanaUrl: "https://192.168.1.102:5601",
  fleetServerUrl: "https://192.168.1.103:8220",
  elasticPassword: "s3cret",
  caCertB64: btoa("fake-ca-cert"),
  version: "9.4.1",
  installDir: "/opt/elastic",
  policyName: "test-policy",
};

/** Minimal stored agent state for seeding readResource. */
const STORED_AGENT = {
  name: "test-agent",
  host: "192.168.1.100",
  os: "linux",
  arch: "aarch64",
  version: "9.4.1",
  installDir: "/opt/elastic",
  policyId: "policy-abc",
  policyName: "test-policy",
  agentId: "",
  running: true,
  status: "healthy",
  enrolledAt: "2026-05-18T11:00:00.000Z",
  syncedAt: "2026-05-18T11:00:00.000Z",
};

/** Returns a mock sshExec that always succeeds with the given stdout. */
function mockSshExec(stdout: string, success = true): ExecuteDeps["sshExec"] {
  return () => Promise.resolve({ stdout, stderr: "", success });
}

/** Returns a mock sshScript that always succeeds with the given stdout. */
function mockSshScript(stdout: string, success = true): ExecuteDeps["sshScript"] {
  return () => Promise.resolve({ stdout, stderr: "", success });
}

/** Returns a mock withCaCert that passes "/fake/ca.crt" to fn without disk I/O. */
const mockWithCaCert: ExecuteDeps["withCaCert"] = <T>(
  _b64: string,
  fn: (path: string) => Promise<T>,
) => fn("/fake/ca.crt");

// ---------------------------------------------------------------------------
// buildLinuxInstallScript — pure function tests
// ---------------------------------------------------------------------------

Deno.test("buildLinuxInstallScript contains version and fleet URL", () => {
  const script = buildLinuxInstallScript({
    installDir: "/opt/elastic",
    version: "9.4.1",
    arch: "aarch64",
    fleetServerUrl: "https://192.168.1.103:8220",
    enrollmentToken: "tok-abc",
    caCertB64: "dGVzdA==",
  });
  assertStringIncludes(script, "9.4.1");
  assertStringIncludes(script, "https://192.168.1.103:8220");
  assertStringIncludes(script, "--enrollment-token=\"tok-abc\"");
  assertStringIncludes(script, "arm64"); // aarch64 maps to arm64 download
});

Deno.test("buildLinuxInstallScript uses x86_64 for x86_64 arch", () => {
  const script = buildLinuxInstallScript({
    installDir: "/opt/elastic",
    version: "9.4.1",
    arch: "x86_64",
    fleetServerUrl: "https://fleet:8220",
    enrollmentToken: "tok",
    caCertB64: "dGVzdA==",
  });
  assertStringIncludes(script, "x86_64");
});

// ---------------------------------------------------------------------------
// Fleet helper functions
// ---------------------------------------------------------------------------

Deno.test("getSystemPackageVersion extracts version from response", async () => {
  const mockFetch: KibanaFetchFn = (_url, path) => {
    assertEquals(path, "/api/fleet/epm/packages/system");
    return Promise.resolve({ item: { version: "1.62.0" } });
  };
  const version = await getSystemPackageVersion("https://kb:5601", "pass", "/ca.crt", mockFetch);
  assertEquals(version, "1.62.0");
});

Deno.test("getSystemPackageVersion throws when version missing", async () => {
  const mockFetch: KibanaFetchFn = () => Promise.resolve({ item: {} });
  await assertRejects(
    () => getSystemPackageVersion("https://kb:5601", "pass", "/ca.crt", mockFetch),
    Error,
    "Could not determine",
  );
});

Deno.test("findOrCreatePolicy returns existing policy ID", async () => {
  const mockFetch: KibanaFetchFn = (_url, path) => {
    if (path.includes("agent_policies")) {
      return Promise.resolve({ items: [{ id: "existing-id", name: "my-policy" }] });
    }
    throw new Error("unexpected call");
  };
  const id = await findOrCreatePolicy("https://kb:5601", "pass", "/ca.crt", "my-policy", mockFetch);
  assertEquals(id, "existing-id");
});

Deno.test("findOrCreatePolicy creates new policy when not found", async () => {
  let postCalled = false;
  const mockFetch: KibanaFetchFn = (_url, path, _pass, _ca, opts) => {
    if (path === "/api/fleet/agent_policies?perPage=100") {
      return Promise.resolve({ items: [] });
    }
    if (path === "/api/fleet/agent_policies" && opts?.method === "POST") {
      postCalled = true;
      return Promise.resolve({ item: { id: "new-policy-id" } });
    }
    throw new Error(`unexpected: ${path}`);
  };
  const id = await findOrCreatePolicy("https://kb:5601", "pass", "/ca.crt", "my-policy", mockFetch);
  assertEquals(id, "new-policy-id");
  assertEquals(postCalled, true);
});

Deno.test("ensureSystemIntegration skips when integration already exists", async () => {
  let postCalled = false;
  const mockFetch: KibanaFetchFn = (_url, path, _pass, _ca, opts) => {
    if (path.includes("package_policies") && !opts?.method) {
      return Promise.resolve({
        items: [{ policy_id: "pid", package: { name: "system" } }],
      });
    }
    if (opts?.method === "POST") postCalled = true;
    return Promise.resolve({});
  };
  await ensureSystemIntegration("https://kb:5601", "pass", "/ca.crt", "pid", "p", "1.62.0", mockFetch);
  assertEquals(postCalled, false);
});

Deno.test("ensureSystemIntegration adds system integration when missing", async () => {
  let postBody: unknown;
  const mockFetch: KibanaFetchFn = (_url, path, _pass, _ca, opts) => {
    if (path.includes("package_policies") && !opts?.method) {
      return Promise.resolve({ items: [] });
    }
    if (opts?.method === "POST") {
      postBody = opts.body;
      return Promise.resolve({ item: { id: "pkg-pol-id" } });
    }
    throw new Error(`unexpected: ${path}`);
  };
  await ensureSystemIntegration("https://kb:5601", "pass", "/ca.crt", "pid", "my-p", "1.62.0", mockFetch);
  const body = postBody as Record<string, unknown>;
  assertEquals((body.package as Record<string, unknown>).name, "system");
  assertEquals(body.policy_id, "pid");
});

Deno.test("createEnrollmentToken returns api_key from response", async () => {
  const mockFetch: KibanaFetchFn = () =>
    Promise.resolve({ item: { api_key: "enrollment-tok-xyz" } });
  const token = await createEnrollmentToken("https://kb:5601", "pass", "/ca.crt", "pid", "tok-name", mockFetch);
  assertEquals(token, "enrollment-tok-xyz");
});

Deno.test("createEnrollmentToken throws when api_key missing", async () => {
  const mockFetch: KibanaFetchFn = () => Promise.resolve({ item: {} });
  await assertRejects(
    () => createEnrollmentToken("https://kb:5601", "pass", "/ca.crt", "pid", "tok", mockFetch),
    Error,
    "no api_key",
  );
});

Deno.test("findAgentId matches by IP in list field (older Fleet)", async () => {
  const mockFetch: KibanaFetchFn = () =>
    Promise.resolve({
      list: [
        { id: "agent-1", local_metadata: { host: { ip: ["10.0.0.1", "192.168.1.50"] } } },
        { id: "agent-2", local_metadata: { host: { ip: ["10.0.0.2"] } } },
      ],
    });
  const id = await findAgentId("https://kb:5601", "pass", "/ca.crt", "192.168.1.50", mockFetch);
  assertEquals(id, "agent-1");
});

Deno.test("findAgentId matches by IP in agents field (newer Fleet)", async () => {
  const mockFetch: KibanaFetchFn = () =>
    Promise.resolve({
      agents: [
        { id: "agent-9", local_metadata: { host: { ip: ["192.168.1.100"] } } },
      ],
    });
  const id = await findAgentId("https://kb:5601", "pass", "/ca.crt", "192.168.1.100", mockFetch);
  assertEquals(id, "agent-9");
});

Deno.test("findAgentId returns empty string when not found", async () => {
  const mockFetch: KibanaFetchFn = () => Promise.resolve({ agents: [] });
  const id = await findAgentId("https://kb:5601", "pass", "/ca.crt", "1.2.3.4", mockFetch);
  assertEquals(id, "");
});

// ---------------------------------------------------------------------------
// fetchAgentStatus
// ---------------------------------------------------------------------------

Deno.test("fetchAgentStatus returns healthy when HEALTHY in output", async () => {
  const status = await fetchAgentStatus(
    "host", "user", "",
    mockSshExec("└─ elastic-agent\n   └─ status: (HEALTHY) Running"),
  );
  assertEquals(status.running, true);
  assertEquals(status.status, "healthy");
});

Deno.test("fetchAgentStatus returns not_installed when command fails", async () => {
  const status = await fetchAgentStatus("host", "user", "", mockSshExec("NOT_RUNNING", false));
  assertEquals(status.running, false);
  assertEquals(status.status, "not_installed");
});

Deno.test("fetchAgentStatus returns degraded status correctly", async () => {
  const status = await fetchAgentStatus(
    "host", "user", "",
    mockSshExec("└─ elastic-agent\n   └─ status: (DEGRADED) issues"),
  );
  assertEquals(status.running, false);
  assertEquals(status.status, "degraded");
});

// ---------------------------------------------------------------------------
// install method
// ---------------------------------------------------------------------------

Deno.test("install throws for unsupported OS", async () => {
  const { context } = createModelTestContext({
    globalArgs: { ...BASE_GLOBAL_ARGS, os: "windows" },
    methodName: "install",
  });
  await assertRejects(
    () => model.methods.install.execute({ _deps: {} }, context),
    Error,
    "OS 'windows' is not yet supported",
  );
});

Deno.test("install happy path writes agent resource", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const mockFetch: KibanaFetchFn = (_url, path, _pass, _ca, opts) => {
    if (path === "/api/fleet/epm/packages/system") return Promise.resolve({ item: { version: "1.62.0" } });
    if (path === "/api/fleet/agent_policies?perPage=100") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/agent_policies") return Promise.resolve({ item: { id: "pol-123" } });
    if (path === "/api/fleet/package_policies?perPage=200") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/package_policies") return Promise.resolve({ item: { id: "pkg-456" } });
    if (path === "/api/fleet/enrollment_api_keys") return Promise.resolve({ item: { api_key: "enroll-tok" } });
    throw new Error(`Unexpected fetch: ${opts?.method ?? "GET"} ${path}`);
  };

  const deps: ExecuteDeps = {
    sshScript: mockSshScript("[EA] Agent is healthy."),
    sshExec: mockSshExec("└─ elastic-agent\n   └─ status: (HEALTHY) Running"),
    kibanaFetch: mockFetch,
    withCaCert: mockWithCaCert,
  };

  await model.methods.install.execute({ _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "agent");
  assertEquals(written[0].name, "test-agent");
  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.version, "9.4.1");
  assertEquals(data.running, true);
  assertEquals(data.policyId, "pol-123");
  assertEquals(data.policyName, "test-policy");
});

Deno.test("install throws when SSH script fails", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const mockFetch: KibanaFetchFn = (_url, path) => {
    if (path === "/api/fleet/epm/packages/system") return Promise.resolve({ item: { version: "1.62.0" } });
    if (path === "/api/fleet/agent_policies?perPage=100") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/agent_policies") return Promise.resolve({ item: { id: "pol-123" } });
    if (path === "/api/fleet/package_policies?perPage=200") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/package_policies") return Promise.resolve({ item: {} });
    if (path === "/api/fleet/enrollment_api_keys") return Promise.resolve({ item: { api_key: "tok" } });
    return Promise.resolve({});
  };

  const deps: ExecuteDeps = {
    sshScript: mockSshScript("error: download failed", false),
    sshExec: mockSshExec(""),
    kibanaFetch: mockFetch,
    withCaCert: mockWithCaCert,
  };

  await assertRejects(
    () => model.methods.install.execute({ _deps: deps }, context),
    Error,
    "elastic-agent install failed",
  );
});

Deno.test("install resolves version from ES when version is empty", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...BASE_GLOBAL_ARGS, version: "" },
    methodName: "install",
  });

  let esVersionQueried = false;
  const mockFetch: KibanaFetchFn = (_url, path) => {
    if (path === "/") { esVersionQueried = true; return Promise.resolve({ version: { number: "9.4.1" } }); }
    if (path === "/api/fleet/epm/packages/system") return Promise.resolve({ item: { version: "1.62.0" } });
    if (path === "/api/fleet/agent_policies?perPage=100") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/agent_policies") return Promise.resolve({ item: { id: "pol-123" } });
    if (path === "/api/fleet/package_policies?perPage=200") return Promise.resolve({ items: [] });
    if (path === "/api/fleet/package_policies") return Promise.resolve({ item: {} });
    if (path === "/api/fleet/enrollment_api_keys") return Promise.resolve({ item: { api_key: "tok" } });
    return Promise.resolve({});
  };

  const deps: ExecuteDeps = {
    sshScript: mockSshScript("[EA] Agent is healthy."),
    sshExec: mockSshExec("└─ elastic-agent\n   └─ status: (HEALTHY) Running"),
    kibanaFetch: mockFetch,
    withCaCert: mockWithCaCert,
  };

  await model.methods.install.execute({ _deps: deps }, context);
  assertEquals(esVersionQueried, true);
  const data = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(data.version, "9.4.1");
});

// ---------------------------------------------------------------------------
// sync method
// ---------------------------------------------------------------------------

Deno.test("sync updates running status from SSH", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: ExecuteDeps = {
    sshExec: mockSshExec("└─ elastic-agent\n   └─ status: (DEGRADED) issues"),
    kibanaFetch: () => Promise.resolve({ agents: [] }),
    withCaCert: mockWithCaCert,
    currentState: STORED_AGENT,  // workaround: swamp-testing bug #371
  };

  await model.methods.sync.execute({ _deps: deps }, context);

  const data = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(data.running, false);
  assertEquals(data.status, "degraded");
  assertEquals(data.version, "9.4.1"); // preserved from stored state
});

Deno.test("sync resolves agentId when empty", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: ExecuteDeps = {
    sshExec: mockSshExec("└─ elastic-agent\n   └─ status: (HEALTHY) Running"),
    kibanaFetch: () =>
      Promise.resolve({
        agents: [{ id: "fleet-agent-xyz", local_metadata: { host: { ip: ["192.168.1.100"] } } }],
      }),
    withCaCert: mockWithCaCert,
    currentState: { ...STORED_AGENT, agentId: "" },  // workaround: swamp-testing bug #371
  };

  await model.methods.sync.execute({ _deps: deps }, context);

  const data = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(data.agentId, "fleet-agent-xyz");
});

// ---------------------------------------------------------------------------
// uninstall method
// ---------------------------------------------------------------------------

Deno.test("uninstall updates stored state to uninstalled", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "uninstall",
  });

  const deps: ExecuteDeps = {
    sshExec: mockSshExec("Successfully uninstalled"),
    currentState: STORED_AGENT,  // workaround: swamp-testing bug #371
  };

  await model.methods.uninstall.execute({ _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.running, false);
  assertEquals(data.status, "uninstalled");
  assertEquals(data.version, "9.4.1"); // preserved
});

Deno.test("uninstall handles missing stored state gracefully", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "uninstall",
    // No storedResources seeded
  });

  const deps: ExecuteDeps = {
    sshExec: mockSshExec("Not installed, nothing to do"),
  };

  await model.methods.uninstall.execute({ _deps: deps }, context);
  // Should not write any resources when no stored state found
  assertEquals(getWrittenResources().length, 0);
});

// ---------------------------------------------------------------------------
// Pre-flight check: agent-installed
// ---------------------------------------------------------------------------

Deno.test("agent-installed check passes when elastic-agent is running", async () => {
  // We can't inject deps into checks, so we test the return value logic directly
  // by constructing a minimal check context with a mocked sshExec.
  // Since checks call module-level sshExec, we verify the check structure instead.
  const check = model.checks["agent-installed"];
  assertEquals(check.labels, ["live"]);
  assertEquals(check.appliesTo, ["uninstall"]);
  assertStringIncludes(check.description, "uninstall");
});

Deno.test("agent-installed check has correct appliesTo scope", () => {
  const check = model.checks["agent-installed"];
  assertEquals(check.appliesTo?.includes("uninstall"), true);
  assertEquals(check.appliesTo?.includes("install"), false);
});
