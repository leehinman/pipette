// gcp-vm_test.ts — unit tests for the gcp-vm extension model.
// Run: deno test extensions/models/gcp-vm_test.ts
import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing";
import { fetchInstanceInfo, model, type ExecuteDeps, type RunGcloudFn } from "./gcp-vm.ts";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const BASE_GLOBAL_ARGS = {
  name: "test-vm",
  zone: "us-central1-a",
  project: "my-project",
  sshAuthorizedKeys: ["ssh-rsa AAAA... user@host"],
};

/** Minimal gcloud describe JSON response for a running instance. */
const DESCRIBE_RUNNING = JSON.stringify({
  status: "RUNNING",
  networkInterfaces: [{
    networkIP: "10.0.0.2",
    accessConfigs: [{ natIP: "34.1.2.3" }],
  }],
  machineType: "zones/us-central1-a/machineTypes/e2-standard-2",
  zone: "projects/my-project/zones/us-central1-a",
});

const DESCRIBE_TERMINATED = JSON.stringify({
  status: "TERMINATED",
  networkInterfaces: [{ networkIP: "10.0.0.2", accessConfigs: [] }],
  machineType: "zones/us-central1-a/machineTypes/e2-standard-2",
  zone: "projects/my-project/zones/us-central1-a",
});

/** Returns a RunGcloudFn that responds by subcommand action. */
function mockGcloud(
  responses: Record<string, { stdout: string; stderr: string; success: boolean }>,
): RunGcloudFn {
  return (args) => {
    const action = args[2]; // "describe" | "create" | "start" | "stop" | "delete"
    const match = responses[action] ?? responses["*"];
    if (!match) throw new Error(`Unexpected gcloud call: ${args.join(" ")}`);
    return Promise.resolve(match);
  };
}

function ok(stdout: string) { return { stdout, stderr: "", success: true }; }
function fail(stderr: string) { return { stdout: "", stderr, success: false }; }

const mkDeps = (runGcloud: RunGcloudFn): ExecuteDeps => ({ runGcloud });

// createModelTestContext returns MethodContext<Record<string,unknown>> but the
// model's execute methods are typed to the specific GlobalArgsSchema shape via
// satisfies — cast to any to avoid the type mismatch in tests.
// deno-lint-ignore no-explicit-any
type C = any;

// ---------------------------------------------------------------------------
// fetchInstanceInfo
// ---------------------------------------------------------------------------

Deno.test("fetchInstanceInfo parses external IP into ipv4 array", async () => {
  const info = await fetchInstanceInfo(
    "test-vm", "us-central1-a", "my-project",
    mockGcloud({ describe: ok(DESCRIBE_RUNNING) }),
  );
  assertEquals(info.ipv4, ["34.1.2.3"]);
  assertEquals(info.internalIp, "10.0.0.2");
  assertEquals(info.status, "RUNNING");
  assertEquals(info.machineType, "e2-standard-2");
  assertEquals(info.zone, "us-central1-a");
});

Deno.test("fetchInstanceInfo falls back to internal IP when no external IP", async () => {
  const noExternal = JSON.stringify({
    status: "RUNNING",
    networkInterfaces: [{ networkIP: "10.0.0.5", accessConfigs: [] }],
    machineType: "zones/us-central1-a/machineTypes/e2-standard-2",
    zone: "projects/my-project/zones/us-central1-a",
  });
  const info = await fetchInstanceInfo(
    "test-vm", "us-central1-a", "my-project",
    mockGcloud({ describe: ok(noExternal) }),
  );
  assertEquals(info.ipv4, ["10.0.0.5"]);
  assertEquals(info.internalIp, "10.0.0.5");
});

Deno.test("fetchInstanceInfo returns empty ipv4 when no IPs present", async () => {
  const noIps = JSON.stringify({
    status: "STAGING",
    networkInterfaces: [{}],
    machineType: "zones/us-central1-a/machineTypes/e2-standard-2",
    zone: "projects/my-project/zones/us-central1-a",
  });
  const info = await fetchInstanceInfo(
    "test-vm", "us-central1-a", "my-project",
    mockGcloud({ describe: ok(noIps) }),
  );
  assertEquals(info.ipv4, []);
  assertEquals(info.internalIp, undefined);
});

Deno.test("fetchInstanceInfo throws descriptive error when gcloud fails", async () => {
  await assertRejects(
    () => fetchInstanceInfo(
      "test-vm", "us-central1-a", "my-project",
      mockGcloud({ describe: fail("instance not found") }),
    ),
    Error,
    "gcloud describe failed",
  );
});

Deno.test("fetchInstanceInfo throws descriptive error on non-JSON gcloud output", async () => {
  await assertRejects(
    () => fetchInstanceInfo(
      "test-vm", "us-central1-a", "my-project",
      mockGcloud({ describe: ok("ERROR: (gcloud.compute) Some HTML error page") }),
    ),
    Error,
    "non-JSON",
  );
});

// ---------------------------------------------------------------------------
// create method
// ---------------------------------------------------------------------------

Deno.test("create happy path writes instance resource with external IP", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "create",
  });

  await model.methods.create.execute(
    { _deps: mkDeps(mockGcloud({ create: ok(""), describe: ok(DESCRIBE_RUNNING) }) ) },
    context as C,
  );

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "instance");
  assertEquals(written[0].name, "test-vm");
  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.status, "RUNNING");
  assertEquals((data.ipv4 as string[])[0], "34.1.2.3");
  assertEquals(data.machineType, "e2-standard-2");
});

Deno.test("create passes machine type and disk size to gcloud", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "create" });

  const capturedArgs: string[][] = [];
  const gcloud: RunGcloudFn = (args) => {
    capturedArgs.push(args);
    return Promise.resolve(args[2] === "create" ? ok("") : ok(DESCRIBE_RUNNING));
  };

  await model.methods.create.execute(
    { _deps: mkDeps(gcloud), machineType: "n2-standard-4", diskSizeGb: 50 },
    context as C,
  );

  const createCall = capturedArgs.find((a) => a[2] === "create")!.join(" ");
  assertStringIncludes(createCall, "n2-standard-4");
  assertStringIncludes(createCall, "50GB");
});

Deno.test("create injects SSH keys as ubuntu-prefixed metadata", async () => {
  const { context } = createModelTestContext({
    globalArgs: { ...BASE_GLOBAL_ARGS, sshAuthorizedKeys: ["ssh-rsa AAAA..."] },
    methodName: "create",
  });

  const capturedArgs: string[][] = [];
  const gcloud: RunGcloudFn = (args) => {
    capturedArgs.push(args);
    return Promise.resolve(args[2] === "create" ? ok("") : ok(DESCRIBE_RUNNING));
  };

  await model.methods.create.execute({ _deps: mkDeps(gcloud) }, context as C);

  const createCall = capturedArgs.find((a) => a[2] === "create")!.join(" ");
  assertStringIncludes(createCall, "ubuntu:ssh-rsa AAAA...");
});

Deno.test("create is idempotent when instance already exists", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "create",
  });

  await model.methods.create.execute(
    { _deps: mkDeps(mockGcloud({
      create: fail("resource 'test-vm' already exists"),
      describe: ok(DESCRIBE_RUNNING),
    })) },
    context as C,
  );

  assertEquals(getWrittenResources().length, 1);
  assertEquals((getWrittenResources()[0].data as Record<string, unknown>).status, "RUNNING");
});

Deno.test("create throws on unexpected gcloud failure", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "create" });

  await assertRejects(
    () => model.methods.create.execute(
      { _deps: mkDeps(mockGcloud({ create: fail("quota exceeded") })) },
      context as C,
    ),
    Error,
    "gcloud create failed",
  );
});

Deno.test("create applies network tags when provided", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "create" });

  const capturedArgs: string[][] = [];
  const gcloud: RunGcloudFn = (args) => {
    capturedArgs.push(args);
    return Promise.resolve(args[2] === "create" ? ok("") : ok(DESCRIBE_RUNNING));
  };

  await model.methods.create.execute(
    { _deps: mkDeps(gcloud), networkTags: ["elastic-stack", "bench"] },
    context as C,
  );

  const createCall = capturedArgs.find((a) => a[2] === "create")!.join(" ");
  assertStringIncludes(createCall, "--tags=elastic-stack,bench");
});

// ---------------------------------------------------------------------------
// sync method
// ---------------------------------------------------------------------------

Deno.test("sync refreshes stored state from live instance", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  await model.methods.sync.execute(
    { _deps: mkDeps(mockGcloud({ describe: ok(DESCRIBE_TERMINATED) })) },
    context as C,
  );

  assertEquals((getWrittenResources()[0].data as Record<string, unknown>).status, "TERMINATED");
});

// ---------------------------------------------------------------------------
// start method
// ---------------------------------------------------------------------------

Deno.test("start issues start command then syncs state", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "start",
  });

  const called: string[] = [];
  const gcloud: RunGcloudFn = (args) => {
    called.push(args[2]);
    return Promise.resolve(args[2] === "start" ? ok("") : ok(DESCRIBE_RUNNING));
  };

  await model.methods.start.execute({ _deps: mkDeps(gcloud) }, context as C);

  assertEquals(called.includes("start"), true);
  assertEquals(called.includes("describe"), true);
  assertEquals((getWrittenResources()[0].data as Record<string, unknown>).status, "RUNNING");
});

Deno.test("start throws on gcloud failure", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "start" });

  await assertRejects(
    () => model.methods.start.execute(
      { _deps: mkDeps(mockGcloud({ start: fail("instance not found") })) },
      context as C,
    ),
    Error,
    "gcloud start failed",
  );
});

// ---------------------------------------------------------------------------
// stop method
// ---------------------------------------------------------------------------

Deno.test("stop issues stop command then syncs state", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "stop",
  });

  const gcloud: RunGcloudFn = (args) =>
    Promise.resolve(args[2] === "stop" ? ok("") : ok(DESCRIBE_TERMINATED));

  await model.methods.stop.execute({ _deps: mkDeps(gcloud) }, context as C);

  assertEquals((getWrittenResources()[0].data as Record<string, unknown>).status, "TERMINATED");
});

Deno.test("stop throws on gcloud failure", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "stop" });

  await assertRejects(
    () => model.methods.stop.execute(
      { _deps: mkDeps(mockGcloud({ stop: fail("could not stop") })) },
      context as C,
    ),
    Error,
    "gcloud stop failed",
  );
});

// ---------------------------------------------------------------------------
// delete method
// ---------------------------------------------------------------------------

Deno.test("delete happy path returns no data handles", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "delete",
  });

  const result = await model.methods.delete.execute(
    { _deps: mkDeps(mockGcloud({ delete: ok("") })) },
    context as C,
  );

  assertEquals(result.dataHandles.length, 0);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("delete is idempotent when instance was not found", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "delete" });

  const result = await model.methods.delete.execute(
    { _deps: mkDeps(mockGcloud({ delete: fail("The resource 'test-vm' was not found") })) },
    context as C,
  );
  assertEquals(result.dataHandles.length, 0);
});

Deno.test("delete is idempotent when instance does not exist", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "delete" });

  const result = await model.methods.delete.execute(
    { _deps: mkDeps(mockGcloud({ delete: fail("instance does not exist") })) },
    context as C,
  );
  assertEquals(result.dataHandles.length, 0);
});

Deno.test("delete throws on unexpected gcloud failure", async () => {
  const { context } = createModelTestContext({ globalArgs: BASE_GLOBAL_ARGS, methodName: "delete" });

  await assertRejects(
    () => model.methods.delete.execute(
      { _deps: mkDeps(mockGcloud({ delete: fail("internal error: something went wrong") })) },
      context as C,
    ),
    Error,
    "gcloud delete failed",
  );
});
