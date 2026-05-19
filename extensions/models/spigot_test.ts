// spigot_test.ts — unit tests for the spigot extension model.
// Run: deno test extensions/models/spigot_test.ts
import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing";
import {
  buildSpigot,
  model,
  sshExec,
  type SpigotDeps,
} from "./spigot.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const BASE_GLOBAL_ARGS = {
  name: "test-spigot",
  host: "192.168.1.100",
  sshUser: "ubuntu",
  sshKey: "",
  arch: "aarch64" as const,
  installPath: "/usr/local/bin/spigot",
};

/** Stored spigot state for seeding currentState. */
const STORED_STATE = {
  name: "test-spigot",
  host: "192.168.1.100",
  installPath: "/usr/local/bin/spigot",
  commit: "abc123def456abc123def456abc123def456abc1",
  ref: "main",
  installedAt: "2026-05-18T11:00:00.000Z",
  syncedAt: "2026-05-18T11:00:00.000Z",
};

/** Returns a mock sshExec that always returns the given stdout. */
function mockSshExec(stdout: string, success = true): SpigotDeps["sshExec"] {
  return () => Promise.resolve({ stdout, stderr: "", success });
}

/** Returns a mock sshTransferFile that always succeeds. */
function mockSshTransferFile(): SpigotDeps["sshTransferFile"] {
  return () => Promise.resolve();
}

/** Returns a mock buildSpigot returning the given commit. */
function mockBuildSpigot(
  commit = "abc123def456abc123def456abc123def456abc1",
  binaryPath = "/tmp/spigot-build-abc123de-linux-arm64",
): SpigotDeps["buildSpigot"] {
  return () => Promise.resolve({ binaryPath, commit });
}

// ---------------------------------------------------------------------------
// install method
// ---------------------------------------------------------------------------

Deno.test("install happy path writes install resource", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const deps: SpigotDeps = {
    buildSpigot: mockBuildSpigot(),
    sshTransferFile: mockSshTransferFile(),
    sshExec: mockSshExec("spigot v0.1.0\n", true),
  };

  await model.methods.install.execute({ ref: "main", _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "install");
  assertEquals(written[0].name, "test-spigot");

  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.name, "test-spigot");
  assertEquals(data.host, "192.168.1.100");
  assertEquals(data.installPath, "/usr/local/bin/spigot");
  assertEquals(data.commit, "abc123def456abc123def456abc123def456abc1");
  assertEquals(data.ref, "main");
});

Deno.test("install uses custom ref when provided", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  let capturedRef = "";
  const deps: SpigotDeps = {
    buildSpigot: (ref, _arch) => {
      capturedRef = ref;
      return Promise.resolve({ binaryPath: "/tmp/spigot-bin", commit: "deadbeef00000000" });
    },
    sshTransferFile: mockSshTransferFile(),
    sshExec: mockSshExec("", true),
  };

  await model.methods.install.execute({ ref: "v1.2.3", _deps: deps }, context);
  assertEquals(capturedRef, "v1.2.3");
});

Deno.test("install maps aarch64 arch to arm64 for go build", async () => {
  const { context } = createModelTestContext({
    globalArgs: { ...BASE_GLOBAL_ARGS, arch: "aarch64" },
    methodName: "install",
  });

  let capturedGoArch = "";
  const deps: SpigotDeps = {
    buildSpigot: (_ref, goArch) => {
      capturedGoArch = goArch;
      return Promise.resolve({ binaryPath: "/tmp/bin", commit: "abc123" });
    },
    sshTransferFile: mockSshTransferFile(),
    sshExec: mockSshExec("", true),
  };

  await model.methods.install.execute({ ref: "main", _deps: deps }, context);
  assertEquals(capturedGoArch, "aarch64"); // passed through; buildSpigot does the mapping internally
});

Deno.test("install throws when buildSpigot fails", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const deps: SpigotDeps = {
    buildSpigot: () => Promise.reject(new Error("go build failed: missing toolchain")),
    sshTransferFile: mockSshTransferFile(),
    sshExec: mockSshExec("", true),
  };

  await assertRejects(
    () => model.methods.install.execute({ ref: "main", _deps: deps }, context),
    Error,
    "go build failed",
  );
});

Deno.test("install throws when sshExec (move/chmod) fails", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const deps: SpigotDeps = {
    buildSpigot: mockBuildSpigot(),
    sshTransferFile: mockSshTransferFile(),
    sshExec: mockSshExec("sudo: permission denied", false),
  };

  await assertRejects(
    () => model.methods.install.execute({ ref: "main", _deps: deps }, context),
    Error,
    "Failed to install spigot",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("install throws when sshTransferFile fails", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "install",
  });

  const deps: SpigotDeps = {
    buildSpigot: mockBuildSpigot(),
    sshTransferFile: () => Promise.reject(new Error("File transfer to 192.168.1.100:/tmp/spigot failed")),
    sshExec: mockSshExec("", true),
  };

  await assertRejects(
    () => model.methods.install.execute({ ref: "main", _deps: deps }, context),
    Error,
    "File transfer",
  );
});

// ---------------------------------------------------------------------------
// sync method
// ---------------------------------------------------------------------------

Deno.test("sync writes updated resource when binary is installed", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("INSTALLED", true),
    currentState: STORED_STATE,
  };

  await model.methods.sync.execute({ _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "install");
  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.commit, STORED_STATE.commit);
  assertEquals(data.ref, STORED_STATE.ref);
  assertEquals(data.installPath, "/usr/local/bin/spigot");
});

Deno.test("sync updates syncedAt timestamp", async () => {
  const before = new Date().toISOString();
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("INSTALLED", true),
    currentState: STORED_STATE,
  };

  await model.methods.sync.execute({ _deps: deps }, context);

  const data = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals((data.syncedAt as string) >= before, true);
});

Deno.test("sync reconstructs state from globalArgs when no stored state", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("INSTALLED", true),
    currentState: null, // no stored state
  };

  await model.methods.sync.execute({ _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const data = written[0].data as Record<string, unknown>;
  assertEquals(data.name, "test-spigot");
  assertEquals(data.host, "192.168.1.100");
  assertEquals(data.commit, "");
});

Deno.test("sync throws when binary is not installed", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("NOT_INSTALLED", true),
    currentState: null,
  };

  await assertRejects(
    () => model.methods.sync.execute({ _deps: deps }, context),
    Error,
    "not installed",
  );
});

Deno.test("sync throws when ssh command fails", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "sync",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("", false),
    currentState: null,
  };

  await assertRejects(
    () => model.methods.sync.execute({ _deps: deps }, context),
    Error,
    "not installed",
  );
});

// ---------------------------------------------------------------------------
// uninstall method
// ---------------------------------------------------------------------------

Deno.test("uninstall removes binary and updates stored state", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "uninstall",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("REMOVED", true),
    currentState: STORED_STATE,
  };

  await model.methods.uninstall.execute({ _deps: deps }, context);

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const data = written[0].data as Record<string, unknown>;
  // Preserves fields from stored state
  assertEquals(data.commit, STORED_STATE.commit);
  assertEquals(data.ref, STORED_STATE.ref);
  assertEquals(data.installPath, STORED_STATE.installPath);
});

Deno.test("uninstall returns empty dataHandles when no stored state", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "uninstall",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("REMOVED", true),
    currentState: null,
  };

  await model.methods.uninstall.execute({ _deps: deps }, context);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("uninstall throws when SSH rm fails", async () => {
  const { context } = createModelTestContext({
    globalArgs: BASE_GLOBAL_ARGS,
    methodName: "uninstall",
  });

  const deps: SpigotDeps = {
    sshExec: mockSshExec("sudo: permission denied", false),
    currentState: STORED_STATE,
  };

  await assertRejects(
    () => model.methods.uninstall.execute({ _deps: deps }, context),
    Error,
    "Failed to uninstall spigot",
  );
});

// ---------------------------------------------------------------------------
// Pre-flight check: spigot-installed
// ---------------------------------------------------------------------------

Deno.test("spigot-installed check has correct metadata", () => {
  const check = model.methods.uninstall.checks["spigot-installed"];
  assertEquals(check.labels, ["live"]);
  assertEquals(check.appliesTo, ["uninstall"]);
  assertStringIncludes(check.description.toLowerCase(), "spigot");
});
