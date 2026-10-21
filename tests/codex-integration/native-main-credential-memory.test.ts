import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { closeSync, lstatSync, mkdtempSync, openSync, readFileSync, readdirSync, renameSync, statSync, symlinkSync, truncateSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getMainAccountToken, getValidMainAccountToken, setMainAuthJsonBeforeRenameHookForTests } from "../../src/codex/main-account";
import { readCodexTokensResult } from "../../src/codex/auth-collision";
import { getNativeMainAuthMemory, observeNativeMainAuthFile, readNativeMainAuthDescriptorBounded, stopNativeMainCredentialWatchers } from "../../src/codex/native-main-credentials";
import { MAX_AUTH_BYTES } from "../../src/codex/native-profile-store";
import { resetOptionalShutdownHooksForTests, runOptionalShutdownHooks } from "../../src/lib/optional-shutdown-hooks";
import { removeTreeWithRetry } from "../helpers/remove-tree";
import { captureAtomicWritePublicationEvidence } from "../helpers/native-main-auth";
import { repoPath } from "../helpers/repo-root";
import { atomicWriteFile, atomicWriteFileAsync, type AtomicWriteAsyncIO, type AtomicWriteIO } from "../../src/config/atomic-write";
import { getConfigPath, getDefaultConfig } from "../../src/config";

type StoreMemoryRead = {
  status: string;
  fileStatus?: string;
  raw?: Buffer;
  digest?: string;
  observationError?: string;
  graceActive?: boolean;
  deletionConfirmed?: boolean;
  snapshot?: {
    raw: Buffer;
    digest: string;
    identity: { dev: number; ino: number };
    observationGeneration: number;
    isSymlink: boolean;
  };
};

type StoreModule = {
  NativeMainCredentialStore: new (options: {
    authPath: string;
    now?: () => number;
    graceMs?: number;
    fileSystem?: Record<string, (...args: any[]) => unknown>;
    writeSyncIO?: {
      write: (path: string, content: string) => void;
      harden: (path: string) => void;
      rename: (source: string, destination: string) => void;
      truncate: (path: string) => void;
      unlink: (path: string) => void;
    };
    writeAsyncIO?: AtomicWriteAsyncIO;
    claimExclusive?: (...args: any[]) => Promise<unknown>;
  }) => {
    start(): void;
    stop(): void;
    observeNow(): unknown;
    readMemory(): StoreMemoryRead;
    canRefreshOrWrite(): boolean;
    persistRefresh(raw: string, options: {
      expectedSnapshot: {
        digest: string;
        identity: { dev: number; ino: number };
        observationGeneration: number;
      };
      beforeRename?: () => void;
    }): Promise<unknown>;
    writeAuthFileAsync(raw: string, options: { expectedSnapshot: ReturnType<typeof captureFence>; beforeRename?: () => void }, writeOverride?: AtomicWriteAsyncIO): Promise<unknown>;
  };
  NATIVE_MAIN_AUTH_DELETE_GRACE_MS: number;
  NATIVE_MAIN_AUTH_CHECK_INTERVAL_MS: number;
  NATIVE_MAIN_AUTH_RETRY_INITIAL_MS: number;
};

let codexHome: string;
let opencodexHome: string;
let authPath: string;
let previousCodexHome: string | undefined;
let previousOcxHome: string | undefined;
let stores: Array<{ stop(): void }>;

function auth(accessToken: string, refreshToken = "refresh-old", accountId = "account-main"): string {
  return JSON.stringify({
    auth_mode: "chatgpt",
    tokens: {
      access_token: accessToken,
      refresh_token: refreshToken,
      account_id: accountId,
    },
  });
}

function captureFence(read: StoreMemoryRead) {
  const snapshot = read.snapshot;
  if (!snapshot) throw new Error("expected a complete native-main snapshot");
  return {
    digest: snapshot.digest,
    identity: { ...snapshot.identity },
    observationGeneration: snapshot.observationGeneration,
  };
}

function token(expSeconds = Math.floor(Date.now() / 1000) + 3600, accountId = "account-main"): string {
  const payload = Buffer.from(JSON.stringify({
    exp: expSeconds,
    "https://api.openai.com/auth": { chatgpt_account_id: accountId },
  })).toString("base64url");
  return "header." + payload + ".signature";
}

async function loadStoreModule(): Promise<StoreModule> {
  return await import("../../src/codex/native-main-credentials") as unknown as StoreModule;
}

beforeEach(() => {
  codexHome = mkdtempSync(join(tmpdir(), "ocx-native-main-memory-codex-"));
  opencodexHome = mkdtempSync(join(tmpdir(), "ocx-native-main-memory-ocx-"));
  authPath = join(codexHome, "auth.json");
  previousCodexHome = process.env.CODEX_HOME;
  previousOcxHome = process.env.OPENCODEX_HOME;
  process.env.CODEX_HOME = codexHome;
  process.env.OPENCODEX_HOME = opencodexHome;
  stores = [];
});

afterEach(() => {
  setMainAuthJsonBeforeRenameHookForTests(null);
  for (const store of stores) store.stop();
  stopNativeMainCredentialWatchers();
  if (previousCodexHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = previousCodexHome;
  if (previousOcxHome === undefined) delete process.env.OPENCODEX_HOME;
  else process.env.OPENCODEX_HOME = previousOcxHome;
  removeTreeWithRetry(codexHome);
  removeTreeWithRetry(opencodexHome);
});

describe("native-main credential memory", () => {
  test("the grace defaults to 60 seconds", async () => {
    const store = await loadStoreModule();
    let now = 1_000;
    let observe: (() => void) | undefined;
    const memory = new store.NativeMainCredentialStore({ authPath, now: () => now, fileSystem: {
      watchDirectory: (() => ({ close() {}, unref() {} })) as never,
      setInterval: ((callback: () => void) => { observe = callback; return { unref() {} }; }) as never,
    } });
    stores.push(memory);
    writeFileSync(authPath, auth("access-good"));
    memory.start();
    unlinkSync(authPath);
    observe?.();
    expect(store.NATIVE_MAIN_AUTH_DELETE_GRACE_MS).toBe(60_000);
    now = 60_999;
    observe?.();
    const retained = memory.readMemory();
    expect(retained.raw?.toString()).toContain("access-good");
    retained.raw?.fill(0);
    retained.snapshot?.raw.fill(0);
    now = 61_000;
    observe?.();
    const cleared = memory.readMemory();
    expect(cleared.status).toBe("missing");
    expect(cleared.raw).toBeUndefined();
    expect(cleared.deletionConfirmed).toBe(true);
    cleared.snapshot?.raw.fill(0);
  });

  test("a configured grace replaces the default", async () => {
    const store = await loadStoreModule();
    let now = 1_000;
    let observe: (() => void) | undefined;
    const memory = new store.NativeMainCredentialStore({ authPath, now: () => now, graceMs: 5_000, fileSystem: {
      watchDirectory: (() => ({ close() {}, unref() {} })) as never,
      setInterval: ((callback: () => void) => { observe = callback; return { unref() {} }; }) as never,
    } });
    stores.push(memory);
    writeFileSync(authPath, auth("access-good"));
    memory.start();
    unlinkSync(authPath);
    observe?.();
    now = 5_999;
    observe?.();
    const retained = memory.readMemory();
    expect(retained.raw?.toString()).toContain("access-good");
    retained.raw?.fill(0);
    retained.snapshot?.raw.fill(0);
    now = 6_000;
    observe?.();
    const cleared = memory.readMemory();
    expect(cleared.raw).toBeUndefined();
    expect(cleared.deletionConfirmed).toBe(true);
    cleared.snapshot?.raw.fill(0);
  });

  test("graceActive reports the running grace for an incomplete file", async () => {
    const store = await loadStoreModule();
    let observe: (() => void) | undefined;
    const memory = new store.NativeMainCredentialStore({ authPath, fileSystem: {
      watchDirectory: (() => ({ close() {}, unref() {} })) as never,
      setInterval: ((callback: () => void) => { observe = callback; return { unref() {} }; }) as never,
    } });
    stores.push(memory);
    writeFileSync(authPath, auth("access-good"));
    memory.start();
    writeFileSync(authPath, "");
    observe?.();
    const incomplete = memory.readMemory();
    expect(incomplete.graceActive).toBe(true);
    incomplete.raw?.fill(0);
    incomplete.snapshot?.raw.fill(0);
    writeFileSync(authPath, auth("access-next"));
    observe?.();
    const complete = memory.readMemory();
    expect(complete.graceActive).toBe(false);
    expect(complete.raw?.toString()).toContain("access-next");
    complete.raw?.fill(0);
    complete.snapshot?.raw.fill(0);
  });

  test("a read error or an incomplete file does not restart the grace", async () => {
    const store = await loadStoreModule();
    let now = 1_000;
    let failStat = false;
    const memory = new store.NativeMainCredentialStore({ authPath, now: () => now, fileSystem: {
      stat: ((path: string) => {
        if (failStat) throw Object.assign(new Error("stat failure"), { code: "EIO" });
        return statSync(path);
      }) as never,
      watchDirectory: (() => ({ close() {}, unref() {} })) as never,
      setInterval: (() => ({ unref() {} })) as never,
    } });
    stores.push(memory);
    writeFileSync(authPath, auth("access-good"));
    memory.start();
    unlinkSync(authPath);
    memory.observeNow();
    now = 31_000;
    failStat = true;
    memory.observeNow();
    failStat = false;
    const unreadable = memory.readMemory();
    expect(unreadable.fileStatus).toBe("unreadable");
    expect(unreadable.raw?.toString()).toContain("access-good");
    unreadable.raw?.fill(0);
    unreadable.snapshot?.raw.fill(0);
    now = 46_000;
    writeFileSync(authPath, "{\"tokens\":{\"access_token\":\"partial");
    memory.observeNow();
    const invalid = memory.readMemory();
    expect(invalid.fileStatus).toBe("invalid");
    expect(invalid.raw?.toString()).toContain("access-good");
    invalid.raw?.fill(0);
    invalid.snapshot?.raw.fill(0);
    now = 60_999;
    unlinkSync(authPath);
    memory.observeNow();
    const retained = memory.readMemory();
    expect(retained.raw?.toString()).toContain("access-good");
    retained.raw?.fill(0);
    retained.snapshot?.raw.fill(0);
    now = 61_000;
    memory.observeNow();
    const cleared = memory.readMemory();
    expect(cleared.status).toBe("missing");
    expect(cleared.raw).toBeUndefined();
    cleared.snapshot?.raw.fill(0);
  });

  test("an empty or partial file past the grace clears memory, the retained grant and its retry", async () => {
    const store = await loadStoreModule();
    for (const content of ["", "{\"tokens\":{\"access_token\":\"partial"] as const) {
      let now = 1_000;
      const timers: Array<() => void> = [];
      let onDirectoryEvent: (() => void) | undefined;
      let clearTimeoutCalls = 0;
      let writeCalls = 0;
      const memory = new store.NativeMainCredentialStore({
        authPath,
        now: () => now,
        fileSystem: {
          watchDirectory: ((_: string, onEvent: () => void) => {
            onDirectoryEvent = onEvent;
            return { close() {}, unref() {} };
          }) as never,
          setInterval: (() => ({ unref() {} })) as never,
          setTimeout: ((callback: () => void) => {
            timers.push(callback);
            return { unref() {} };
          }) as never,
          clearTimeout: (() => { clearTimeoutCalls++; }) as never,
        },
        writeSyncIO: {
          write: () => { writeCalls++; throw new Error("invalid file must not be replaced"); },
          harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
        },
      });
      stores.push(memory);
      writeFileSync(authPath, auth("access-old"));
      memory.start();
      const initial = memory.readMemory();
      const expectedSnapshot = captureFence(initial);
      initial.snapshot?.raw.fill(0);
      initial.raw?.fill(0);
      writeFileSync(authPath, content);
      onDirectoryEvent?.();
      const first = await memory.persistRefresh(auth("rotated-access", "rotated-refresh"), { expectedSnapshot });
      expect(first).toMatchObject({ status: "retained" });
      expect(timers).toHaveLength(1);
      now = 60_999;
      memory.observeNow();
      const retained = memory.readMemory();
      expect(retained.raw?.toString()).toContain("rotated-refresh");
      retained.raw?.fill(0);
      retained.snapshot?.raw.fill(0);
      now = 61_000;
      memory.observeNow();
      const cleared = memory.readMemory();
      expect(cleared.status).toBe("invalid");
      expect(cleared.fileStatus).toBe("invalid");
      expect(cleared.raw).toBeUndefined();
      expect(cleared.deletionConfirmed).toBe(true);
      expect(clearTimeoutCalls).toBe(1);
      cleared.snapshot?.raw.fill(0);
      timers[0]?.();
      for (let i = 0; i < 12; i++) await Promise.resolve();
      expect(writeCalls).toBe(0);
      const afterRetry = memory.readMemory();
      expect(afterRetry.raw).toBeUndefined();
      afterRetry.snapshot?.raw.fill(0);
      const second = await memory.persistRefresh(auth("rotated-access", "rotated-refresh"), { expectedSnapshot });
      expect(second).toMatchObject({ status: "deleted" });
      memory.stop();
    }
  });

  test("a complete file inside the grace switches the login at once and ends the grace", async () => {
    const store = await loadStoreModule();
    let now = 1_000;
    const memory = new store.NativeMainCredentialStore({ authPath, now: () => now, fileSystem: {
      watchDirectory: (() => ({ close() {}, unref() {} })) as never,
      setInterval: (() => ({ unref() {} })) as never,
    } });
    stores.push(memory);
    writeFileSync(authPath, auth("access-a", "refresh-a", "account-a"));
    memory.start();
    unlinkSync(authPath);
    memory.observeNow();
    now = 60_000;
    writeFileSync(authPath, auth("access-b", "refresh-b", "account-b"));
    memory.observeNow();
    const switched = memory.readMemory();
    expect(switched.raw?.toString()).toContain("access-b");
    expect(switched.fileStatus).toBe("valid");
    expect(switched.graceActive).toBe(false);
    expect(switched.deletionConfirmed).toBe(false);
    switched.raw?.fill(0);
    switched.snapshot?.raw.fill(0);
    now = 100_000;
    unlinkSync(authPath);
    memory.observeNow();
    const restarted = memory.readMemory();
    expect(restarted.raw?.toString()).toContain("access-b");
    restarted.raw?.fill(0);
    restarted.snapshot?.raw.fill(0);
    now = 159_999;
    memory.observeNow();
    const beforeExpiry = memory.readMemory();
    expect(beforeExpiry.raw?.toString()).toContain("access-b");
    beforeExpiry.raw?.fill(0);
    beforeExpiry.snapshot?.raw.fill(0);
    now = 160_000;
    memory.observeNow();
    const expired = memory.readMemory();
    expect(expired.status).toBe("missing");
    expect(expired.raw).toBeUndefined();
    expired.snapshot?.raw.fill(0);
  });

  test("logout: a deleted auth.json with no new file clears the login after the configured grace", async () => {
    writeFileSync(getConfigPath(), JSON.stringify({ ...getDefaultConfig(), nativeMainAuthGraceSeconds: 1 }));
    writeFileSync(authPath, auth("access-good"));
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
    unlinkSync(authPath);
    const first = observeNativeMainAuthFile(authPath);
    expect(first.status).toBe("ok");
    first.raw?.fill(0);
    first.snapshot?.raw.fill(0);
    const retained = getMainAccountToken();
    expect(retained?.accessToken).toBe("access-good");
    await Bun.sleep(1_100);
    const second = observeNativeMainAuthFile(authPath);
    expect(second.status).toBe("missing");
    expect(second.raw).toBeUndefined();
    second.snapshot?.raw.fill(0);
    expect(getMainAccountToken()).toBeNull();
  });

  test("the native auth IO override stays under central synchronous evidence capture", async () => {
    const storeModule = await loadStoreModule();
    const original = auth("access-old");
    const candidate = auth("access-override");
    writeFileSync(authPath, original, { mode: 0o600 });
    const memoryStore = new storeModule.NativeMainCredentialStore({ authPath });
    stores.push(memoryStore);
    const initial = memoryStore.observeNow();
    const expectedSnapshot = captureFence(initial);
    initial.snapshot?.raw.fill(0);
    initial.raw?.fill(0);
    let ctimeOnlyRewrite = false;
    const writerOverride: AtomicWriteAsyncIO = {
      write: (path, content) => writeFileSync(path, content, { mode: 0o600 }),
      harden: () => {},
      rename: async (source, target, afterReplace) => {
        renameSync(source, target);
        await Bun.sleep(30);
        const before = statSync(target);
        writeFileSync(target, candidate);
        utimesSync(target, before.atimeMs / 1000, before.mtimeMs / 1000);
        const after = statSync(target);
        ctimeOnlyRewrite = after.mtimeMs === before.mtimeMs && after.ctimeMs > before.ctimeMs;
        afterReplace?.();
      },
      truncate: path => truncateSync(path, 0),
      unlink: path => unlinkSync(path),
    };

    await expect(memoryStore.writeAuthFileAsync(candidate, { expectedSnapshot }, writerOverride)).rejects.toThrow(
      "did not capture publication evidence synchronously",
    );
    const observed = memoryStore.readMemory();
    expect(ctimeOnlyRewrite).toBe(true);
    expect(readFileSync(authPath, "utf8")).toBe(candidate);
    expect(observed.status).toBe("ok");
    observed.snapshot?.raw.fill(0);
    observed.raw?.fill(0);
  });

  test("a stop between default writer evidence capture and delivery clears publication state", async () => {
    const storeModule = await loadStoreModule();
    writeFileSync(authPath, auth("access-before-stop"), { mode: 0o600 });
    const memoryStore = new storeModule.NativeMainCredentialStore({ authPath });
    stores.push(memoryStore);
    const initial = memoryStore.observeNow();
    const expectedSnapshot = captureFence(initial);
    initial.snapshot?.raw.fill(0);
    initial.raw?.fill(0);

    await expect(memoryStore.writeAuthFileAsync(auth("access-after-stop"), {
      expectedSnapshot,
      beforeRename: () => {
        queueMicrotask(() => queueMicrotask(() => queueMicrotask(() => memoryStore.stop())));
      },
    })).rejects.toThrow("stopped");
    const stopped = memoryStore.readMemory();
    expect(stopped.status).toBe("stopped");
    expect(stopped.raw).toBeUndefined();
    expect(stopped.snapshot).toBeUndefined();
    expect(stopped.canRefreshOrWrite).toBe(false);
    expect(stopped.canWriteFile).toBe(false);
  });

  test("an injected rename cannot capture evidence after an asynchronous ctime-only rewrite", async () => {
    const content = auth("access-injected-rename");
    writeFileSync(authPath, content, { mode: 0o600 });
    let rewriteWasCtimeOnly = false;
    let evidenceWasCaptured = false;
    const io: AtomicWriteAsyncIO = {
      write: (path, value) => writeFileSync(path, value, { mode: 0o600 }),
      harden: () => {},
      rename: async (source, target, afterReplace) => {
        renameSync(source, target);
        await new Promise(resolve => setTimeout(resolve, 30));
        const before = statSync(target);
        writeFileSync(target, content);
        utimesSync(target, before.atimeMs / 1000, before.mtimeMs / 1000);
        const rewritten = statSync(target);
        rewriteWasCtimeOnly = rewritten.mtimeMs === before.mtimeMs && rewritten.ctimeMs > before.ctimeMs;
        afterReplace?.();
      },
      truncate: path => truncateSync(path, 0),
      unlink: path => unlinkSync(path),
    };

    await expect(atomicWriteFileAsync(authPath, content, io, undefined, {
      afterRenameEvidence: () => { evidenceWasCaptured = true; },
    })).rejects.toThrow();
    expect(rewriteWasCtimeOnly).toBe(true);
    expect(evidenceWasCaptured).toBe(false);
    expect(readFileSync(authPath, "utf8")).toBe(content);
  });

  test("the synchronous writer refuses evidence from an injected asynchronous rename", async () => {
    const content = auth("access-injected-sync-rename");
    writeFileSync(authPath, auth("access-old"), { mode: 0o600 });
    let evidenceWasCaptured = false;
    let rewriteWasCtimeOnly = false;
    let renameOperation: Promise<void> | undefined;
    const io: AtomicWriteIO = {
      write: (path, value) => writeFileSync(path, value, { mode: 0o600 }),
      harden: () => {},
      rename: ((source: string, target: string) => {
        renameOperation = (async () => {
          renameSync(source, target);
          await new Promise(resolve => setTimeout(resolve, 30));
          const before = statSync(target);
          writeFileSync(target, content);
          utimesSync(target, before.atimeMs / 1000, before.mtimeMs / 1000);
          const after = statSync(target);
          rewriteWasCtimeOnly = after.mtimeMs === before.mtimeMs && after.ctimeMs > before.ctimeMs;
        })();
        return renameOperation;
      }) as unknown as AtomicWriteIO["rename"],
      truncate: path => truncateSync(path, 0),
      unlink: path => unlinkSync(path),
    };

    expect(() => atomicWriteFile(authPath, content, io, {
      afterRenameEvidence: () => { evidenceWasCaptured = true; },
    })).toThrow("injected atomic rename did not capture publication evidence synchronously");
    await renameOperation;
    expect(rewriteWasCtimeOnly).toBe(true);
    expect(evidenceWasCaptured).toBe(false);
    expect(readFileSync(authPath, "utf8")).toBe(content);
  });

  test("an injected rename cannot capture evidence before replacing the target", async () => {
    const content = auth("access-injected-early-evidence");
    writeFileSync(authPath, auth("access-old"), { mode: 0o600 });
    let evidenceWasCaptured = false;
    const io: AtomicWriteAsyncIO = {
      write: (path, value) => writeFileSync(path, value, { mode: 0o600 }),
      harden: () => {},
      rename: (source, target, afterReplace) => {
        afterReplace?.();
        renameSync(source, target);
      },
      truncate: path => truncateSync(path, 0),
      unlink: path => unlinkSync(path),
    };

    await expect(atomicWriteFileAsync(authPath, content, io, undefined, {
      afterRenameEvidence: () => { evidenceWasCaptured = true; },
    })).rejects.toThrow("injected atomic rename evidence preceded publication");
    expect(evidenceWasCaptured).toBe(false);
    expect(readFileSync(authPath, "utf8")).toBe(content);
  });

  test("an empty Codex rewrite keeps serving the last good credential", () => {
    writeFileSync(authPath, auth("access-good"));
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
    writeFileSync(authPath, "");
    const observed = observeNativeMainAuthFile(authPath);
    expect(observed).toMatchObject({ status: "ok", fileStatus: "invalid" });
    observed.raw?.fill(0);
    observed.snapshot?.raw.fill(0);
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
  });

  test("a half-written Codex rewrite keeps serving the last good credential", () => {
    writeFileSync(authPath, auth("access-good"));
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
    writeFileSync(authPath, "{\"tokens\":{\"access_token\":\"partial");
    const observed = observeNativeMainAuthFile(authPath);
    expect(observed).toMatchObject({ status: "ok", fileStatus: "invalid" });
    observed.raw?.fill(0);
    observed.snapshot?.raw.fill(0);
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
  });

  test("deletion and restoration inside grace keeps the last good credential available", async () => {
    const store = await loadStoreModule();
    const memoryStore = new store.NativeMainCredentialStore({ authPath });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-good"));
    memoryStore.start();
    memoryStore.observeNow();
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
    unlinkSync(authPath);
    const missing = memoryStore.observeNow();
    expect(missing.graceActive).toBe(true);
    expect(missing.canRefreshOrWrite).toBe(false);
    expect(getMainAccountToken()?.accessToken).toBe("access-good");
    writeFileSync(authPath, auth("access-codex-new", "refresh-codex-new"));
    memoryStore.observeNow();
    expect(JSON.parse(memoryStore.readMemory().raw!.toString()).tokens.refresh_token).toBe("refresh-codex-new");
  });

  test("a directory watcher adopts a valid replacement immediately", async () => {
    const store = await loadStoreModule();
    let onDirectoryEvent: (() => void) | undefined;
    let watchedDirectory = "";
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: ((directory: string, onEvent: () => void) => {
          watchedDirectory = directory;
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-old"));
    memoryStore.start();
    writeFileSync(authPath, auth("access-codex-new", "refresh-codex-new"));
    onDirectoryEvent?.();
    expect(watchedDirectory).toBe(codexHome);
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-codex-new");
  });

  test("the stat timer adopts a change when the directory event is dropped", async () => {
    const store = await loadStoreModule();
    let onTimer: (() => void) | undefined;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: ((callback: () => void, delayMs: number) => {
          expect(delayMs).toBe(store.NATIVE_MAIN_AUTH_CHECK_INTERVAL_MS);
          onTimer = callback;
          return { unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-old"));
    memoryStore.start();
    writeFileSync(authPath, auth("access-codex-new", "refresh-codex-new"));
    onTimer?.();
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-codex-new");
  });

  test("a pre-write observation adopts a valid newer Codex credential", async () => {
    const store = await loadStoreModule();
    writeFileSync(authPath, auth(token(Math.floor(Date.now() / 1000) + 600)));
    const memoryStore = new store.NativeMainCredentialStore({ authPath });
    stores.push(memoryStore);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    const external = auth(token(Math.floor(Date.now() / 1000) + 7200), "refresh-codex-new");
    writeFileSync(authPath, external);
    await memoryStore.persistRefresh(auth("refreshed-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    expect(JSON.parse(memoryStore.readMemory().raw!.toString()).tokens.refresh_token).toBe("refresh-codex-new");
    expect(readFileSync(authPath, "utf8")).toBe(external);
  });

  test("a pre-write check hashes even when the stat signature is unchanged", async () => {
    const store = await loadStoreModule();
    const original = auth("access-old");
    writeFileSync(authPath, original);
    const stableStat = lstatSync(authPath);
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: { stat: (() => stableStat) as never },
    });
    stores.push(memoryStore);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    const external = auth("access-new", "refresh-new", "account-main");
    writeFileSync(authPath, external);
    const outcome = await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    const adopted = memoryStore.readMemory();
    const adoptedRaw = adopted.raw!.toString();
    adopted.snapshot?.raw.fill(0);
    adopted.raw?.fill(0);
    expect(outcome).toMatchObject({ status: "superseded" });
    expect(adoptedRaw).toContain('"refresh_token":"refresh-new"');
    expect(readFileSync(authPath, "utf8")).toBe(external);
  });

  test("an observed external write at final validation aborts the stale staged bytes", async () => {
    const store = await loadStoreModule();
    const original = JSON.stringify({ auth_mode: "chatgpt", tokens: {
      access_token: "old-access",
      refresh_token: "old-refresh",
      account_id: "account-main",
    } });
    const external = JSON.stringify({ auth_mode: "chatgpt", tokens: {
      access_token: "codex-access",
      refresh_token: "codex-refresh",
      account_id: "account-main",
    }, external_marker: "preserve" });
    let beforeRenameCalls = 0;
    let writeAttempts = 0;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
      },
      writeSyncIO: {
        write: (path, content) => {
          writeAttempts++;
          writeFileSync(path, content, { mode: 0o600 });
        },
        harden: () => {},
        rename: (source, target) => renameSync(source, target),
        truncate: path => truncateSync(path, 0),
        unlink: path => unlinkSync(path),
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);

    const result = await memoryStore.persistRefresh(auth("ocx-access", "ocx-refresh"), {
      expectedSnapshot,
      beforeRename: () => {
        beforeRenameCalls++;
        if (beforeRenameCalls === 1) writeFileSync(authPath, external);
      },
    });
    const observed = memoryStore.readMemory();
    const observedRaw = observed.raw!.toString("utf8");
    observed.snapshot?.raw.fill(0);
    observed.raw?.fill(0);

    expect(result).toMatchObject({ status: "superseded" });
    expect(beforeRenameCalls).toBe(1);
    expect(writeAttempts).toBe(1);
    expect(readFileSync(authPath, "utf8")).toBe(external);
    expect(observedRaw).toBe(external);
  });

  test("an API-key login supersedes a retained refresh and is adopted without a watcher throw", async () => {
    const store = await loadStoreModule();
    let onDirectoryEvent: (() => void) | undefined;
    let scheduledDelay = 0;
    const original = auth("old-access");
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: ((_: string, onEvent: () => void) => {
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
        setInterval: (() => ({ unref() {} })) as never,
        setTimeout: ((_: () => void, delay: number) => {
          scheduledDelay = delay;
          return {};
        }) as never,
      },
      writeSyncIO: {
        write: () => { throw Object.assign(new Error("disk unavailable"), { code: "EIO" }); },
        harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    expect(scheduledDelay).toBe(store.NATIVE_MAIN_AUTH_RETRY_INITIAL_MS);

    const external = JSON.stringify({ auth_mode: "apikey", OPENAI_API_KEY: "codex-api-key" });
    writeFileSync(authPath, external);
    expect(() => onDirectoryEvent?.()).not.toThrow();
    const observed = memoryStore.readMemory();
    const observedRaw = observed.raw!.toString("utf8");
    observed.snapshot?.raw.fill(0);
    observed.raw?.fill(0);
    expect(observedRaw).toBe(external);
    expect(readFileSync(authPath, "utf8")).toBe(external);
  });

  test("an access-only ChatGPT envelope is a hiccup and a later complete login wins", async () => {
    const store = await loadStoreModule();
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
      },
      writeSyncIO: {
        write: () => { throw Object.assign(new Error("disk unavailable"), { code: "EIO" }); },
        harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
      },
    });
    stores.push(memoryStore);
    const original = auth("access-old", "refresh-old");
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), { expectedSnapshot });

    const partial = JSON.stringify({ auth_mode: "chatgpt", tokens: { access_token: "other" } });
    writeFileSync(authPath, partial);
    memoryStore.observeNow();

    const hiccup = memoryStore.readMemory();
    const hiccupRaw = hiccup.snapshot?.raw.toString("utf8");
    hiccup.snapshot?.raw.fill(0);
    hiccup.raw?.fill(0);
    expect(hiccup).toMatchObject({ status: "ok", fileStatus: "invalid", canRefreshOrWrite: false });
    expect(hiccupRaw).toContain("rotated-refresh");
    expect(readFileSync(authPath, "utf8")).toBe(partial);

    const complete = auth("codex-access", "codex-refresh");
    writeFileSync(authPath, complete);
    memoryStore.observeNow();
    const adopted = memoryStore.readMemory();
    const adoptedRaw = adopted.snapshot?.raw.toString("utf8");
    adopted.snapshot?.raw.fill(0);
    adopted.raw?.fill(0);
    expect(adopted).toMatchObject({ status: "ok", fileStatus: "valid", canRefreshOrWrite: true });
    expect(adoptedRaw).toBe(complete);
  });

  test("a same-byte replacement observed during refresh invalidates the original publication snapshot", async () => {
    const store = await loadStoreModule();
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
      },
    });
    stores.push(memoryStore);
    const original = auth("access-old", "refresh-old");
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    const expectedIdentity = expected.identity;
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);

    const swapPath = join(codexHome, "same-bytes-auth.json");
    writeFileSync(swapPath, original);
    unlinkSync(authPath);
    renameSync(swapPath, authPath);
    memoryStore.observeNow();

    const outcome = await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    const observed = memoryStore.readMemory();
    const observedRaw = observed.snapshot?.raw.toString("utf8");
    observed.snapshot?.raw.fill(0);
    observed.raw?.fill(0);
    expect(outcome).toMatchObject({ status: "superseded" });
    expect(observed.identity).not.toEqual(expectedIdentity);
    expect(observedRaw).toBe(original);
    expect(readFileSync(authPath, "utf8")).toBe(original);
  });

  test("an observer read failure stays visible and the next timer retries adoption", async () => {
    const store = await loadStoreModule();
    let onDirectoryEvent: (() => void) | undefined;
    let onTimer: (() => void) | undefined;
    let failNextRead = false;
    let readCalls = 0;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        read: ((path: string) => {
          readCalls++;
          if (failNextRead) {
            failNextRead = false;
            throw Object.assign(new Error("temporary read failure"), { code: "EIO" });
          }
          return readFileSync(path);
        }) as never,
        watchDirectory: ((_: string, onEvent: () => void) => {
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
        setInterval: ((callback: () => void) => {
          onTimer = callback;
          return { unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-before"));
    memoryStore.start();
    writeFileSync(authPath, auth("access-after", "refresh-after"));
    failNextRead = true;
    expect(() => onDirectoryEvent?.()).not.toThrow();
    expect(memoryStore.readMemory()).toMatchObject({ status: "ok", fileStatus: "unreadable" });
    const failedReadCount = readCalls;

    onTimer?.();

    expect(readCalls).toBe(failedReadCount + 1);
    expect(memoryStore.readMemory()).toMatchObject({ status: "ok", fileStatus: "valid" });
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-after");
  });

  test("a symlinked auth.json continues to serve and observe its regular target", async () => {
    const store = await loadStoreModule();
    const targetPath = join(codexHome, "managed-auth.json");
    writeFileSync(targetPath, auth("symlink-access"));
    symlinkSync(targetPath, authPath);
    let onDirectoryEvent: (() => void) | undefined;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: ((_: string, onEvent: () => void) => {
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
        setInterval: (() => ({ unref() {} })) as never,
      },
    });
    stores.push(memoryStore);
    memoryStore.start();
    expect(memoryStore.readMemory().raw?.toString()).toContain("symlink-access");
    expect(readCodexTokensResult(authPath).status).toBe("ok");
    expect(readCodexTokensResult(authPath, { bounded: true }).status).toBe("unreadable");

    writeFileSync(targetPath, auth("symlink-replacement", "symlink-refresh"));
    expect(() => onDirectoryEvent?.()).not.toThrow();
    expect(memoryStore.readMemory().raw?.toString()).toContain("symlink-replacement");
  });

  test("bounded Codex token reads reject a symlinked auth.json", async () => {
    const targetPath = join(codexHome, "bounded-managed-auth.json");
    writeFileSync(targetPath, auth("bounded-symlink-access"));
    symlinkSync(targetPath, authPath);

    expect(readCodexTokensResult(authPath).status).toBe("ok");
    expect(readCodexTokensResult(authPath, { bounded: true }).status).toBe("unreadable");
  });

  test("a confirmed deletion clears memory and cannot be written back", async () => {
    const store = await loadStoreModule();
    let now = 1_000;
    let onTimer: (() => void) | undefined;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      now: () => now,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: ((callback: () => void) => {
          onTimer = callback;
          return { unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-good"));
    memoryStore.start();
    const previous = memoryStore.readMemory();
    const expectedSnapshot = captureFence(previous);
    unlinkSync(authPath);
    onTimer?.();
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-good");
    expect(memoryStore.canRefreshOrWrite()).toBe(false);
    now += store.NATIVE_MAIN_AUTH_DELETE_GRACE_MS + 1;
    onTimer?.();
    expect(memoryStore.readMemory().status).toBe("missing");
    expect(memoryStore.readMemory().raw).toBeUndefined();
    const outcome = await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    expect(outcome).toMatchObject({ status: "deleted" });
    expect(lstatSync(codexHome).isDirectory()).toBe(true);
    expect(() => lstatSync(authPath)).toThrow();
  });

  test("a Codex login at the rename boundary supersedes the rotated grant", async () => {
    writeFileSync(authPath, JSON.stringify({
      tokens: { access_token: token(Math.floor(Date.now() / 1000) - 60), refresh_token: "refresh-old", account_id: "account-main" },
    }));
    const externalAccess = token(Math.floor(Date.now() / 1000) + 600);
    const external = JSON.stringify({
      auth_mode: "chatgpt",
      tokens: {
        access_token: externalAccess,
        refresh_token: "refresh-codex-new",
        account_id: "account-main",
      },
    });
    let writerCalls = 0;
    setMainAuthJsonBeforeRenameHookForTests(() => {
      writerCalls++;
      writeFileSync(authPath, external);
    });
    const result = await getValidMainAccountToken({
      refreshToken: async () => ({
        access: "rotated-access",
        refresh: "rotated-refresh",
        expires: Date.now() + 3600_000,
        accountId: "account-main",
      }),
    });
    expect(writerCalls).toBe(1);
    expect(result?.accessToken).toBe("rotated-access");
    expect(readCodexTokensResult()).toMatchObject({
      status: "ok",
      tokens: { access_token: externalAccess, account_id: "account-main" },
    });
    expect(readFileSync(authPath, "utf8")).toBe(external);
  });

  test("an empty file retains a rotated grant until the last good file returns", async () => {
    const store = await loadStoreModule();
    const original = auth("access-old");
    const timers: Array<() => void> = [];
    let onDirectoryEvent: (() => void) | undefined;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: ((_: string, onEvent: () => void) => {
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
        setInterval: (() => ({ unref() {} })) as never,
        setTimeout: ((callback: () => void) => {
          timers.push(callback);
          return { unref() {} };
        }) as never,
      },
      writeSyncIO: {
        write: () => { throw new Error("invalid file must not be replaced"); },
        harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    writeFileSync(authPath, "");
    onDirectoryEvent?.();

    const result = await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });

    const retained = memoryStore.readMemory();
    const retainedRaw = retained.raw?.toString("utf8");
    retained.snapshot?.raw.fill(0);
    retained.raw?.fill(0);
    expect(result).toMatchObject({ status: "retained" });
    expect(retained).toMatchObject({ status: "ok", fileStatus: "invalid" });
    expect(retainedRaw).toContain("rotated-refresh");
    expect(readFileSync(authPath, "utf8")).toBe("");
    expect(timers).toHaveLength(1);

    writeFileSync(authPath, original);
    onDirectoryEvent?.();
    const restored = memoryStore.readMemory();
    const restoredRaw = restored.raw?.toString("utf8");
    restored.snapshot?.raw.fill(0);
    restored.raw?.fill(0);
    expect(restoredRaw).toBe(original);
  });

  test("a rotated grant stays in memory and retries promptly after a write error", async () => {
    const store = await loadStoreModule();
    let scheduledDelay = 0;
    let clearedRetry = false;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
        setTimeout: ((_: () => void, delay: number) => {
          scheduledDelay = delay;
          return {};
        }) as never,
        clearTimeout: (() => { clearedRetry = true; }) as never,
      },
      writeSyncIO: {
        write: () => { throw Object.assign(new Error("disk unavailable"), { code: "EIO" }); },
        harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
      },
    });
    stores.push(memoryStore);
    const original = auth("access-old");
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    const result = await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    const retained = memoryStore.readMemory();
    const retainedRaw = retained.raw!.toString();
    retained.snapshot?.raw.fill(0);
    retained.raw?.fill(0);
    expect(result).toMatchObject({ status: "retained" });
    expect(JSON.parse(retainedRaw).tokens.refresh_token).toBe("rotated-refresh");
    expect(readFileSync(authPath, "utf8")).toBe(original);
    expect(scheduledDelay).toBe(store.NATIVE_MAIN_AUTH_RETRY_INITIAL_MS);
    if ("snapshot" in result && result.snapshot) result.snapshot.raw.fill(0);
    memoryStore.stop();
    expect(clearedRetry).toBe(true);
  });

  test("a read hiccup on unchanged disk preserves and retries the retained rotated grant", async () => {
    const store = await loadStoreModule();
    const timers: Array<{ callback: () => void; delay: number }> = [];
    let failNextRead = false;
    let writeAttempts = 0;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      claimExclusive: (async (_context: unknown, operation: () => Promise<unknown>) => operation()) as never,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
        setTimeout: ((callback: () => void, delay: number) => {
          timers.push({ callback, delay });
          return {};
        }) as never,
        clearTimeout: (() => {}) as never,
        read: ((path: string) => {
          if (failNextRead) {
            failNextRead = false;
            throw Object.assign(new Error("temporary credential read failure"), { code: "EIO" });
          }
          return readFileSync(path);
        }) as never,
      },
      writeSyncIO: {
        write: (path, content) => {
          writeAttempts++;
          if (writeAttempts === 1) {
            failNextRead = true;
            throw Object.assign(new Error("first publication failed"), { code: "EIO" });
          }
          writeFileSync(path, content, { mode: 0o600 });
        },
        harden: () => {},
        rename: (source, target, afterReplace) => {
          renameSync(source, target);
          afterReplace?.();
        },
        truncate: path => truncateSync(path, 0),
        unlink: path => unlinkSync(path),
      },
    });
    stores.push(memoryStore);
    const original = auth("access-old", "refresh-old");
    writeFileSync(authPath, original);
    memoryStore.start();
    const initial = memoryStore.readMemory();
    const expectedSnapshot = captureFence(initial);
    initial.snapshot?.raw.fill(0);
    initial.raw?.fill(0);

    const first = await memoryStore.persistRefresh(auth("access-rotated", "refresh-rotated"), {
      expectedSnapshot,
    });
    expect(first).toMatchObject({ status: "retained" });
    expect(memoryStore.observeNow()).toMatchObject({ fileStatus: "unreadable" });
    const afterReadError = memoryStore.readMemory();
    expect(afterReadError.raw?.toString("utf8")).toContain("refresh-rotated");
    afterReadError.snapshot?.raw.fill(0);
    afterReadError.raw?.fill(0);

    expect(memoryStore.observeNow()).toMatchObject({ fileStatus: "valid" });
    expect(timers).toHaveLength(1);
    timers[0]!.callback();
    for (let turn = 0; turn < 12; turn++) await Promise.resolve();
    memoryStore.observeNow();
    const afterRetry = memoryStore.readMemory();
    const afterRetryRaw = afterRetry.raw?.toString("utf8");
    afterRetry.snapshot?.raw.fill(0);
    afterRetry.raw?.fill(0);
    expect(afterRetryRaw).toContain("refresh-rotated");
    expect(JSON.parse(readFileSync(authPath, "utf8")).tokens.refresh_token).toBe("refresh-rotated");
    expect(writeAttempts).toBe(2);
  });

  test("persistent write failures back off exponentially and a later retry publishes the grant", async () => {
    const store = await loadStoreModule();
    const timers: Array<{ callback: () => void; delay: number; cleared: boolean; fired: boolean }> = [];
    const delays: number[] = [];
    let allowWrite = false;
    let claimCount = 0;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      claimExclusive: (async (_context: unknown, operation: () => Promise<unknown>) => {
        claimCount++;
        return operation();
      }) as never,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
        setTimeout: ((callback: () => void, delay: number) => {
          delays.push(delay);
          const timer = { callback, delay, cleared: false, fired: false };
          timers.push(timer);
          return timer;
        }) as never,
        clearTimeout: ((timer: { cleared: boolean }) => { timer.cleared = true; }) as never,
      },
      writeSyncIO: {
        write: (path, content) => {
          if (!allowWrite) throw Object.assign(new Error("disk unavailable"), { code: "EIO" });
          writeFileSync(path, content, { mode: 0o600 });
        },
        harden: () => {},
        rename: (source, target, afterReplace) => {
          renameSync(source, target);
          afterReplace?.();
        },
        truncate: path => truncateSync(path, 0),
        unlink: path => unlinkSync(path),
      },
    });
    stores.push(memoryStore);
    const original = auth("access-old");
    writeFileSync(authPath, original);
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);

    await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });
    expect(delays).toEqual([store.NATIVE_MAIN_AUTH_RETRY_INITIAL_MS]);
    for (let attempt = 0; attempt < 6; attempt++) {
      const timer = timers.at(-1)!;
      timer.callback();
      for (let turn = 0; turn < 8; turn++) await Promise.resolve();
    }
    expect(delays).toEqual([50, 100, 200, 400, 800, 1_000, 1_000]);
    expect(claimCount).toBe(6);

    allowWrite = true;
    timers.at(-1)!.callback();
    for (let turn = 0; turn < 8; turn++) await Promise.resolve();
    expect(claimCount).toBe(7);
    expect(JSON.parse(readFileSync(authPath, "utf8")).tokens.refresh_token).toBe("rotated-refresh");
    expect(delays).toHaveLength(7);
  });

  test("a blocked retry is single-flight and stop aborts its claim wait", async () => {
    const store = await loadStoreModule();
    const timers: Array<{ callback: () => void; delay: number; cleared: boolean }> = [];
    let onInterval: (() => void) | undefined;
    let claimStarts = 0;
    const claimSignals: AbortSignal[] = [];
    let markStarted!: () => void;
    const started = new Promise<void>(resolve => { markStarted = resolve; });
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      claimExclusive: (async (_context: unknown, _operation: () => Promise<unknown>, options: { signal?: AbortSignal }) => {
        claimStarts++;
        if (options.signal) claimSignals.push(options.signal);
        markStarted();
        await new Promise<void>((resolve, reject) => {
          const signal = options.signal;
          if (!signal) return;
          if (signal.aborted) reject(signal.reason);
          else signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      }) as never,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: ((callback: () => void) => {
          onInterval = callback;
          return { unref() {} };
        }) as never,
        setTimeout: ((callback: () => void, delay: number) => {
          const timer = { callback, delay, cleared: false };
          timers.push(timer);
          return timer;
        }) as never,
        clearTimeout: ((timer: { cleared: boolean }) => { timer.cleared = true; }) as never,
      },
      writeSyncIO: {
        write: () => { throw Object.assign(new Error("disk unavailable"), { code: "EIO" }); },
        harden: () => {}, rename: () => {}, truncate: () => {}, unlink: () => {},
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-old"));
    memoryStore.start();
    const expected = memoryStore.readMemory();
    const expectedSnapshot = captureFence(expected);
    expected.snapshot?.raw.fill(0);
    expected.raw?.fill(0);
    await memoryStore.persistRefresh(auth("rotated-access", "rotated-refresh"), {
      expectedSnapshot,
    });

    const firstTimer = timers.at(-1)!;
    firstTimer.fired = true;
    firstTimer.callback();
    await started;
    onInterval?.();
    const queuedTimer = timers.at(-1)!;
    if (queuedTimer !== firstTimer) {
      queuedTimer.fired = true;
      queuedTimer.callback();
    }
    onInterval?.();
    expect(claimStarts).toBe(1);
    memoryStore.stop();
    for (let turn = 0; turn < 8; turn++) await Promise.resolve();
    expect(claimSignals).toHaveLength(1);
    expect(claimSignals[0]?.aborted).toBe(true);
    expect(timers.filter(timer => !timer.cleared && !timer.fired)).toHaveLength(0);
  });

  test("transient observations retain memory while a valid changed file is adopted", async () => {
    const store = await loadStoreModule();
    let onDirectoryEvent: (() => void) | undefined;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: ((_: string, onEvent: () => void) => {
          onDirectoryEvent = onEvent;
          return { close() {}, unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-good"));
    memoryStore.start();
    writeFileSync(authPath, "");
    onDirectoryEvent?.();
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-good");
    writeFileSync(authPath, auth("access-restored", "refresh-restored"));
    onDirectoryEvent?.();
    expect(memoryStore.readMemory().raw?.toString()).toContain("access-restored");
  });

  test.each(["apikey", "api_key"] as const)("complete API-key login in %s mode replaces ChatGPT memory", async authMode => {
    const store = await loadStoreModule();
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("chatgpt-access", "chatgpt-refresh"));
    memoryStore.start();
    writeFileSync(authPath, JSON.stringify({
      auth_mode: authMode,
      OPENAI_API_KEY: "codex-api-key",
      tokens: null,
    }));
    memoryStore.observeNow();

    const adopted = memoryStore.readMemory();
    const adoptedRaw = adopted.raw?.toString("utf8");
    adopted.snapshot?.raw.fill(0);
    adopted.raw?.fill(0);
    expect(adopted).toMatchObject({ status: "ok", fileStatus: "valid" });
    expect(adoptedRaw).toBe(JSON.stringify({
      auth_mode: authMode,
      OPENAI_API_KEY: "codex-api-key",
      tokens: null,
    }));
  });

  test("the bounded credential reader rejects concurrent growth and oversized files", () => {
    const original = Buffer.from("small complete credential");
    let contents = Buffer.from(original);
    const unchanged = readNativeMainAuthDescriptorBounded(
      BigInt(original.byteLength),
      (target, offset, length, position) => {
        const count = Math.min(length, contents.byteLength - position);
        contents.copy(target, offset, position, position + count);
        return count;
      },
      () => BigInt(contents.byteLength),
    );
    expect(unchanged).toEqual(original);
    unchanged.fill(0);

    let reads = 0;
    const readGrowing = (target: Buffer, offset: number, length: number, position: number): number => {
      const count = Math.min(length, contents.byteLength - position);
      contents.copy(target, offset, position, position + count);
      if (reads++ === 0) contents = Buffer.concat([contents, Buffer.from("-grew")]);
      return count;
    };
    expect(() => readNativeMainAuthDescriptorBounded(
      BigInt(original.byteLength),
      readGrowing,
      () => BigInt(contents.byteLength),
    )).toThrow("changed while being read");

    reads = 0;
    contents = Buffer.from(original);
    const readGrowingPastCap = (target: Buffer, offset: number, length: number, position: number): number => {
      const count = Math.min(length, contents.byteLength - position);
      contents.copy(target, offset, position, position + count);
      if (reads++ === 0) {
        contents = Buffer.alloc(MAX_AUTH_BYTES + 1);
        original.copy(contents);
      }
      return count;
    };
    expect(() => readNativeMainAuthDescriptorBounded(
      BigInt(original.byteLength),
      readGrowingPastCap,
      () => BigInt(contents.byteLength),
    )).toThrow("too large");

    let oversizedReadCalls = 0;
    expect(() => readNativeMainAuthDescriptorBounded(
      BigInt(MAX_AUTH_BYTES + 1),
      () => { oversizedReadCalls++; return 0; },
      () => 0n,
    )).toThrow("too large");
    expect(oversizedReadCalls).toBe(0);
  });

  test("the watcher hashes only after a stat signature changes", async () => {
    const store = await loadStoreModule();
    let onTimer: (() => void) | undefined;
    let statCalls = 0;
    let readCalls = 0;
    const realStat = lstatSync;
    const realRead = readFileSync;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        stat: ((path: string) => { statCalls++; return realStat(path); }) as never,
        read: ((path: string) => { readCalls++; return realRead(path); }) as never,
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: ((callback: () => void) => {
          onTimer = callback;
          return { unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-good"));
    memoryStore.start();
    const initialReads = readCalls;
    onTimer?.();
    expect(statCalls).toBeGreaterThan(1);
    expect(readCalls).toBe(initialReads);
    writeFileSync(authPath, auth("access-next"));
    onTimer?.();
    expect(readCalls).toBe(initialReads + 1);
  });

  test("a dropped event converges on same-size bytes with an unchanged stat signature", async () => {
    const store = await loadStoreModule();
    let now = 0;
    let onTimer: (() => void) | undefined;
    let readCalls = 0;
    const original = auth("access-old", "refresh-old");
    const replacement = auth("access-new", "refresh-new");
    expect(Buffer.byteLength(original)).toBe(Buffer.byteLength(replacement));
    writeFileSync(authPath, original);
    const stableStat = lstatSync(authPath);
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      now: () => now,
      fileSystem: {
        stat: (() => stableStat) as never,
        lstat: (() => stableStat) as never,
        read: ((path: string) => {
          readCalls++;
          return readFileSync(path);
        }) as never,
        watchDirectory: (() => ({ close() {}, unref() {} })) as never,
        setInterval: ((callback: () => void) => {
          onTimer = callback;
          return { unref() {} };
        }) as never,
      },
    });
    stores.push(memoryStore);
    memoryStore.start();
    const initialReads = readCalls;
    writeFileSync(authPath, replacement);

    now += 999;
    onTimer?.();
    expect(readCalls).toBe(initialReads);
    expect(memoryStore.readMemory().raw?.toString("utf8")).toBe(original);

    now += 1;
    onTimer?.();
    const observed = memoryStore.readMemory();
    const observedRaw = observed.snapshot?.raw.toString("utf8");
    observed.snapshot?.raw.fill(0);
    observed.raw?.fill(0);
    expect(readCalls).toBe(initialReads + 1);
    expect(observedRaw).toBe(replacement);
  });

  test("the watcher and timer stop cleanly", async () => {
    const store = await loadStoreModule();
    let watcherClosed = false;
    let timerCleared = false;
    const memoryStore = new store.NativeMainCredentialStore({
      authPath,
      fileSystem: {
        watchDirectory: (() => ({ close() { watcherClosed = true; }, unref() {} })) as never,
        setInterval: (() => ({ unref() {} })) as never,
        clearInterval: (() => { timerCleared = true; }) as never,
      },
    });
    stores.push(memoryStore);
    writeFileSync(authPath, auth("access-good"));
    memoryStore.start();
    memoryStore.stop();
    expect(watcherClosed).toBe(true);
    expect(timerCleared).toBe(true);
  });

  test("an accessor after the shutdown sweep returns stopped without restarting observation", () => {
    resetOptionalShutdownHooksForTests();
    writeFileSync(authPath, auth("access-good"));
    const beforeShutdown = getNativeMainAuthMemory(authPath);
    expect(beforeShutdown.status).toBe("ok");
    beforeShutdown.snapshot?.raw.fill(0);
    beforeShutdown.raw?.fill(0);

    try {
      runOptionalShutdownHooks();
      const afterShutdown = getNativeMainAuthMemory(authPath);
      expect(afterShutdown.status).toBe("stopped");
      expect(afterShutdown.canRefreshOrWrite).toBe(false);
      afterShutdown.snapshot?.raw.fill(0);
      afterShutdown.raw?.fill(0);
    } finally {
      stopNativeMainCredentialWatchers();
      resetOptionalShutdownHooksForTests();
    }
  });
});
