import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  statSync,
  watch as watchFsDirectory,
  type FSWatcher,
  type Stats,
} from "node:fs";
import { dirname, resolve } from "node:path";
import {
  atomicWriteFile,
  atomicWriteFileAsync,
  resolveWriteTarget,
  type AtomicWriteAsyncHooks,
  type AtomicWriteAsyncIO,
  type AtomicWriteHooks,
  type AtomicWriteIO,
  type AtomicWritePublicationEvidence,
  type AtomicWriteTargetIdentity,
} from "../config/atomic-write";
import { advanceCodexCredentialMutationEpoch } from "./credential-mutation-epoch";
import {
  NATIVE_MAIN_AUTH_CHECK_INTERVAL_MS,
  NATIVE_MAIN_AUTH_DELETE_GRACE_MS,
  NATIVE_MAIN_AUTH_FORCE_READ_INTERVAL_MS,
  NATIVE_MAIN_AUTH_RETRY_INITIAL_MS,
  NATIVE_MAIN_AUTH_RETRY_MAX_MS,
} from "./native-main-credential-config";
import { withNativeMainExclusiveClaim } from "./native-main-claim";
import {
  MAX_AUTH_BYTES,
  resolveNativeProfileContext,
} from "./native-profile-store";
import { didRunOptionalShutdownHooks, registerOptionalShutdownHook } from "../lib/optional-shutdown-hooks";

export {
  NATIVE_MAIN_AUTH_CHECK_INTERVAL_MS,
  NATIVE_MAIN_AUTH_DELETE_GRACE_MS,
  NATIVE_MAIN_AUTH_FORCE_READ_INTERVAL_MS,
  NATIVE_MAIN_AUTH_RETRY_INITIAL_MS,
  NATIVE_MAIN_AUTH_RETRY_MAX_MS,
} from "./native-main-credential-config";

export type NativeMainAuthStatus = "ok" | "missing" | "invalid" | "unreadable" | "stopped";
export type NativeMainAuthFileStatus = "valid" | "missing" | "invalid" | "unreadable";
export type NativeMainAuthLeafProvenance = "regular" | "link" | "unknown";

interface NativeMainAuthStatSignature {
  dev: number;
  ino: number;
  size: number;
  mode: number;
  mtimeMs: number;
  ctimeMs: number;
}

interface NativeMainAuthPhysicalSignature {
  target: Readonly<NativeMainAuthStatSignature> | null;
  leaf: Readonly<NativeMainAuthStatSignature> | null;
}

export interface NativeMainAuthIdentity {
  dev: number;
  ino: number;
}

export interface NativeMainAuthSnapshot {
  path: string;
  raw: Buffer;
  digest: string;
  identity: NativeMainAuthIdentity;
  observationGeneration: number;
  observationSequence: number;
  isSymlink: boolean;
  leafProvenance: NativeMainAuthLeafProvenance;
  statSignature: Readonly<NativeMainAuthStatSignature>;
  physicalSignature: string;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

export interface NativeMainAuthWriteFence {
  digest: string;
  identity: NativeMainAuthIdentity;
  observationGeneration: number;
}

export interface NativeMainAuthWriteReceipt {
  readonly path: string;
  readonly digest: string;
  readonly identity: Readonly<NativeMainAuthIdentity>;
  readonly observationGeneration: number;
  readonly observationSequence: number;
  readonly publicationId: number;
  readonly statSignature: string;
}

export interface NativeMainAuthMemoryRead {
  status: NativeMainAuthStatus;
  fileStatus: NativeMainAuthFileStatus;
  graceActive: boolean;
  canRefreshOrWrite: boolean;
  canWriteFile: boolean;
  isSymlink: boolean;
  leafProvenance: NativeMainAuthLeafProvenance;
  deletionConfirmed: boolean;
  observationGeneration: number;
  observationSequence: number;
  observationError?: string;
  snapshot?: NativeMainAuthSnapshot;
  raw?: Buffer;
  digest?: string;
  identity?: NativeMainAuthIdentity;
}

export interface NativeMainCredentialWatcher {
  close(): void;
  unref?(): void;
}

export interface NativeMainCredentialFileSystem {
  lstat(path: string): Stats;
  stat(path: string): Stats;
  read(path: string): Buffer | string;
  watchDirectory(
    path: string,
    onEvent: () => void,
    onError: () => void,
  ): NativeMainCredentialWatcher;
  setInterval(callback: () => void, delayMs: number): NodeJS.Timeout;
  clearInterval(timer: NodeJS.Timeout): void;
  setTimeout(callback: () => void, delayMs: number): NodeJS.Timeout;
  clearTimeout(timer: NodeJS.Timeout): void;
}

export interface NativeMainCredentialStoreOptions {
  authPath: string;
  now?: () => number;
  fileSystem?: Partial<NativeMainCredentialFileSystem>;
  writeSyncIO?: AtomicWriteIO;
  writeAsyncIO?: AtomicWriteAsyncIO;
  claimExclusive?: typeof withNativeMainExclusiveClaim;
}

export interface NativeMainRefreshWriteOptions {
  expectedSnapshot: NativeMainAuthWriteFence;
  beforeRename?: () => void;
}

export interface NativeMainAuthWriteOptions {
  expectedSnapshot: NativeMainAuthWriteFence;
  beforeRename?: () => void;
}

export type NativeMainAuthWriteOverride = AtomicWriteAsyncIO;

export type NativeMainRefreshWriteResult =
  | { status: "written"; snapshot: NativeMainAuthSnapshot; receipt: NativeMainAuthWriteReceipt }
  | { status: "retained"; snapshot: NativeMainAuthSnapshot }
  | { status: "recovery-required"; snapshot?: NativeMainAuthSnapshot }
  | { status: "superseded"; snapshot?: NativeMainAuthSnapshot }
  | { status: "deleted" | "stopped" };

interface ObservationHistoryEntry {
  kind: "complete" | "unknown" | "invalid" | "missing";
  generation: number;
  digest?: string;
  identity?: NativeMainAuthIdentity;
  physicalSignature?: string;
}

type ObservationExistence = "present" | "absent" | "unknown";

type ObservationContent =
  | { kind: "complete"; raw: string; digest: string; identity: NativeMainAuthIdentity }
  | { kind: "incomplete" | "invalid"; digest: string; identity: NativeMainAuthIdentity }
  | { kind: "unreadable" };

interface NativeMainAuthObservation {
  readonly existence: ObservationExistence;
  readonly witnessedPresence: boolean;
  readonly leafProvenance: NativeMainAuthLeafProvenance;
  readonly content: Readonly<ObservationContent>;
  readonly statSignature: Readonly<NativeMainAuthPhysicalSignature> | null;
  readonly error?: string;
  readonly source: "unowned" | "publication" | "receipt-check";
  readonly publicationId?: number;
}

interface PublicationAuthority {
  readonly publicationId: number;
  readonly observationSequence: number;
  readonly unownedObservationSequence: number;
  readonly observationGeneration: number;
  readonly identity: Readonly<NativeMainAuthIdentity>;
  readonly digest: string;
  readonly raw: string;
}

export class NativeMainAuthChangedError extends Error {
  constructor() {
    super("Codex auth.json changed before native-main publication");
    this.name = "NativeMainAuthChangedError";
  }
}

export class NativeMainAuthDeletedError extends Error {
  constructor() {
    super("Codex auth.json deletion was confirmed");
    this.name = "NativeMainAuthDeletedError";
  }
}

export class NativeMainAuthStoppedError extends Error {
  constructor() {
    super("Native-main credential access is stopped after shutdown.");
    this.name = "NativeMainAuthStoppedError";
  }
}

type AuthRoot = Record<string, unknown>;

interface PendingRefresh {
  raw: string;
  digest: string;
  expectedSnapshot: NativeMainAuthSnapshot;
  retryFence: NativeMainAuthWriteFence;
  retryPhysicalSignature: string;
  generation: number;
  retryDelayMs: number;
  recoveryRequired: boolean;
}

const MAX_PUBLICATION_HISTORY = 256;

export function readNativeMainAuthDescriptorBounded(
  initialSize: bigint,
  read: (buffer: Buffer, offset: number, length: number, position: number) => number,
  currentSize: () => bigint,
): Buffer {
  const maximumBytes = BigInt(MAX_AUTH_BYTES);
  if (initialSize < 0n || initialSize > maximumBytes) {
    throw new Error("native-main credential file is too large");
  }
  let buffer = Buffer.alloc(Math.max(1, Number(initialSize)));
  let total = 0;
  try {
    while (true) {
      if (total === buffer.byteLength) {
        if (total > MAX_AUTH_BYTES) throw new Error("native-main credential file is too large");
        const nextSize = Math.min(MAX_AUTH_BYTES + 1, Math.max(64, buffer.byteLength * 2));
        const grown = Buffer.alloc(nextSize);
        buffer.copy(grown, 0, 0, total);
        buffer.fill(0);
        buffer = grown;
      }
      const bytesRead = read(buffer, total, buffer.byteLength - total, total);
      if (!Number.isInteger(bytesRead) || bytesRead < 0 || bytesRead > buffer.byteLength - total) {
        throw new Error("invalid native-main credential read length");
      }
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_AUTH_BYTES) throw new Error("native-main credential file is too large");
    }
    const finishedSize = currentSize();
    if (finishedSize !== initialSize || BigInt(total) !== finishedSize) {
      throw new Error("native-main credential file changed while being read");
    }
    return Buffer.from(buffer.subarray(0, total));
  } finally {
    buffer.fill(0);
  }
}

function readNativeMainAuthFile(path: string): Buffer {
  let descriptor: number | undefined;
  let failed = false;
  try {
    const flags = process.platform === "win32"
      ? fsConstants.O_RDONLY
      : fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
    descriptor = openSync(path, flags);
    const opened = fstatSync(descriptor, { bigint: true });
    if (!opened.isFile()) {
      throw new Error("invalid native-main credential file");
    }
    return readNativeMainAuthDescriptorBounded(
      opened.size,
      (target, offset, length, position) => readSync(descriptor!, target, offset, length, position),
      () => fstatSync(descriptor!, { bigint: true }).size,
    );
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch (error) {
        if (!failed) throw error;
      }
    }
  }
}

function freezeIdentity(value: NativeMainAuthIdentity): Readonly<NativeMainAuthIdentity> {
  return Object.freeze({ dev: value.dev, ino: value.ino });
}

const defaultFileSystem: NativeMainCredentialFileSystem = {
  lstat: path => lstatSync(path),
  stat: path => statSync(path),
  read: path => readNativeMainAuthFile(resolveWriteTarget(path)),
  watchDirectory: (path, onEvent, onError) => {
    const watcher: FSWatcher = watchFsDirectory(path, { persistent: false }, () => onEvent());
    watcher.on("error", onError);
    return watcher;
  },
  setInterval: (callback, delayMs) => setInterval(callback, delayMs),
  clearInterval: timer => clearInterval(timer),
  setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimeout: timer => clearTimeout(timer),
};

function errnoCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function tokenValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

type CompleteAuth = { kind: "chatgpt" | "api-key"; root: AuthRoot };

function classifyCompleteAuth(raw: string): CompleteAuth | null {
  try {
    const root = object(JSON.parse(raw) as unknown);
    const tokens = object(root?.tokens);
    const accessToken = tokenValue(tokens?.access_token);
    const refreshToken = tokenValue(tokens?.refresh_token);
    if (!root) return null;
    if (root.auth_mode === "apikey" || root.auth_mode === "api_key") {
      return tokenValue(root.OPENAI_API_KEY) ? { kind: "api-key", root } : null;
    }
    if (root.auth_mode !== undefined && root.auth_mode !== "chatgpt") return null;
    if (root.auth_mode === undefined && !tokens && tokenValue(root.OPENAI_API_KEY)) {
      return { kind: "api-key", root };
    }
    if (!tokens || !accessToken || !refreshToken) return null;
    return { kind: "chatgpt", root };
  } catch {
    return null;
  }
}

function classifyObservedContent(
  bytes: Buffer,
  stat: Stats,
): Readonly<ObservationContent> {
  const raw = bytes.toString("utf8");
  const contentDigest = digest(bytes);
  const observedIdentity = identity(stat);
  if (!Buffer.from(raw, "utf8").equals(bytes)) {
    return Object.freeze({ kind: "invalid", digest: contentDigest, identity: observedIdentity });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return Object.freeze({ kind: raw.trim() ? "invalid" : "incomplete", digest: contentDigest, identity: observedIdentity });
  }
  const root = object(parsed);
  if (!root) return Object.freeze({ kind: "invalid", digest: contentDigest, identity: observedIdentity });
  const classified = classifyCompleteAuth(raw);
  if (classified) {
    return Object.freeze({
      kind: "complete",
      raw,
      digest: contentDigest,
      identity: observedIdentity,
    });
  }
  const tokens = object(root.tokens);
  if (root.auth_mode === "chatgpt" || root.auth_mode === undefined && tokens) {
    return Object.freeze({ kind: "incomplete", digest: contentDigest, identity: observedIdentity });
  }
  if (root.auth_mode === "apikey" || root.auth_mode === "api_key") {
    return Object.freeze({ kind: tokenValue(root.OPENAI_API_KEY) ? "invalid" : "incomplete", digest: contentDigest, identity: observedIdentity });
  }
  if (root.auth_mode === undefined && !tokens && root.OPENAI_API_KEY === undefined && Object.keys(root).length === 0) {
    return Object.freeze({ kind: "incomplete", digest: contentDigest, identity: observedIdentity });
  }
  return Object.freeze({ kind: "invalid", digest: contentDigest, identity: observedIdentity });
}

function parseChatGptAuth(raw: string): AuthRoot | null {
  const classified = classifyCompleteAuth(raw);
  return classified?.kind === "chatgpt" ? classified.root : null;
}

function digest(raw: Buffer | string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function identity(stat: Stats): NativeMainAuthIdentity {
  return Object.freeze({ dev: Number(stat.dev), ino: Number(stat.ino) });
}

function statSignatureOf(stat: Stats): Readonly<NativeMainAuthStatSignature> {
  return Object.freeze({
    dev: Number(stat.dev),
    ino: Number(stat.ino),
    size: Number(stat.size),
    mode: Number(stat.mode),
    mtimeMs: Number(stat.mtimeMs),
    ctimeMs: Number(stat.ctimeMs),
  });
}

function physicalSignatureKey(signature: Readonly<NativeMainAuthPhysicalSignature> | null): string | null {
  return signature === null ? null : JSON.stringify(signature);
}

function publicationPhysicalSignatureKey(identity: Readonly<AtomicWriteTargetIdentity>): string {
  const stat = Object.freeze({
    dev: identity.dev,
    ino: identity.ino,
    size: identity.size,
    mode: identity.mode,
    mtimeMs: identity.mtimeMs,
    ctimeMs: identity.ctimeMs,
  });
  return physicalSignatureKey(Object.freeze({ target: stat, leaf: stat }))!;
}

function observationContentKey(content: Readonly<ObservationContent>): string {
  return "digest" in content ? `${content.kind}:${content.digest}` : content.kind;
}

function sameStatSignature(
  left: Readonly<NativeMainAuthStatSignature> | null,
  right: Readonly<NativeMainAuthStatSignature> | null,
): boolean {
  return left === right || !!left && !!right
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function snapshotFrom(
  path: string,
  record: NativeMainAuthObservation & {
    content: Readonly<{ kind: "complete"; raw: string; digest: string; identity: NativeMainAuthIdentity }>;
  },
  observationGeneration: number,
  observationSequence: number,
): NativeMainAuthSnapshot {
  const raw = Buffer.from(record.content.raw, "utf8");
  const stat = record.statSignature?.target;
  if (!stat) throw new Error("Complete native-main observation omitted its target stat signature.");
  return {
    path,
    raw,
    digest: record.content.digest,
    identity: { ...record.content.identity },
    observationGeneration,
    observationSequence,
    isSymlink: record.leafProvenance === "link",
    leafProvenance: record.leafProvenance,
    statSignature: stat,
    physicalSignature: physicalSignatureKey(record.statSignature) ?? "unknown",
    size: raw.byteLength,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

export function nativeMainAuthFence(snapshot: NativeMainAuthSnapshot): NativeMainAuthWriteFence {
  return {
    digest: snapshot.digest,
    identity: { ...snapshot.identity },
    observationGeneration: snapshot.observationGeneration,
  };
}

export function nativeMainAuthReceiptFence(receipt: NativeMainAuthWriteReceipt): NativeMainAuthWriteFence {
  return {
    digest: receipt.digest,
    identity: { ...receipt.identity },
    observationGeneration: receipt.observationGeneration,
  };
}

export function nativeMainAuthReceiptMatches(
  snapshot: NativeMainAuthSnapshot | undefined,
  receipt: NativeMainAuthWriteReceipt,
): boolean {
  return !!snapshot
    && resolve(snapshot.path) === receipt.path
    && snapshot.digest === receipt.digest
    && snapshot.identity.dev === receipt.identity.dev
    && snapshot.identity.ino === receipt.identity.ino
    && snapshot.observationGeneration === receipt.observationGeneration
    && snapshot.physicalSignature === receipt.statSignature;
}

export function nativeMainAuthStrictNoFollowAllowed(
  observation: Pick<NativeMainAuthMemoryRead, "status" | "leafProvenance" | "snapshot">,
): boolean {
  return observation.status === "ok"
    && observation.leafProvenance === "regular"
    && observation.snapshot?.leafProvenance === "regular";
}

function immutableWriteReceipt(
  path: string,
  candidateDigest: string,
  targetIdentity: AtomicWriteTargetIdentity,
  observationGeneration: number,
  observationSequence: number,
  publicationId: number,
  statSignature: string,
): NativeMainAuthWriteReceipt {
  return Object.freeze({
    path: resolve(path),
    digest: candidateDigest,
    identity: Object.freeze({ dev: targetIdentity.dev, ino: targetIdentity.ino }),
    observationGeneration,
    observationSequence,
    publicationId,
    statSignature,
  });
}

export function nativeMainAuthFenceMatches(
  snapshot: NativeMainAuthSnapshot | undefined,
  fence: NativeMainAuthWriteFence,
): boolean {
  return !!snapshot
    && snapshot.digest === fence.digest
    && snapshot.identity.dev === fence.identity.dev
    && snapshot.identity.ino === fence.identity.ino
    && snapshot.observationGeneration === fence.observationGeneration;
}

function snapshotCopy(snapshot: NativeMainAuthSnapshot | undefined): NativeMainAuthSnapshot | undefined {
  if (!snapshot) return undefined;
  return {
    ...snapshot,
    raw: Buffer.from(snapshot.raw),
    identity: { ...snapshot.identity },
    statSignature: Object.freeze({ ...snapshot.statSignature }),
  };
}

function mergeRefreshIntoDisk(diskRaw: string, refreshRaw: string): string {
  const disk = classifyCompleteAuth(diskRaw);
  const refresh = classifyCompleteAuth(refreshRaw);
  const diskTokens = object(disk?.root.tokens);
  const refreshTokens = object(refresh?.root.tokens);
  if (disk?.kind !== "chatgpt" || refresh?.kind !== "chatgpt" || !diskTokens || !refreshTokens) {
    throw new NativeMainAuthChangedError();
  }
  return JSON.stringify({
    ...disk.root,
    tokens: { ...diskTokens, ...refreshTokens },
  }, null, 2) + "\n";
}

function cloneRaw(snapshot: NativeMainAuthSnapshot): string {
  return snapshot.raw.toString("utf8");
}

function sameSnapshot(
  left: NativeMainAuthSnapshot | null | undefined,
  right: NativeMainAuthSnapshot | null | undefined,
): boolean {
  return !!left && !!right
    && left.digest === right.digest
    && left.identity.dev === right.identity.dev
    && left.identity.ino === right.identity.ino;
}

function nativeMainAuthFenceContentMatches(
  snapshot: NativeMainAuthSnapshot | undefined,
  fence: NativeMainAuthWriteFence,
): boolean {
  return !!snapshot
    && snapshot.digest === fence.digest
    && snapshot.identity.dev === fence.identity.dev
    && snapshot.identity.ino === fence.identity.ino;
}

export class NativeMainCredentialStore {
  readonly authPath: string;
  private readonly now: () => number;
  private readonly fileSystem: NativeMainCredentialFileSystem;
  private readonly writeSyncIO?: AtomicWriteIO;
  private readonly writeAsyncIO?: AtomicWriteAsyncIO;
  private readonly claimExclusive: typeof withNativeMainExclusiveClaim;
  private observationError: string | undefined;
  private memory: NativeMainAuthSnapshot | null = null;
  private disk: NativeMainAuthSnapshot | null = null;
  private fileStatus: NativeMainAuthFileStatus = "missing";
  private signature: string | null = null;
  private isSymlink = false;
  private leafProvenance: NativeMainAuthLeafProvenance = "unknown";
  private lastForcedReadAt: number | null = null;
  private readonly observationLedger = {
    observationGeneration: 0,
    observationSequence: 0,
    unownedObservationSequence: 0,
    latestObservation: null as NativeMainAuthObservation | null,
    lastCompleteChangeGeneration: 0,
    lastHiccupGeneration: 0,
    deletionStartedAt: null as number | null,
    deletionConfirmed: false,
    observationHistory: [] as ObservationHistoryEntry[],
    observationHistoryFloor: 0,
  };
  private watcher: NativeMainCredentialWatcher | null = null;
  private timer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private retryAbortController: AbortController | null = null;
  private retryInFlight = false;
  private pendingRefresh: PendingRefresh | null = null;
  private publishingDigest: string | null = null;
  private publishingGeneration: number | null = null;
  private nextRefreshGeneration = 0;
  private nextPublicationGeneration = 0;
  private nextReceiptPublicationId = 0;
  private readonly activeReceipts = new Map<number, { receipt: NativeMainAuthWriteReceipt; invalidated: boolean }>();
  private started = false;
  private stopped = false;

  constructor(options: NativeMainCredentialStoreOptions) {
    this.authPath = resolve(options.authPath);
    this.now = options.now ?? Date.now;
    this.fileSystem = { ...defaultFileSystem, ...options.fileSystem };
    this.writeSyncIO = options.writeSyncIO;
    this.writeAsyncIO = options.writeAsyncIO;
    this.claimExclusive = options.claimExclusive ?? withNativeMainExclusiveClaim;
  }

  start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.ensureWatcher();
    this.timer = this.fileSystem.setInterval(() => {
      this.ensureWatcher();
      const forceRead = this.lastForcedReadAt === null
        || this.now() - this.lastForcedReadAt >= NATIVE_MAIN_AUTH_FORCE_READ_INTERVAL_MS;
      this.observeInBackground(forceRead);
    }, NATIVE_MAIN_AUTH_CHECK_INTERVAL_MS);
    this.timer.unref?.();
    this.observeNow();
  }

  stop(): void {
    this.stopped = true;
    this.retryAbortController?.abort(new Error("Native-main credential store stopped."));
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.timer) {
      this.fileSystem.clearInterval(this.timer);
      this.timer = null;
    }
    this.clearRetryTimer();
    this.started = false;
    this.clearMemory();
    this.pendingRefresh = null;
    this.publishingDigest = null;
    this.publishingGeneration = null;
    this.activeReceipts.clear();
  }

  observeNow(forceRead = true): NativeMainAuthMemoryRead {
    if (this.stopped) return this.readMemory();
    if (forceRead) this.lastForcedReadAt = this.now();
    const record = this.classifyPhysicalObservation(forceRead);
    return this.applyObservationTransition(record);
  }

  private classifyPhysicalObservation(
    forceRead: boolean,
    requestedSource?: {
      kind: "publication" | "receipt-check";
      publicationId: number;
      digest: string;
      identity: Readonly<NativeMainAuthIdentity>;
      statSignature?: string;
    },
  ): NativeMainAuthObservation {
    const freezeSignature = (target: Stats | null, leaf: Stats | null): Readonly<NativeMainAuthPhysicalSignature> | null => {
      if (!target && !leaf) return null;
      return Object.freeze({
        target: target ? statSignatureOf(target) : null,
        leaf: leaf ? statSignatureOf(leaf) : null,
      });
    };
    const finish = (
      existence: ObservationExistence,
      leafProvenance: NativeMainAuthLeafProvenance,
      content: Readonly<ObservationContent>,
      signature: Readonly<NativeMainAuthPhysicalSignature> | null,
      error?: string,
    ): NativeMainAuthObservation => {
      let source: NativeMainAuthObservation["source"] = "unowned";
      if (requestedSource && content.kind === "complete"
        && content.digest === requestedSource.digest
        && content.identity.dev === requestedSource.identity.dev
        && content.identity.ino === requestedSource.identity.ino
        && leafProvenance === "regular"
        && (requestedSource.statSignature === undefined
          || physicalSignatureKey(signature) === requestedSource.statSignature)) {
        source = requestedSource.kind;
      }
      return Object.freeze({
        existence,
        witnessedPresence,
        leafProvenance,
        content,
        statSignature: signature,
        ...(error ? { error } : {}),
        source,
        ...(source !== "unowned" && requestedSource ? { publicationId: requestedSource.publicationId } : {}),
      });
    };
    const unreadable = (error: string) => Object.freeze({ kind: "unreadable" as const });
    let witnessedPresence = false;
    let targetStat: Stats | null = null;
    let statFailure: unknown;
    try {
      targetStat = this.fileSystem.stat(this.authPath);
    } catch (error) {
      statFailure = error;
    }
    if (targetStat) witnessedPresence = true;
    let leafStat: Stats | null = null;
    let leafFailure: unknown;
    try {
      leafStat = this.fileSystem.lstat(this.authPath);
    } catch (error) {
      leafFailure = error;
    }
    if (leafStat) witnessedPresence = true;
    const leafProvenance: NativeMainAuthLeafProvenance = leafStat
      ? leafStat.isSymbolicLink() ? "link" : leafStat.isFile() ? "regular" : "unknown"
      : "unknown";
    if (!targetStat) {
      const missing = errnoCode(statFailure) === "ENOENT" && errnoCode(leafFailure) === "ENOENT";
      const existence = leafStat ? "present" : missing ? "absent" : "unknown";
      const error = missing ? undefined : errnoCode(statFailure) === "ENOENT" && leafFailure
        ? "lstat-failed" : "stat-failed";
      return finish(existence, leafProvenance, unreadable(error ?? "missing"), freezeSignature(null, leafStat), error);
    }
    if (!leafStat) {
      return finish("present", "unknown", unreadable("lstat-failed"), freezeSignature(targetStat, null), "lstat-failed");
    }
    const initialSignature = freezeSignature(targetStat, leafStat)!;
    const initialSignatureKey = physicalSignatureKey(initialSignature)!;
    if (leafProvenance === "unknown" || !targetStat.isFile() || targetStat.size > MAX_AUTH_BYTES) {
      return finish("present", leafProvenance, unreadable("not-regular-file"), initialSignature, "not-regular-file");
    }
    if (!forceRead && this.signature === initialSignatureKey && this.observationLedger.latestObservation) {
      return finish("present", leafProvenance, this.observationLedger.latestObservation.content, initialSignature);
    }
    let bytes: Buffer;
    try {
      const read = this.fileSystem.read(this.authPath);
      if (Buffer.isBuffer(read)) {
        bytes = Buffer.from(read);
        read.fill(0);
      } else {
        bytes = Buffer.from(read, "utf8");
      }
      witnessedPresence = true;
    } catch (error) {
      const code = errnoCode(error);
      return finish("present", leafProvenance, unreadable(code === "ENOENT" ? "read-missing" : "read-failed"), initialSignature, "read-failed");
    }
    if (bytes.byteLength > MAX_AUTH_BYTES) {
      const contentDigest = digest(bytes);
      const contentIdentity = identity(targetStat);
      bytes.fill(0);
      return finish("present", leafProvenance, Object.freeze({ kind: "invalid", digest: contentDigest, identity: contentIdentity }), initialSignature, "too-large");
    }
    let currentStat: Stats | null = null;
    let currentStatFailure: unknown;
    try {
      currentStat = this.fileSystem.stat(this.authPath);
    } catch (error) {
      currentStatFailure = error;
    }
    if (currentStat) witnessedPresence = true;
    let currentLeafStat: Stats | null = null;
    let currentLeafFailure: unknown;
    try {
      currentLeafStat = this.fileSystem.lstat(this.authPath);
    } catch (error) {
      currentLeafFailure = error;
    }
    if (currentLeafStat) witnessedPresence = true;
    if (!currentStat || !currentLeafStat) {
      bytes.fill(0);
      const currentProvenance: NativeMainAuthLeafProvenance = currentLeafStat
        ? currentLeafStat.isSymbolicLink() ? "link" : currentLeafStat.isFile() ? "regular" : "unknown"
        : "unknown";
      const existence = currentLeafStat || currentStat ? "present"
        : errnoCode(currentStatFailure) === "ENOENT" && errnoCode(currentLeafFailure) === "ENOENT" ? "absent" : "unknown";
      return finish(existence, currentProvenance, unreadable("stat-failed-after-read"), freezeSignature(currentStat, currentLeafStat), "stat-failed-after-read");
    }
    const currentProvenance: NativeMainAuthLeafProvenance = currentLeafStat.isSymbolicLink()
      ? "link" : currentLeafStat.isFile() ? "regular" : "unknown";
    const currentSignature = freezeSignature(currentStat, currentLeafStat)!;
    const currentSignatureKey = physicalSignatureKey(currentSignature)!;
    if (currentSignatureKey !== initialSignatureKey || bytes.byteLength !== currentStat.size) {
      bytes.fill(0);
      return finish("present", currentProvenance, unreadable("file-changed-during-read"), currentSignature, "file-changed-during-read");
    }
    const content = classifyObservedContent(bytes, currentStat);
    bytes.fill(0);
    return finish("present", currentProvenance, content, currentSignature);
  }

  private applyObservationTransition(record: NativeMainAuthObservation): NativeMainAuthMemoryRead {
    const previousRecord = this.observationLedger.latestObservation;
    const signatureChanged = physicalSignatureKey(previousRecord?.statSignature ?? null)
      !== physicalSignatureKey(record.statSignature);
    const contentChanged = !previousRecord
      || observationContentKey(previousRecord.content) !== observationContentKey(record.content);
    const provenanceChanged = !previousRecord || previousRecord.leafProvenance !== record.leafProvenance;
    const existenceChanged = !previousRecord || previousRecord.existence !== record.existence;
    const physicalChange = signatureChanged || contentChanged || provenanceChanged || existenceChanged;
    this.observationLedger.observationSequence++;
    if (physicalChange) this.observationLedger.observationGeneration++;
    if (record.source === "unowned") {
      this.observationLedger.unownedObservationSequence = this.observationLedger.observationSequence;
    }
    for (const [publicationId, active] of this.activeReceipts) {
      if (record.source === "unowned" || record.publicationId !== publicationId) {
        active.invalidated = true;
      }
    }
    this.observationLedger.latestObservation = record;
    this.signature = record.content.kind === "unreadable" || record.existence === "unknown"
      ? null : physicalSignatureKey(record.statSignature);
    this.observationError = record.error;
    this.leafProvenance = record.leafProvenance;
    this.isSymlink = record.leafProvenance === "link";
    if (record.witnessedPresence || record.existence === "present") {
      this.observationLedger.deletionStartedAt = null;
      this.observationLedger.deletionConfirmed = false;
    } else if (record.existence === "unknown") {
      this.observationLedger.deletionStartedAt = null;
      this.observationLedger.deletionConfirmed = false;
    }
    const historyKind: ObservationHistoryEntry["kind"] = record.existence === "absent"
      ? "missing" : record.content.kind === "complete" ? "complete"
        : record.content.kind === "invalid" || record.content.kind === "incomplete" ? "invalid" : "unknown";
    const historyEntry: ObservationHistoryEntry = {
      kind: historyKind,
      generation: this.observationLedger.observationGeneration,
      ...(record.content.kind === "complete" ? {
        digest: record.content.digest,
        identity: { ...record.content.identity },
        physicalSignature: physicalSignatureKey(record.statSignature) ?? "unknown",
      } : {}),
    };
    const previousHistory = this.observationLedger.observationHistory.at(-1);
    const sameHistoryState = previousHistory?.kind === historyEntry.kind
      && (historyEntry.kind !== "complete"
        || previousHistory.digest === historyEntry.digest
          && previousHistory.identity?.dev === historyEntry.identity?.dev
          && previousHistory.identity?.ino === historyEntry.identity?.ino
          && previousHistory.physicalSignature === historyEntry.physicalSignature);
    if (!sameHistoryState) this.observationLedger.observationHistory.push(historyEntry);
    if (this.observationLedger.observationHistory.length > MAX_PUBLICATION_HISTORY) {
      const removed = this.observationLedger.observationHistory.shift()!;
      this.observationLedger.observationHistoryFloor = Math.max(this.observationLedger.observationHistoryFloor, removed.generation);
    }
    const isHiccup = record.existence !== "present" || record.content.kind !== "complete";
    if (isHiccup) {
      this.observationLedger.lastHiccupGeneration = this.observationLedger.observationGeneration;
      this.disk?.raw.fill(0);
      this.disk = null;
    }
    if (record.existence === "absent") {
      this.fileStatus = "missing";
      if (this.observationLedger.deletionStartedAt === null) this.observationLedger.deletionStartedAt = this.now();
      if (this.now() - this.observationLedger.deletionStartedAt >= NATIVE_MAIN_AUTH_DELETE_GRACE_MS) {
        this.observationLedger.deletionConfirmed = true;
        this.clearMemory();
        this.pendingRefresh = null;
        this.clearRetryTimer();
      }
      return this.readMemory();
    }
    if (record.existence === "unknown") {
      this.fileStatus = "unreadable";
      return this.readMemory();
    }
    if (record.content.kind === "incomplete" || record.content.kind === "invalid") {
      this.fileStatus = "invalid";
      return this.readMemory();
    }
    if (record.content.kind === "unreadable") {
      this.fileStatus = "unreadable";
      return this.readMemory();
    }
    this.fileStatus = "valid";
    const observed = snapshotFrom(this.authPath, record as NativeMainAuthObservation & {
      content: Readonly<{ kind: "complete"; raw: string; digest: string; identity: NativeMainAuthIdentity }>;
    }, this.observationLedger.observationGeneration, this.observationLedger.observationSequence);
    this.disk?.raw.fill(0);
    this.disk = observed;
    const pending = this.pendingRefresh;
    if (pending) {
      const historyLost = this.observationLedger.observationHistoryFloor > pending.retryFence.observationGeneration;
      const matchesRetainedBase = nativeMainAuthFenceContentMatches(observed, pending.retryFence)
        && observed.physicalSignature === pending.retryPhysicalSignature;
      if (historyLost && matchesRetainedBase) {
        pending.recoveryRequired = true;
        this.clearRetryTimer();
        this.setMemory(pending.raw, observed);
        return this.readMemory();
      }
      const matchesPendingBase = sameSnapshot(observed, pending.expectedSnapshot);
      const matchesRetryFence = nativeMainAuthFenceMatches(observed, pending.retryFence);
      const isPendingCandidate = pending.digest === observed.digest;
      const matchesPendingBaseAfterHiccup = matchesPendingBase
        && this.canContinueRetryAfterHiccup(pending);
      if (matchesPendingBaseAfterHiccup || matchesRetryFence || isPendingCandidate && record.source === "publication") {
        this.setMemory(pending.raw, observed);
        return this.readMemory();
      }
      const completeChange = physicalChange || !sameSnapshot(pending.expectedSnapshot, observed);
      if (record.source === "unowned" && completeChange) {
        this.observationLedger.lastCompleteChangeGeneration = this.observationLedger.observationGeneration;
        this.pendingRefresh = null;
        this.clearRetryTimer();
      }
    }
    if (!pending || this.pendingRefresh !== pending) {
      const prior = pending?.expectedSnapshot ?? this.memory;
      const externalChange = record.source === "unowned"
        && (physicalChange || !sameSnapshot(prior, observed));
      if (externalChange) this.observationLedger.lastCompleteChangeGeneration = this.observationLedger.observationGeneration;
      this.setMemory(cloneRaw(observed), observed);
      if (externalChange && prior && !sameSnapshot(prior, observed)) advanceCodexCredentialMutationEpoch();
    } else {
      this.setMemory(cloneRaw(observed), observed);
    }
    return this.readMemory();
  }

  readMemory(): NativeMainAuthMemoryRead {
    const graceActive = this.fileStatus === "missing"
      && this.observationLedger.deletionStartedAt !== null
      && !this.observationLedger.deletionConfirmed;
    const status = this.stopped ? "stopped"
      : this.memory ? "ok" : this.fileStatus === "valid" ? "unreadable" : this.fileStatus;
    const snapshot = snapshotCopy(this.memory ?? undefined);
    return {
      status,
      fileStatus: this.fileStatus,
      graceActive,
      canRefreshOrWrite: this.canRefreshOrWrite(),
      canWriteFile: this.fileStatus === "valid"
        && !!this.disk
        && this.leafProvenance === "regular"
        && this.disk.leafProvenance === "regular"
        && !this.observationLedger.deletionConfirmed
        && !this.stopped,
      isSymlink: this.isSymlink,
      leafProvenance: this.leafProvenance,
      deletionConfirmed: this.observationLedger.deletionConfirmed,
      observationGeneration: this.observationLedger.observationGeneration,
      observationSequence: this.observationLedger.observationSequence,
      ...(this.observationError ? { observationError: this.observationError } : {}),
      ...(snapshot ? {
        snapshot,
        raw: Buffer.from(snapshot.raw),
        digest: snapshot.digest,
        identity: { ...snapshot.identity },
      } : {}),
    };
  }

  canRefreshOrWrite(): boolean {
    return !this.stopped
      && this.fileStatus === "valid"
      && !!this.disk
      && !!this.memory
      && this.leafProvenance === "regular"
      && this.memory.leafProvenance === "regular"
      && this.disk.leafProvenance === "regular"
      && this.memory.digest === this.disk.digest
      && nativeMainAuthFenceMatches(this.memory, nativeMainAuthFence(this.disk))
      && !this.observationLedger.deletionConfirmed;
  }

  verifyReceipt(receipt: NativeMainAuthWriteReceipt): boolean {
    return this.observeReceiptCurrent(receipt);
  }

  async persistRefresh(raw: string, options: NativeMainRefreshWriteOptions): Promise<NativeMainRefreshWriteResult> {
    if (this.stopped) return { status: "stopped" };
    if (!parseChatGptAuth(raw)) throw new Error("Refusing to publish an invalid native-main credential.");
    this.observeNow(true);
    if (this.observationLedger.deletionConfirmed) {
      return { status: "deleted" };
    }

    const memorySnapshot = snapshotCopy(this.memory ?? undefined);
    const publicationState = this.classifyPublicationFence(options.expectedSnapshot);
    if (publicationState === "changed") {
      memorySnapshot?.raw.fill(0);
      return this.supersededResult();
    }

    if (publicationState === "blocked") {
      if (!nativeMainAuthFenceContentMatches(memorySnapshot, options.expectedSnapshot)) {
        memorySnapshot?.raw.fill(0);
        return this.supersededResult();
      }
      const existingPending = this.pendingRefresh;
      if (existingPending?.recoveryRequired) {
        memorySnapshot?.raw.fill(0);
        return this.recoveryRequiredResult();
      }
      if (existingPending && existingPending.digest !== memorySnapshot?.digest) {
        memorySnapshot?.raw.fill(0);
        return this.supersededResult();
      }
      const candidateBase = existingPending?.raw ?? cloneRaw(memorySnapshot!);
      const candidateRaw = mergeRefreshIntoDisk(candidateBase, raw);
      const expectedBase = existingPending?.expectedSnapshot
        ?? { ...memorySnapshot!, observationGeneration: options.expectedSnapshot.observationGeneration };
      const retryFence = existingPending?.retryFence ?? options.expectedSnapshot;
      this.retainRefresh(
        candidateRaw,
        expectedBase,
        retryFence,
        existingPending?.retryPhysicalSignature ?? expectedBase.physicalSignature,
      );
      memorySnapshot?.raw.fill(0);
      this.scheduleRetry(NATIVE_MAIN_AUTH_RETRY_INITIAL_MS);
      const retained = snapshotCopy(this.memory ?? undefined);
      return retained ? { status: "retained", snapshot: retained } : { status: "deleted" };
    }

    const candidateRaw = mergeRefreshIntoDisk(cloneRaw(this.disk!), raw);
    this.retainRefresh(candidateRaw, this.disk!);
    memorySnapshot?.raw.fill(0);

    for (let attempt = 0; attempt < 3; attempt++) {
      const result = this.tryPublishPendingRefresh(options.beforeRename);
      if (result) {
        if (result.status === "retained") this.scheduleRetry(NATIVE_MAIN_AUTH_RETRY_INITIAL_MS);
        return result;
      }
      if (!this.pendingRefresh) {
        return this.supersededResult();
      }
    }
    this.scheduleRetry(NATIVE_MAIN_AUTH_RETRY_INITIAL_MS);
    const retained = snapshotCopy(this.memory ?? undefined);
    return retained ? { status: "retained", snapshot: retained } : { status: "deleted" };
  }

  writeAuthFileSync(raw: string, options: NativeMainAuthWriteOptions): NativeMainAuthWriteReceipt {
    return this.writeAuthFile(raw, options, false);
  }

  async writeAuthFileAsync(
    raw: string,
    options: NativeMainAuthWriteOptions,
    writeOverride?: NativeMainAuthWriteOverride,
  ): Promise<NativeMainAuthWriteReceipt> {
    return await this.writeAuthFile(raw, options, true, writeOverride);
  }

  private supersededResult(): NativeMainRefreshWriteResult {
    if (this.observationLedger.deletionConfirmed) return { status: "deleted" };
    const current = snapshotCopy(this.memory ?? undefined);
    return current ? { status: "superseded", snapshot: current } : { status: "superseded" };
  }

  private ensureWatcher(): void {
    if (this.watcher || this.stopped) return;
    try {
      const watcher = this.fileSystem.watchDirectory(
        dirname(this.authPath),
        () => this.observeInBackground(true),
        () => {
          try { this.watcher?.close(); } catch { /* the timer reopens it */ }
          this.watcher = null;
        },
      );
      watcher.unref?.();
      this.watcher = watcher;
    } catch {
      // The short timer remains the fallback and retries watcher registration.
    }
  }

  private observeInBackground(forceRead: boolean): void {
    try {
      this.observeNow(forceRead);
    } catch { /* The classifier returns an unreadable record for filesystem failures. */ }
    this.retryPendingRefresh();
  }

  private setMemory(raw: string, basedOn?: NativeMainAuthSnapshot): void {
    const previous = this.memory;
    const next: NativeMainAuthSnapshot = basedOn && raw === cloneRaw(basedOn)
      ? snapshotCopy(basedOn)!
      : {
        path: this.authPath,
        raw: Buffer.from(raw),
        digest: digest(raw),
        identity: basedOn ? { ...basedOn.identity } : { dev: 0, ino: 0 },
        observationGeneration: basedOn?.observationGeneration ?? this.observationLedger.observationGeneration,
        observationSequence: basedOn?.observationSequence ?? this.observationLedger.observationSequence,
        isSymlink: basedOn?.isSymlink ?? this.isSymlink,
        leafProvenance: basedOn?.leafProvenance ?? this.leafProvenance,
        statSignature: basedOn?.statSignature ?? Object.freeze({
          dev: 0, ino: 0, size: Buffer.byteLength(raw), mode: 0, mtimeMs: this.now(), ctimeMs: this.now(),
        }),
        physicalSignature: basedOn?.physicalSignature ?? "unknown",
        size: Buffer.byteLength(raw),
        mtimeMs: basedOn?.mtimeMs ?? this.now(),
        ctimeMs: basedOn?.ctimeMs ?? this.now(),
      };
    this.memory = next;
    if (previous && previous !== this.disk) previous.raw.fill(0);
  }

  private retainRefresh(
    raw: string,
    expectedSnapshot: NativeMainAuthSnapshot,
    retryFence: NativeMainAuthWriteFence = nativeMainAuthFence(expectedSnapshot),
    retryPhysicalSignature = expectedSnapshot.physicalSignature,
  ): void {
    const memoryBefore = snapshotCopy(this.memory ?? undefined);
    this.pendingRefresh = {
      raw,
      digest: digest(raw),
      expectedSnapshot: snapshotCopy(expectedSnapshot)!,
      retryFence: { ...retryFence, identity: { ...retryFence.identity } },
      retryPhysicalSignature,
      generation: ++this.nextRefreshGeneration,
      retryDelayMs: NATIVE_MAIN_AUTH_RETRY_INITIAL_MS,
      recoveryRequired: false,
    };
    this.setMemory(raw, expectedSnapshot);
    memoryBefore?.raw.fill(0);
  }

  private tryPublishPendingRefresh(beforeRename?: () => void): NativeMainRefreshWriteResult | null {
    const pending = this.pendingRefresh;
    if (!pending) return null;
    if (this.stopped) return { status: "stopped" };
    this.observeNow(true);
    if (this.observationLedger.deletionConfirmed) {
      this.pendingRefresh = null;
      this.clearRetryTimer();
      return { status: "deleted" };
    }
    if (this.pendingRefresh !== pending) return this.supersededResult();
    const publicationState = this.classifyPendingRefreshFence(pending);
    if (publicationState === "blocked") {
      if (this.fileStatus === "valid" && this.disk) {
        pending.recoveryRequired = true;
        this.clearRetryTimer();
        return this.recoveryRequiredResult();
      }
      return null;
    }
    if (publicationState === "changed") {
      this.pendingRefresh = null;
      this.clearRetryTimer();
      return this.supersededResult();
    }

    const stagedRaw = pending.raw;
    const stagedDigest = pending.digest;
    const stagedGeneration = pending.generation;
    let receipt: NativeMainAuthWriteReceipt | undefined;
    let publicationAuthority: PublicationAuthority | undefined;

    try {
      atomicWriteFile(this.authPath, stagedRaw, this.writeSyncIO, {
        beforeRename,
        validateBeforeRename: (_targetPath, tempIdentity) => {
          const current = this.observeNow(true);
          if (!current.canWriteFile
            || !this.disk
            || !tempIdentity
            || this.pendingRefresh !== pending
            || pending.generation !== stagedGeneration
            || pending.digest !== stagedDigest
            || this.classifyPendingRefreshFence(pending) !== "current") throw new NativeMainAuthChangedError();
          publicationAuthority = this.capturePublicationAuthority(stagedRaw, stagedDigest, tempIdentity);
        },
        afterRenameEvidence: (_targetPath, evidence) => {
          if (!publicationAuthority) throw new NativeMainAuthChangedError();
          receipt = this.recordOwnRename(stagedDigest, evidence, publicationAuthority);
        },
      });
    } catch (error) {
      if (error instanceof NativeMainAuthChangedError) {
        this.observeNow(true);
        if (this.pendingRefresh !== pending) return this.supersededResult();
        return null;
      }
      const retained = snapshotCopy(this.memory ?? undefined);
      return retained ? { status: "retained", snapshot: retained } : { status: "deleted" };
    }

    const receiptCurrent = !!receipt && this.observeReceiptCurrent(receipt);
    if (!receiptCurrent || !this.disk || !receipt || !nativeMainAuthReceiptMatches(this.disk, receipt)) {
      if (this.pendingRefresh !== pending) return this.supersededResult();
      if (this.fileStatus === "valid" && this.disk) {
        pending.recoveryRequired = true;
        return this.recoveryRequiredResult();
      }
      const retained = snapshotCopy(this.memory ?? undefined);
      return retained ? { status: "retained", snapshot: retained } : { status: "deleted" };
    }
    if (this.pendingRefresh === pending) this.pendingRefresh = null;
    this.clearRetryTimer();
    const written = snapshotCopy(this.memory ?? undefined);
    return written && receipt ? { status: "written", snapshot: written, receipt } : { status: "deleted" };
  }

  private classifyPendingRefreshFence(pending: PendingRefresh): "current" | "changed" | "blocked" {
    const state = this.classifyPublicationFence(pending.retryFence);
    if (state !== "blocked") return state;
    return this.canContinueRetryAfterHiccup(pending) ? "current" : "blocked";
  }

  private recoveryRequiredResult(): NativeMainRefreshWriteResult {
    const retained = snapshotCopy(this.memory ?? undefined);
    return retained ? { status: "recovery-required", snapshot: retained } : { status: "recovery-required" };
  }

  private recordOwnRename(
    candidateDigest: string,
    evidence: AtomicWritePublicationEvidence,
    authority: PublicationAuthority,
  ): NativeMainAuthWriteReceipt {
    if (this.stopped) throw new NativeMainAuthStoppedError();
    const targetIdentity = evidence.identity;
    if (this.observationLedger.observationSequence !== authority.observationSequence
      || this.observationLedger.unownedObservationSequence !== authority.unownedObservationSequence
      || targetIdentity.dev !== authority.identity.dev
      || targetIdentity.ino !== authority.identity.ino
      || evidence.digest !== candidateDigest) {
      this.observeNow(true);
      throw new NativeMainAuthChangedError();
    }
    this.lastForcedReadAt = this.now();
    const record = this.classifyPhysicalObservation(true, {
      kind: "publication",
      publicationId: authority.publicationId,
      digest: candidateDigest,
      identity: authority.identity,
      statSignature: publicationPhysicalSignatureKey(targetIdentity),
    });
    this.applyObservationTransition(record);
    if (record.source !== "publication" || !this.disk
      || this.disk.observationGeneration !== authority.observationGeneration
      || this.disk.digest !== authority.digest
      || this.disk.identity.dev !== authority.identity.dev
      || this.disk.identity.ino !== authority.identity.ino) {
      throw new NativeMainAuthChangedError();
    }
    const receipt = immutableWriteReceipt(
      this.authPath,
      candidateDigest,
      targetIdentity,
      authority.observationGeneration,
      authority.observationSequence,
      authority.publicationId,
      this.disk.physicalSignature,
    );
    this.activeReceipts.set(authority.publicationId, { receipt, invalidated: false });
    return receipt;
  }

  private capturePublicationAuthority(
    raw: string,
    candidateDigest: string,
    targetIdentity: AtomicWriteTargetIdentity,
  ): PublicationAuthority {
    if (this.stopped || this.fileStatus !== "valid" || !this.disk
      || this.leafProvenance !== "regular" || this.disk.leafProvenance !== "regular") {
      throw new NativeMainAuthChangedError();
    }
    return Object.freeze({
      publicationId: ++this.nextReceiptPublicationId,
      observationSequence: this.observationLedger.observationSequence,
      unownedObservationSequence: this.observationLedger.unownedObservationSequence,
      observationGeneration: this.observationLedger.observationGeneration + 1,
      identity: freezeIdentity(targetIdentity),
      digest: candidateDigest,
      raw,
    });
  }

  private observeReceiptCurrent(receipt: NativeMainAuthWriteReceipt): boolean {
    if (this.stopped) return false;
    const active = this.activeReceipts.get(receipt.publicationId);
    if (!active || active.invalidated || active.receipt !== receipt) return false;
    this.lastForcedReadAt = this.now();
    const record = this.classifyPhysicalObservation(true, {
      kind: "receipt-check",
      publicationId: receipt.publicationId,
      digest: receipt.digest,
      identity: receipt.identity,
      statSignature: receipt.statSignature,
    });
    this.applyObservationTransition(record);
    return record.source === "receipt-check"
      && !active.invalidated
      && this.fileStatus === "valid"
      && !!this.disk
      && this.disk.leafProvenance === "regular"
      && this.memory?.leafProvenance === "regular"
      && nativeMainAuthReceiptMatches(this.disk, receipt);
  }

  private classifyPublicationFence(expected: NativeMainAuthWriteFence): "current" | "changed" | "blocked" {
    if (this.fileStatus !== "valid" || !this.disk || this.observationLedger.deletionConfirmed) return "blocked";
    if (nativeMainAuthFenceMatches(this.disk, expected)) return "current";
    if (this.observationLedger.lastCompleteChangeGeneration > expected.observationGeneration) return "changed";
    if (this.observationLedger.lastHiccupGeneration > expected.observationGeneration) return "blocked";
    return "changed";
  }

  private canContinueRetryAfterHiccup(pending: PendingRefresh): boolean {
    const expected = pending.retryFence;
    if (this.observationLedger.observationHistoryFloor > expected.observationGeneration
      || this.fileStatus !== "valid"
      || !this.disk
      || this.observationLedger.deletionConfirmed
      || !nativeMainAuthFenceContentMatches(this.disk, expected)) return false;
    let hiccupObserved = false;
    let baseRecoveredAfterHiccup = false;
    for (const entry of this.observationLedger.observationHistory) {
      if (entry.generation <= expected.observationGeneration) continue;
      if (entry.kind !== "complete") {
        hiccupObserved = true;
        baseRecoveredAfterHiccup = false;
        continue;
      }
      if (entry.digest !== expected.digest
        || entry.identity?.dev !== expected.identity.dev
        || entry.identity?.ino !== expected.identity.ino
        || entry.physicalSignature !== pending.retryPhysicalSignature) return false;
      if (hiccupObserved) baseRecoveredAfterHiccup = true;
    }
    return hiccupObserved && baseRecoveredAfterHiccup;
  }

  private writeAuthFile(
    raw: string,
    options: NativeMainAuthWriteOptions,
    asynchronous: false,
  ): NativeMainAuthWriteReceipt;
  private writeAuthFile(
    raw: string,
    options: NativeMainAuthWriteOptions,
    asynchronous: true,
    writeOverride?: NativeMainAuthWriteOverride,
  ): Promise<NativeMainAuthWriteReceipt>;
  private writeAuthFile(
    raw: string,
    options: NativeMainAuthWriteOptions,
    asynchronous: boolean,
    writeOverride?: NativeMainAuthWriteOverride,
  ): NativeMainAuthWriteReceipt | Promise<NativeMainAuthWriteReceipt> {
    if (this.stopped) throw new NativeMainAuthStoppedError();
    if (!parseChatGptAuth(raw)) throw new Error("Refusing to publish an invalid native-main credential.");
    this.observeNow(true);
    if (this.classifyPublicationFence(options.expectedSnapshot) !== "current") throw new NativeMainAuthChangedError();
    const candidateDigest = digest(raw);
    const candidateGeneration = ++this.nextPublicationGeneration;
    this.publishingDigest = candidateDigest;
    this.publishingGeneration = candidateGeneration;
    let receipt: NativeMainAuthWriteReceipt | undefined;
    let publicationAuthority: PublicationAuthority | undefined;
    const matchesExpected = (): boolean => this.classifyPublicationFence(options.expectedSnapshot) === "current";
    const validateBeforeRename = (_targetPath: string, tempIdentity?: AtomicWriteTargetIdentity): void => {
      if (this.stopped) throw new NativeMainAuthStoppedError();
      this.observeNow(true);
      if (this.publishingGeneration !== candidateGeneration || !matchesExpected() || !tempIdentity) {
        throw new NativeMainAuthChangedError();
      }
      publicationAuthority = this.capturePublicationAuthority(raw, candidateDigest, tempIdentity);
    };
    const hooks: AtomicWriteHooks = {
      beforeRename: options.beforeRename,
      validateBeforeRename,
      afterRenameEvidence: (_targetPath, evidence) => {
        if (!publicationAuthority) throw new NativeMainAuthChangedError();
        receipt = this.recordOwnRename(candidateDigest, evidence, publicationAuthority);
      },
    };
    const asyncHooks: AtomicWriteAsyncHooks = {
      beforeRename: options.beforeRename,
      validateBeforeRename,
      afterRenameEvidence: (_targetPath, evidence) => {
        if (!publicationAuthority) throw new NativeMainAuthChangedError();
        receipt = this.recordOwnRename(candidateDigest, evidence, publicationAuthority);
      },
    };
    const verify = (): NativeMainAuthWriteReceipt => {
      if (this.stopped) throw new NativeMainAuthStoppedError();
      const receiptCurrent = !!receipt && this.observeReceiptCurrent(receipt);
      if (this.publishingGeneration !== candidateGeneration
        || !receiptCurrent
        || this.fileStatus !== "valid"
        || this.leafProvenance !== "regular"
        || !this.disk
        || !receipt
        || !nativeMainAuthReceiptMatches(this.disk, receipt)) {
        throw new NativeMainAuthChangedError();
      }
      return receipt;
    };

    if (asynchronous) {
      const write = atomicWriteFileAsync(this.authPath, raw, writeOverride ?? this.writeAsyncIO, undefined, asyncHooks);
      return write
        .then(verify)
        .catch(error => {
          if (error instanceof NativeMainAuthChangedError || error instanceof NativeMainAuthStoppedError) throw error;
          const observed = this.observeNow(true);
          if (observed.fileStatus !== "valid" || !observed.canWriteFile) throw new NativeMainAuthChangedError();
          throw error;
        })
        .finally(() => {
          if (this.publishingGeneration === candidateGeneration) {
            this.publishingGeneration = null;
            this.publishingDigest = null;
          }
        });
    }
    try {
      atomicWriteFile(this.authPath, raw, this.writeSyncIO, hooks);
      return verify();
    } finally {
      if (this.publishingGeneration === candidateGeneration) {
        this.publishingGeneration = null;
        this.publishingDigest = null;
      }
    }
  }

  private retryPendingRefresh(): void {
    if (!this.pendingRefresh || this.pendingRefresh.recoveryRequired
      || this.retryTimer || this.retryInFlight || this.stopped) return;
    this.scheduleRetry(this.pendingRefresh.retryDelayMs);
  }

  private scheduleRetry(delayMs: number): void {
    if (this.retryTimer || this.retryInFlight || this.stopped
      || !this.pendingRefresh || this.pendingRefresh.recoveryRequired) return;
    const delay = Math.max(NATIVE_MAIN_AUTH_RETRY_INITIAL_MS, delayMs);
    this.retryTimer = this.fileSystem.setTimeout(() => {
      this.retryTimer = null;
      if (this.stopped) return;
      void this.retryPendingRefreshUnderClaim();
    }, delay);
    this.retryTimer.unref?.();
  }

  private async retryPendingRefreshUnderClaim(): Promise<void> {
    if (!this.pendingRefresh || this.pendingRefresh.recoveryRequired || this.stopped || this.retryInFlight) return;
    const pending = this.pendingRefresh;
    const controller = new AbortController();
    this.retryInFlight = true;
    this.retryAbortController = controller;
    try {
      const context = resolveNativeProfileContext({ codexHome: dirname(this.authPath) });
      await this.claimExclusive(context, async () => {
        if (this.stopped || controller.signal.aborted || this.pendingRefresh !== pending) return;
        this.tryPublishPendingRefresh();
      }, { waitMs: 30_000, signal: controller.signal });
    } catch {
      // A later observer tick retries claim or publication failures.
    } finally {
      this.retryInFlight = false;
      if (this.retryAbortController === controller) this.retryAbortController = null;
      if (this.stopped || !this.pendingRefresh) return;
      if (this.pendingRefresh.recoveryRequired) return;
      if (this.pendingRefresh === pending) {
        pending.retryDelayMs = Math.min(
          NATIVE_MAIN_AUTH_RETRY_MAX_MS,
          pending.retryDelayMs * 2,
        );
      }
      this.scheduleRetry(this.pendingRefresh.retryDelayMs);
    }
  }

  private clearRetryTimer(): void {
    if (!this.retryTimer) return;
    this.fileSystem.clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }

  private clearMemory(): void {
    this.memory?.raw.fill(0);
    this.disk?.raw.fill(0);
    this.memory = null;
    this.disk = null;
  }
}

const stores = new Map<string, NativeMainCredentialStore>();
let detachShutdownHook: (() => void) | null = null;

function storeFor(path: string): NativeMainCredentialStore {
  const target = resolve(path);
  let store = stores.get(target);
  if (!store) {
    store = new NativeMainCredentialStore({ authPath: target });
    stores.set(target, store);
    if (didRunOptionalShutdownHooks()) {
      store.stop();
    } else {
      store.start();
      if (!detachShutdownHook) {
        detachShutdownHook = registerOptionalShutdownHook("native-main-auth", stopNativeMainCredentialWatchers);
      }
    }
  }
  return store;
}

export function getNativeMainAuthMemory(path: string): NativeMainAuthMemoryRead {
  return storeFor(path).readMemory();
}

export function observeNativeMainAuthFile(path: string): NativeMainAuthMemoryRead {
  return storeFor(path).observeNow();
}

export function nativeMainAuthCanRefreshOrWrite(path: string): boolean {
  return storeFor(path).canRefreshOrWrite();
}

export function persistRefreshedNativeMainAuthFile(
  path: string,
  raw: string,
  options: NativeMainRefreshWriteOptions,
): Promise<NativeMainRefreshWriteResult> {
  return storeFor(path).persistRefresh(raw, options);
}

export function writeNativeMainAuthFileSyncClaimed(
  path: string,
  raw: string,
  options: NativeMainAuthWriteOptions,
): NativeMainAuthWriteReceipt {
  return storeFor(path).writeAuthFileSync(raw, options);
}

export async function writeNativeMainAuthFileAsyncClaimed(
  path: string,
  raw: string,
  options: NativeMainAuthWriteOptions,
  writeOverride?: NativeMainAuthWriteOverride,
): Promise<NativeMainAuthWriteReceipt> {
  return await storeFor(path).writeAuthFileAsync(raw, options, writeOverride);
}

export function verifyNativeMainAuthWriteReceipt(receipt: NativeMainAuthWriteReceipt): boolean {
  return storeFor(receipt.path).verifyReceipt(receipt);
}

export function stopNativeMainCredentialWatchers(): void {
  for (const store of stores.values()) store.stop();
  stores.clear();
  detachShutdownHook?.();
  detachShutdownHook = null;
}
