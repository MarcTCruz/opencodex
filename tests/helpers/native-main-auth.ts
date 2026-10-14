import { createHash } from "node:crypto";
import { fstatSync, readFileSync, writeFileSync } from "node:fs";
import type { AtomicWritePublicationEvidence, AtomicWriteTargetIdentity } from "../../src/config/atomic-write";
import { observeNativeMainAuthFile } from "../../src/codex/native-main-credentials";

export function observeNativeMainAuthFileForTests(authPath: string): void {
  const observation = observeNativeMainAuthFile(authPath);
  observation.raw?.fill(0);
  observation.snapshot?.raw.fill(0);
}

export function writeNativeMainAuthFileForTests(authPath: string, raw: string): void {
  writeFileSync(authPath, raw);
  observeNativeMainAuthFileForTests(authPath);
}

export function writeNativeMainAuthTokensForTests(authPath: string, tokens: Record<string, unknown>): void {
  writeNativeMainAuthFileForTests(authPath, JSON.stringify({ tokens }));
}

export function captureAtomicWritePublicationEvidence(descriptor: number): AtomicWritePublicationEvidence {
  const before = identityFromDescriptor(descriptor);
  const bytes = readFileSync(descriptor);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const after = identityFromDescriptor(descriptor);
  const size = bytes.byteLength;
  bytes.fill(0);
  if (!sameIdentity(before, after) || after.size !== size) {
    throw new Error("test atomic publication changed while evidence was captured");
  }
  return { identity: after, digest };
}

function identityFromDescriptor(descriptor: number): AtomicWriteTargetIdentity {
  const stat = fstatSync(descriptor);
  return {
    dev: Number(stat.dev),
    ino: Number(stat.ino),
    size: Number(stat.size),
    mode: Number(stat.mode),
    mtimeMs: Number(stat.mtimeMs),
    ctimeMs: Number(stat.ctimeMs),
  };
}

function sameIdentity(left: AtomicWriteTargetIdentity, right: AtomicWriteTargetIdentity): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}
