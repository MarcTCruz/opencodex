# Native-main in-memory credential store

## Scope and base

This unit implements the in-memory alternative to the hard-link publication guard for native-main `CODEX_HOME/auth.json`. The inspected base is `a63267c13`; the auth implementation files named in the supplied behavior report have no diff from `3e58c2ce3` to this base.

The supplied behavior report is useful for the main refresh and profile-switch paths, but its reader inventory is not exhaustive for this checkout. The source search also found the account-pause reader, Orca import's main-identity check, and direct profile-manager envelope reads. The implementation and tests cover those paths.

## `auth.json` reader and writer inventory at the base

### Effective Codex home credential (`<CODEX_HOME>/auth.json`)

| Source path | Operation at the base | New boundary |
| --- | --- | --- |
| `src/codex/main-account.ts` | `readMainAuthJsonCredential()` reads/decodes the file for status, refresh, and reauth. Refresh and reauth each call `atomicWriteFile()`. | Read through the native-main memory store; refresh and reauth publish through its writer. |
| `src/codex/auth-collision.ts` | `readCodexTokensResult()` uses `readFileSync()` or `readBounded()`; `readCodexTokens()` and `getMainChatgptAccountId()` are memory-facing callers. | Parse the memory snapshot; preserve the result API and failure statuses. |
| `src/codex/auth-api/main-account-probe.ts` | Reads through `readCodexTokensResult()` both for the initial probe and its bounded current-credential check. | Continue through the memory-backed reader. |
| `src/codex/auth-api/account-pause-group.ts` | Reads via `readCodexTokensResult()` and separately calls `readBounded()` to retain the auth envelope. | Parse both credential and envelope from the memory snapshot. |
| `src/codex/account-lifecycle.ts` | `initializeMainAccountPolicyBinding()` reads a supplied auth path through `readCodexTokensResult(..., { bounded: true })`. | Initialize/observe through the store, then bind from memory. |
| `src/codex/native-profile-manager.ts` | Reads the live envelope for registration, switch, recovery, verification, and doctor. Writes the selected envelope, switch rollback, and recovery rollback with its async atomic writer. | Read live envelopes from memory; send all live auth writes through the central writer while keeping the encrypted journal, boundary hooks, verification, and rollback. Staging `auth.json` files remain separate. |
| `src/codex/native-profile-store.ts` | Its generic `readNativeEnvelopeResult(path)`/`readNativeEnvelope(path)` helpers perform bounded reads; the manager uses them on the live path. | The manager's live-path default uses the memory snapshot. Generic readers remain for non-live/staged paths and independent store tests. |
| `src/codex/orca-import.ts` | `prepare()` bounded-reads `<getCodexHome()>/auth.json` to reserve the main identity during an explicit offline import. | Read the memory snapshot for the effective native-main path. Orca-managed homes remain independent source files. |
| `src/codex/home.ts` | Checks whether `auth.json` exists to decide whether the local Codex home is in use; it does not read credential bytes. | Path discovery remains a filesystem-presence check, outside credential consumption. |
| `src/cli/doctor.ts` | Reports whether `<CODEX_HOME>/auth.json` exists; it does not read credential bytes. | Diagnostic existence check remains unchanged. |
| `src/codex/native-main-auth-temp.ts` | Removes only owned stale `auth.json.ocx.*.tmp` residues; it does not write or read the canonical credential. | Temporary-file cleanup remains separate from the canonical single writer. |

### Other `auth.json` paths found by the whole-`src/` search

| Source path | Operation at the base | Path and relationship |
| --- | --- | --- |
| `src/oauth/store.ts` | Reads and writes provider OAuth credentials and keeps the one-time migration backup. | `<OPENCODEX_HOME>/auth.json`, a separate provider store. |
| `src/server/configured-credentials.ts` | Reads provider OAuth credentials when rebuilding configured-credential state. | Same OpenCodex provider store. |
| `src/providers/devin-provider-merge-migration.ts` | Snapshots the store before moving the retired Devin provider slot and rekeys that slot through the OAuth store API. | Same OpenCodex provider store. |
| `src/config.ts` | Re-pins the existing secret-file permissions. | Same OpenCodex provider store; it does not read credential bytes. |
| `src/oauth/local-token-detect.ts` | Reads the installed Grok CLI credential. | A separate Grok CLI credential store. |
| `src/oauth/meta-muse.ts` | Reads a pointer with no credential secret. | A separate Muse configuration pointer. |
| `src/oauth/command-code.ts` | Reads CommandCode's local login record. | A separate CommandCode login record. |
| `src/codex/orca-auth-source.ts`, `src/codex/orca-import.ts` | Reads explicitly managed Orca account-home credentials. The import also read the effective main file directly at base. | UUID-owned Orca homes; the effective-main import check now uses memory. |
| `src/codex/native-profile-manager.ts` | Reads a staged login and securely removes its staged auth file. | Instance-local plaintext staging home, not the live CODEX_HOME file. |
| `src/codex/home.ts`, `src/cli/doctor.ts` | Test CODEX_HOME auth path presence; doctor also checks the OpenCodex provider-store path and parent-directory writeability. | Discovery and diagnostics only; neither reads token bytes. |
| `src/codex/native-main-auth-temp.ts` | Removes only owned stale `auth.json.ocx.*.tmp` residues. | Same-directory temporary write artifacts, not the canonical credential. |

`src/server/responses/core-auth.ts` and several other files mention auth.json only in comments; they do not open or write it.

## Requirements and implementation map

| # | Owner requirement | Implementation and proof |
| --- | --- | --- |
| 1 | One writer for effective native-main auth, for refresh, device reauth, profile switch, rollback, and recovery. | `src/codex/native-main-credentials.ts` owns temp-file/rename publication; callers use its APIs. A source guard rejects other effective-path readers/writers. |
| 2 | OpenCodex readers use memory, never file bytes. | The store owns the raw memory snapshot; `main-account.ts`, `auth-collision.ts`, account-pause, lifecycle binding, profile manager, and Orca import read it. A source guard covers the effective path. |
| 3 | Reliable observing: directory watcher, short stat-first timer with conditional hashing, plus pre-refresh and pre-write observation; no handle keeps the process alive and shutdown closes both. | The store watches the CODEX_HOME directory, checks on the configured interval, hashes only changed stat signatures, and shares one observer across triggers. Tests simulate a dropped event and verify the timer path. |
| 4 | Adopt valid Codex content; preserve memory through empty, partial, malformed, or unreadable states and never overwrite a hiccup. | The observer accepts usable token envelopes or an API-key envelope, adopts any valid external change regardless of token expiry or account fields, and retains its last good snapshot on hiccups. |
| 5 | Treat deletion as logout only after grace; return a restored valid file within grace; do not refresh/write during grace; permanently clear memory after confirmed deletion. | `NATIVE_MAIN_AUTH_DELETE_GRACE_MS` is a named ten-minute duration to cover the interactive browser-login gap. Store state and tests cover grace, restore, expiry, and no write-back. |
| 6 | Preserve safe publication: temp file + rename, re-observe immediately before rename, and adopt a valid external file on conflict. | The central writer wraps existing atomic writers with a final shared observation and compares an immutable expected file identity/digest and staged-candidate generation before rename; any observed valid external change supersedes the pending candidate. |
| 7 | Publish promptly after refresh and retry non-conflict write failures without debounce; retain a successful grant in memory. | Refresh calls the writer in the same claimed operation; transient I/O failures retain the grant and schedule an unref'd retry starting at 50 ms, exponentially backed off to one second. Invalid, unreadable, and grace-period missing files retain the rotated grant without replacing the hiccup. |
| 8 | Keep the CODEX_HOME exclusive claim around cross-process refresh and write coordination. | Refresh and reauth retain their existing outer claim; native-profile API and startup transactions hold the claim around the central writer; the retry path reacquires the same claim. |

## Tests-first baseline

Before implementation, the new memory-store regression file was run against unchanged base `a63267c13`:

```text
bun test tests/codex-integration/native-main-credential-memory.test.ts
0 pass / 12 fail
```

The failures showed the intended gaps: empty and half-written files lost the last good credential; delete-and-restore had no in-memory grace state; watcher/timer/pre-write observation and confirmed-deletion APIs were absent; a refused refresh publication still raised `MainAuthJsonChangedDuringRefreshError`; and the source guard found direct file reads in `main-account.ts`, `auth-collision.ts`, `account-pause-group.ts`, and `native-profile-manager.ts`. These were the base-red failures; implementation-era and final validation results are recorded in the change report.

## Deletion grace choice

The grace is ten minutes. The relevant upstream behavior deletes `auth.json` before the interactive browser login finishes; a grace measured in seconds would cover a rewrite gap but not a user completing the browser step. Ten minutes covers a normal browser handoff while still making an abandoned login converge to logout in a bounded period. Memory remains usable during that interval, but all refresh and write attempts are blocked. Once confirmed, the cache and pending refresh publication are cleared, so neither an in-memory retry nor a later caller can recreate the deleted file.

## Remaining accepted risk

A Codex in-place write can still land between the final observation and OpenCodex's rename. The observer narrows that interval and preserves valid changes seen before the rename, but only a lock shared with Codex can close it. The upstream Codex writer does not currently take that lock. The hard-link guard prototype remains out of scope.
