# Native Main Credentials

`src/codex/native-main-credentials.ts` owns content reads and writes for effective
`$CODEX_HOME/auth.json`. Request, account, lifecycle, profile, and Orca-import checks use its
in-memory snapshot. The home resolver and doctor may check whether the path exists; staged profile
files and explicitly managed Orca homes remain separate inputs.

Ordinary credential reads follow a symlinked `auth.json` to preserve Codex-home compatibility. The
snapshot keeps that link provenance. Bounded token reads, native-profile reads and writability
checks, and Orca main-identity reads reject a symlink. Orca asks the store for a current observation
and proceeds only with a valid current file or a confirmed missing file; stopped, invalid, unreadable,
and grace-period states are refused.

Credential reads use a descriptor opened with no-follow where the platform supports it. The reader
starts with the observed file size, grows its buffer only as needed up to the 4 MiB limit plus one
byte, and checks the descriptor size again after EOF. Oversized or concurrently growing files are
refused; only allocated scratch buffers are cleared.

The store watches the CODEX_HOME directory and runs a 250 ms stat check. A changed device, inode,
size, mode, mtime, or ctime triggers a bounded read and hash. A one-second fixed cadence also forces
that read and hash when the stat signature is unchanged, so dropped events and same-size rewrites
converge. Directory events, the timer, pre-refresh checks, and pre-publication checks all produce
one immutable observation record through the same classifier. One transition applies it to memory,
deletion grace, hiccup recovery, history, and generation. Watcher errors cause registration to be
retried by the timer, and shutdown closes the watcher and clears both timers.

One classifier decides whether observed content is complete enough to replace memory. A ChatGPT
login needs non-empty access and refresh tokens; an API-key login needs a non-empty key. The profile
parser separately requires its ID-token and account-identity fields to encrypt a profile. Those
fields do not arbitrate between complete logins: every complete external change wins without
expiry, account, or other precedence checks. Empty, partial, malformed, or unreadable files leave
the last good snapshot available, retain any rotated refresh grant, and pause refresh and every
OpenCodex write. Missing files start a ten-minute grace period with the same write block. A valid
file restored within that period is observed; after ten continuous minutes of confirmed absence,
the cache and pending refresh are cleared so an old grant cannot recreate the file.

The observation record preserves witnessed presence from every probe, including the initial stat,
leaf lstat, read, and both post-read probes. Any witnessed presence ends the absence interval even
when the final probe sees disappearance. A read failure with a present leaf is an unknown hiccup,
so it retains memory and a rotated refresh grant while blocking writes. Retry authority retains the
original complete physical signature, including mtime and ctime; later recovery from an unknown
observation does not excuse a subsequent observed rewrite. If bounded history no longer proves
whether a complete change intervened, the grant remains in memory and recovery is required rather
than adopting the old disk credential.

Refresh publication runs immediately through the shared temp-file/rename writer; there is no
debounce. Final validation captures receipt authority before rename: the observation sequence and
the temp file's identity. Immediately after rename returns, the sync writer captures publication
evidence synchronously from the retained descriptor. The async writer invokes that capture
synchronously from the rename helper before returning to its promise continuation. Evidence takes
a descriptor `fstat`, hashes bytes read through that descriptor, then takes another `fstat`; it
includes device, inode, size, mode, mtime, and ctime. A receipt is issued only when the descriptor
stays stable, its digest matches the candidate, its identity matches the staged file, and no
unowned observation intervened. Later path observations count as the publication only when their
complete physical signature matches that descriptor evidence. A rewrite after evidence capture is
refused even when it restores mtime and changes only ctime. Any intervening observation, even one
that later sees the old bytes restored, refuses continuation and rollback; the current credential
and encrypted journal remain available for recovery. The receipt binds the accepted target's full
physical signature.
Retries keep their original disk fence when later refresh results are merged into a retained grant.
If an unreadable or invalid observation interrupts a retained refresh grant, retry may continue only
when observation history proves that every intervening observation was a hiccup and the same
complete base identity and digest returned. A complete different observation or truncated history
blocks retry and retains the grant for recovery. Invalid, unreadable, and grace-missing states block
writes including rollback and recovery; profile recovery keeps the encrypted journal until a valid
physical state is observed. Device reauth, profile switch, rollback, and recovery use the same writer.

Refresh and reauth keep their CODEX_HOME claim, and profile operations retain their outer claim,
journal, boundary hooks, read-back verification, and rollback. A Bun parser-based import guard
rejects every module other than the credential store that combines effective-path authority with a
raw filesystem capability. Static imports, re-exports, dynamic imports, and `require` calls are
parsed; importing `createRequire` from `node:module` is itself treated as acquiring a raw
capability. The generic filesystem facade is removed so it cannot export
path-accepting raw readers, writers, or openers.
Modules that need unrelated filesystem operations import their narrow `node:fs` or
`node:fs/promises` operations directly. The import guard recognizes the profile-store
`readBounded` calls only for `context.vaultPath` and `context.journalPath`, and `privateFileState`
only for `context.journalPath` and `context.recoveryBlockPath`. Doctor may use `existsSync` for the
resolved CODEX_HOME directory; `auth.json` existence goes through the credential store. The
generic `readNativeEnvelope` wrappers count as raw capabilities and are rejected if passed the live
auth path; the profile manager uses them only for its verified owned-stage path. These operation/path
exemptions cannot read or write effective `auth.json`. The credential store is the sole module
allowed to combine live-path authority with raw I/O.

After optional shutdown hooks run, a late accessor returns the defined `stopped` status and cannot
start a watcher, timer, or retry.

The ten-minute grace covers the interactive browser handoff rather than only a short filesystem
rewrite gap. It bounds abandoned logins while avoiding a false logout during a normal login.

### Accepted remaining risk

> A Codex write that lands within the same split second as OpenCodex's rename can still be lost.

Closing this window needs a lock that Codex also honors, which requires an upstream Codex change: [openai/codex#40267](https://github.com/openai/codex/issues/40267#issuecomment-6152924173).
