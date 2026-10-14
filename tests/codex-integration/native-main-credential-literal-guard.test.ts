import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { repoRoot } from "../helpers/repo-root";

const ROOT = repoRoot();
const ALLOWED: string[] = [
  "src/cli/doctor.ts:325",
  "src/codex/auth-collision.ts:36",
  "src/codex/desktop-compatibility/runtime.ts:112",
  "src/codex/home.ts:170",
  "src/codex/main-account.ts:162",
  "src/codex/main-account.ts:483",
  "src/codex/native-profile-manager.ts:800",
  "src/codex/native-profile-manager.ts:1172",
  "src/codex/native-profile-store.ts:377",
  "src/codex/orca-auth-source.ts:85",
  "src/codex/orca-import.ts:145",
  "src/codex/orca-import.ts:200",
  "src/config.ts:219",
  "src/lib/config-ownership.ts:41",
  "src/oauth/command-code.ts:40",
  "src/oauth/local-token-detect.ts:16",
  "src/oauth/meta-muse.ts:33",
  "src/oauth/store.ts:78",
  "src/server/configured-credentials.ts:186",
];

const found: string[] = [];
for (const path of new Bun.Glob("src/**/*.{ts,mts,mjs}").scanSync({ cwd: ROOT, dot: true })) {
  const lines = readFileSync(join(ROOT, path), "utf8").split("\n");
  lines.forEach((line, i) => {
    if (line.includes('"auth.json"')) found.push(`${path.replaceAll("\\", "/")}:${i + 1}`);
  });
}
test("every auth.json literal line in src matches the file:line allowlist", () => {
  expect([...found].sort()).toEqual([...ALLOWED].sort());
});
