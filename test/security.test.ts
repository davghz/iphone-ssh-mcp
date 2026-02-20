import test from "node:test";
import assert from "node:assert/strict";
import {
  ensureAllowedLocalPath,
  ensureAllowedWritePaths,
  escapeScpRemotePath,
  isLikelyWriteCommand,
  matchDeniedPattern,
  normalizeRemotePath,
  shellQuote,
} from "../src/security.js";

test("normalizeRemotePath requires absolute path", () => {
  assert.throws(() => normalizeRemotePath("var/mobile/test.txt"), /Expected absolute remote path/);
  assert.equal(normalizeRemotePath("/var/mobile/../mobile/a.txt"), "/var/mobile/a.txt");
});

test("ensureAllowedWritePaths enforces roots", () => {
  const roots = ["/var/mobile", "/tmp"];
  assert.deepEqual(ensureAllowedWritePaths(["/var/mobile/test.txt"], roots), ["/var/mobile/test.txt"]);
  assert.throws(() => ensureAllowedWritePaths(["/etc/passwd"], roots), /Write path blocked by allowlist/);
});

test("ensureAllowedLocalPath enforces local roots", () => {
  const root = "/Users/davgz/iphone-ssh-mcp";
  const ok = ensureAllowedLocalPath("/Users/davgz/iphone-ssh-mcp/artifacts/a.txt", [root]);
  assert.equal(ok, "/Users/davgz/iphone-ssh-mcp/artifacts/a.txt");
  assert.throws(() => ensureAllowedLocalPath("/tmp/b.txt", [root]), /Local path blocked/);
});

test("deny patterns block destructive commands", () => {
  assert.ok(matchDeniedPattern("rm -rf /") !== null);
  assert.ok(matchDeniedPattern("reboot") !== null);
  assert.equal(matchDeniedPattern("ls -la"), null);
});

test("write detector catches writes but not read commands", () => {
  assert.equal(isLikelyWriteCommand("ls -la /var/mobile"), false);
  assert.equal(isLikelyWriteCommand("tail -n 200 /var/log/syslog"), false);
  assert.equal(isLikelyWriteCommand("mkdir -p /var/mobile/test"), true);
  assert.equal(isLikelyWriteCommand("python3.14 -m pip install requests"), true);
});

test("shellQuote safely wraps apostrophes", () => {
  assert.equal(shellQuote("abc"), "'abc'");
  assert.equal(shellQuote("a'b"), "'a'\\''b'");
});

test("escapeScpRemotePath escapes shell-significant chars without adding wrapper quotes", () => {
  assert.equal(escapeScpRemotePath("/tmp/file.deb"), "/tmp/file.deb");
  assert.equal(escapeScpRemotePath("/tmp/my file.deb"), "/tmp/my\\ file.deb");
  assert.equal(escapeScpRemotePath("/tmp/weird'file"), "/tmp/weird\\'file");
});
