import os from "node:os";
import path from "node:path";

const DEFAULT_WRITE_ROOTS = [
  "/var/mobile",
  "/private/var/mobile",
  "/var/root",
  "/private/var/root",
  "/tmp",
  "/private/tmp",
  "/var/tmp",
  "/private/var/tmp",
  "/usr/local",
];

export interface ServerConfig {
  sshHost: string;
  sshUser: string;
  sshPort: number;
  sshKeyPath?: string;
  sshPassword?: string;
  sshConnectTimeoutSec: number;
  sshCommandTimeoutSec: number;
  sshStrictHostKeyChecking: "yes" | "no" | "accept-new";
  sshKnownHostsFile: string;
  tweakPort: number;
  tweakTimeoutMs: number;
  allowedWriteRoots: string[];
  localArtifactRoots: string[];
}

function env(name: string, fallback?: string): string | undefined {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    return fallback;
  }
  return value.trim();
}

function envInt(name: string, fallback: number): number {
  const value = env(name);
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function envList(name: string, fallback: string[]): string[] {
  const value = env(name);
  if (!value) return fallback;
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizePathList(paths: string[]): string[] {
  return [...new Set(paths.map((entry) => path.posix.normalize(entry)))];
}

const defaultKnownHosts = path.join(os.homedir(), ".ssh", "known_hosts");
const defaultKeyPath = path.join(os.homedir(), ".ssh", "id_rsa");

export const config: ServerConfig = {
  sshHost: env("IPHONE_SSH_HOST", "10.0.0.9")!,
  sshUser: env("IPHONE_SSH_USER", "root")!,
  sshPort: envInt("IPHONE_SSH_PORT", 22),
  sshKeyPath: env("IPHONE_SSH_KEY_PATH", defaultKeyPath),
  sshPassword: env("IPHONE_SSH_PASSWORD"),
  sshConnectTimeoutSec: envInt("IPHONE_SSH_CONNECT_TIMEOUT_SEC", 5),
  sshCommandTimeoutSec: envInt("IPHONE_SSH_COMMAND_TIMEOUT_SEC", 30),
  sshStrictHostKeyChecking: (env("IPHONE_SSH_STRICT_HOST_KEY_CHECKING", "accept-new") as
    | "yes"
    | "no"
    | "accept-new") ?? "accept-new",
  sshKnownHostsFile: env("IPHONE_SSH_KNOWN_HOSTS_FILE", defaultKnownHosts)!,
  tweakPort: envInt("IPHONE_TWEAK_PORT", 8765),
  tweakTimeoutMs: envInt("IPHONE_TWEAK_TIMEOUT_MS", 8_000),
  allowedWriteRoots: normalizePathList(envList("IPHONE_ALLOWED_WRITE_ROOTS", DEFAULT_WRITE_ROOTS)),
  localArtifactRoots: normalizePathList(
    envList("IPHONE_LOCAL_ARTIFACT_ROOTS", [path.resolve(process.cwd())]),
  ),
};

export function summarizeConfig(input: ServerConfig): string {
  const keyAuth = input.sshKeyPath ? `key=${input.sshKeyPath}` : "key=<none>";
  const pwAuth = input.sshPassword ? "password=set" : "password=<unset>";
  return [
    `ssh=${input.sshUser}@${input.sshHost}:${input.sshPort}`,
    keyAuth,
    pwAuth,
    `tweak=http://${input.sshHost}:${input.tweakPort}`,
    `write_roots=${input.allowedWriteRoots.join(",")}`,
    `local_roots=${input.localArtifactRoots.join(",")}`,
  ].join(" | ");
}
