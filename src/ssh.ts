import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { escapeScpRemotePath } from "./security.js";

const execFileAsync = promisify(execFile);

export interface SshConfig {
  host: string;
  user: string;
  port: number;
  keyPath?: string;
  password?: string;
  connectTimeoutSec: number;
  commandTimeoutSec: number;
  strictHostKeyChecking: "yes" | "no" | "accept-new";
  knownHostsFile: string;
}

export interface ExecResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  signal: NodeJS.Signals | null;
  authMode: "key" | "password";
}

interface RawExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  signal: NodeJS.Signals | null;
}

export class SshRunner {
  private readonly config: SshConfig;

  private sshpassAvailableCache: boolean | null = null;

  constructor(config: SshConfig) {
    this.config = config;
  }

  async execRemote(command: string, timeoutSec?: number): Promise<ExecResult> {
    const timeoutMs = (timeoutSec ?? this.config.commandTimeoutSec) * 1_000;
    const keyAttempt = await this.runSshCommand(command, timeoutMs, true);
    if (keyAttempt.ok || !this.shouldTryPassword(keyAttempt.stderr)) {
      return keyAttempt;
    }

    const passwordAttempt = await this.runSshCommand(command, timeoutMs, false);
    return passwordAttempt;
  }

  async copyFromRemote(remotePath: string, localPath: string, timeoutSec?: number): Promise<ExecResult> {
    const timeoutMs = (timeoutSec ?? this.config.commandTimeoutSec) * 1_000;
    const destination = path.resolve(localPath);
    const remoteSpec = `${this.config.user}@${this.config.host}:${escapeScpRemotePath(remotePath)}`;

    const keyAttempt = await this.runScp([remoteSpec, destination], timeoutMs, true);
    if (keyAttempt.ok || !this.shouldTryPassword(keyAttempt.stderr)) {
      return keyAttempt;
    }

    return this.runScp([remoteSpec, destination], timeoutMs, false);
  }

  async copyToRemote(localPath: string, remotePath: string, timeoutSec?: number): Promise<ExecResult> {
    const timeoutMs = (timeoutSec ?? this.config.commandTimeoutSec) * 1_000;
    const source = path.resolve(localPath);
    const remoteSpec = `${this.config.user}@${this.config.host}:${escapeScpRemotePath(remotePath)}`;

    const keyAttempt = await this.runScp([source, remoteSpec], timeoutMs, true);
    if (keyAttempt.ok || !this.shouldTryPassword(keyAttempt.stderr)) {
      return keyAttempt;
    }

    return this.runScp([source, remoteSpec], timeoutMs, false);
  }

  private sshBaseArgs(batchMode: boolean): string[] {
    const args: string[] = [
      "-p",
      String(this.config.port),
      "-T",
      "-o",
      `ConnectTimeout=${this.config.connectTimeoutSec}`,
      "-o",
      "ServerAliveInterval=15",
      "-o",
      "ServerAliveCountMax=2",
      "-o",
      `StrictHostKeyChecking=${this.config.strictHostKeyChecking}`,
      "-o",
      `UserKnownHostsFile=${this.config.knownHostsFile}`,
      "-o",
      `BatchMode=${batchMode ? "yes" : "no"}`,
    ];

    if (this.config.keyPath && batchMode) {
      args.push("-i", this.config.keyPath);
    }

    if (!batchMode) {
      args.push("-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no");
    }

    return args;
  }

  private scpBaseArgs(batchMode: boolean): string[] {
    const args: string[] = [
      "-P",
      String(this.config.port),
      "-o",
      `ConnectTimeout=${this.config.connectTimeoutSec}`,
      "-o",
      `StrictHostKeyChecking=${this.config.strictHostKeyChecking}`,
      "-o",
      `UserKnownHostsFile=${this.config.knownHostsFile}`,
      "-o",
      `BatchMode=${batchMode ? "yes" : "no"}`,
    ];

    if (this.config.keyPath && batchMode) {
      args.push("-i", this.config.keyPath);
    }

    if (!batchMode) {
      args.push("-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no");
    }

    return args;
  }

  private async runSshCommand(command: string, timeoutMs: number, batchMode: boolean): Promise<ExecResult> {
    const args = [...this.sshBaseArgs(batchMode), `${this.config.user}@${this.config.host}`, command];
    const result = await this.execWithOptionalSshPass("ssh", args, timeoutMs, batchMode);
    return {
      ok: result.exitCode === 0,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      signal: result.signal,
      authMode: batchMode ? "key" : "password",
    };
  }

  private async runScp(pathArgs: string[], timeoutMs: number, batchMode: boolean): Promise<ExecResult> {
    const args = [...this.scpBaseArgs(batchMode), ...pathArgs];
    const result = await this.execWithOptionalSshPass("scp", args, timeoutMs, batchMode);
    return {
      ok: result.exitCode === 0,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      signal: result.signal,
      authMode: batchMode ? "key" : "password",
    };
  }

  private async execWithOptionalSshPass(
    command: string,
    args: string[],
    timeoutMs: number,
    batchMode: boolean,
  ): Promise<RawExecResult> {
    if (batchMode || !this.config.password) {
      return execFileSafe(command, args, timeoutMs);
    }

    const hasSshpass = await this.hasSshpass();
    if (!hasSshpass) {
      return {
        stdout: "",
        stderr:
          "Password fallback requested but sshpass is not installed. Install sshpass or configure IPHONE_SSH_KEY_PATH.",
        exitCode: 255,
        signal: null,
      };
    }

    return execFileSafe("sshpass", ["-p", this.config.password, command, ...args], timeoutMs);
  }

  private shouldTryPassword(stderr: string): boolean {
    if (!this.config.password) {
      return false;
    }
    return /permission denied|publickey|keyboard-interactive|authentication/i.test(stderr);
  }

  private async hasSshpass(): Promise<boolean> {
    if (this.sshpassAvailableCache !== null) {
      return this.sshpassAvailableCache;
    }

    const result = await execFileSafe("sshpass", ["-V"], 3_000);
    this.sshpassAvailableCache = result.exitCode === 0;
    return this.sshpassAvailableCache;
  }
}

async function execFileSafe(command: string, args: string[], timeoutMs: number): Promise<RawExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout, stderr, exitCode: 0, signal: null };
  } catch (error) {
    const err = error as Error & {
      stdout?: string;
      stderr?: string;
      code?: number | string;
      signal?: NodeJS.Signals;
    };
    const code = typeof err.code === "number" ? err.code : 1;
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? err.message,
      exitCode: code,
      signal: err.signal ?? null,
    };
  }
}
