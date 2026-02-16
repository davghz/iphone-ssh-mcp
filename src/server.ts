#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { config, summarizeConfig } from "./config.js";
import {
  ensureAllowedLocalPath,
  ensureAllowedWritePaths,
  isLikelyWriteCommand,
  matchDeniedPattern,
  normalizeRemotePath,
  shellQuote,
} from "./security.js";
import { type ExecResult, SshRunner } from "./ssh.js";
import { TweakClient } from "./tweak.js";

const ssh = new SshRunner({
  host: config.sshHost,
  user: config.sshUser,
  port: config.sshPort,
  keyPath: config.sshKeyPath,
  password: config.sshPassword,
  connectTimeoutSec: config.sshConnectTimeoutSec,
  commandTimeoutSec: config.sshCommandTimeoutSec,
  strictHostKeyChecking: config.sshStrictHostKeyChecking,
  knownHostsFile: config.sshKnownHostsFile,
});

const tweak = new TweakClient({
  host: config.sshHost,
  port: config.tweakPort,
  timeoutMs: config.tweakTimeoutMs,
});

type ToolResult = CallToolResult;

const RunCommandArgs = z.object({
  command: z.string().min(1),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const RunWriteCommandArgs = z.object({
  command: z.string().min(1),
  write_paths: z.array(z.string().min(1)).min(1),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const ListDirArgs = z.object({
  path: z.string().default("/var/mobile"),
  show_hidden: z.boolean().default(true),
  max_entries: z.number().int().min(1).max(2000).default(200),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const ReadFileArgs = z.object({
  path: z.string().min(1),
  max_bytes: z.number().int().min(1).max(1_000_000).default(64_000),
  encoding: z.enum(["text", "base64"]).default("text"),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const WriteFileArgs = z.object({
  path: z.string().min(1),
  content: z.string(),
  mode: z
    .string()
    .regex(/^[0-7]{3,4}$/)
    .default("0644"),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const PullFileArgs = z.object({
  remote_path: z.string().min(1),
  local_path: z.string().min(1),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const PushFileArgs = z.object({
  local_path: z.string().min(1),
  remote_path: z.string().min(1),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const LogsArgs = z.object({
  filter: z.string().optional(),
  lines: z.number().int().min(1).max(5000).default(200),
  minutes: z.number().int().min(1).max(120).default(10),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const CrashLogsArgs = z.object({
  app_name: z.string().min(1),
  lines: z.number().int().min(1).max(2000).default(120),
  timeout_sec: z.number().int().min(1).max(300).optional(),
});

const RespringArgs = z.object({
  confirm: z.boolean().default(false),
  timeout_sec: z.number().int().min(1).max(60).default(20),
});

const TweakRequestArgs = z.object({
  endpoint: z.string().min(1),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  body: z.unknown().optional(),
});

const ScreenshotArgs = z.object({
  save_path: z.string().optional(),
});

const EMPTY_OBJECT_SCHEMA = {
  type: "object",
  properties: {},
};

const TOOLS = [
  {
    name: "iphone_get_device_info",
    description: "Fetch baseline iPhone device/runtime info over SSH.",
    inputSchema: EMPTY_OBJECT_SCHEMA,
  },
  {
    name: "iphone_run_command",
    description:
      "Run a read-only shell command on iPhone over SSH. Write-like commands are blocked here.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        timeout_sec: { type: "number" },
      },
      required: ["command"],
    },
  },
  {
    name: "iphone_run_write_command",
    description:
      "Run a write-capable SSH command. Requires write_paths that must stay inside allowlisted roots.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        write_paths: { type: "array", items: { type: "string" } },
        timeout_sec: { type: "number" },
      },
      required: ["command", "write_paths"],
    },
  },
  {
    name: "iphone_list_dir",
    description: "List directory contents on iPhone.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        show_hidden: { type: "boolean" },
        max_entries: { type: "number" },
        timeout_sec: { type: "number" },
      },
    },
  },
  {
    name: "iphone_read_file",
    description: "Read a remote file from iPhone as text or base64.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        max_bytes: { type: "number" },
        encoding: { type: "string", enum: ["text", "base64"] },
        timeout_sec: { type: "number" },
      },
      required: ["path"],
    },
  },
  {
    name: "iphone_write_file",
    description: "Write a text file on iPhone within allowlisted write roots.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        content: { type: "string" },
        mode: { type: "string" },
        timeout_sec: { type: "number" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "iphone_pull_file",
    description: "Copy remote file from iPhone to local machine via scp.",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: { type: "string" },
        local_path: { type: "string" },
        timeout_sec: { type: "number" },
      },
      required: ["remote_path", "local_path"],
    },
  },
  {
    name: "iphone_push_file",
    description: "Copy local file to iPhone via scp into allowlisted write roots.",
    inputSchema: {
      type: "object",
      properties: {
        local_path: { type: "string" },
        remote_path: { type: "string" },
        timeout_sec: { type: "number" },
      },
      required: ["local_path", "remote_path"],
    },
  },
  {
    name: "iphone_get_logs",
    description: "Fetch recent iPhone logs with optional filter.",
    inputSchema: {
      type: "object",
      properties: {
        filter: { type: "string" },
        lines: { type: "number" },
        minutes: { type: "number" },
        timeout_sec: { type: "number" },
      },
    },
  },
  {
    name: "iphone_get_crash_logs",
    description: "Fetch crash logs matching an app name from CrashReporter folder.",
    inputSchema: {
      type: "object",
      properties: {
        app_name: { type: "string" },
        lines: { type: "number" },
        timeout_sec: { type: "number" },
      },
      required: ["app_name"],
    },
  },
  {
    name: "iphone_respring",
    description: "Respring the iPhone (kill SpringBoard). Requires confirm=true.",
    inputSchema: {
      type: "object",
      properties: {
        confirm: { type: "boolean" },
        timeout_sec: { type: "number" },
      },
    },
  },
  {
    name: "iphone_tweak_status",
    description: "Check tweak HTTP status endpoint (/status).",
    inputSchema: EMPTY_OBJECT_SCHEMA,
  },
  {
    name: "iphone_tweak_request",
    description: "Make arbitrary HTTP request to tweak endpoint.",
    inputSchema: {
      type: "object",
      properties: {
        endpoint: { type: "string" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
        body: {},
      },
      required: ["endpoint"],
    },
  },
  {
    name: "iphone_take_screenshot",
    description: "Capture screenshot from tweak endpoint (/screenshot).",
    inputSchema: {
      type: "object",
      properties: {
        save_path: { type: "string" },
      },
    },
  },
] as const;

const server = new Server(
  {
    name: "iphone-ssh-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...TOOLS] }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments ?? {};

  try {
    switch (request.params.name) {
      case "iphone_get_device_info": {
        const command = [
          "echo '== uname ==' && uname -a",
          "echo '== os ==' && (sysctl -n kern.osversion 2>/dev/null || true)",
          "echo '== uptime ==' && uptime",
          "echo '== disk ==' && df -h /",
          "echo '== python ==' && (python3.14 -V 2>/dev/null || python3 -V 2>/dev/null || echo 'python3 not found')",
          "echo '== pip ==' && (python3.14 -m pip --version 2>/dev/null || python3 -m pip --version 2>/dev/null || echo 'pip not found')",
        ].join(" ; ");

        const result = await execReadCommand(command);
        return withExecResult(result);
      }

      case "iphone_run_command": {
        const parsed = parseArgs(RunCommandArgs, args);
        const result = await execReadCommand(parsed.command, parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_run_write_command": {
        const parsed = parseArgs(RunWriteCommandArgs, args);
        const result = await execWriteCommand(parsed.command, parsed.write_paths, parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_list_dir": {
        const parsed = parseArgs(ListDirArgs, args);
        const remotePath = normalizeRemotePath(parsed.path);
        const listFlags = parsed.show_hidden ? "-la" : "-l";
        const command = [
          `if [ -d ${shellQuote(remotePath)} ]; then`,
          `  ls ${listFlags} ${shellQuote(remotePath)} | head -n ${parsed.max_entries}`,
          "else",
          `  echo 'Directory not found: ${remotePath}' >&2 ; exit 2`,
          "fi",
        ].join(" ");

        const result = await execReadCommand(command, parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_read_file": {
        const parsed = parseArgs(ReadFileArgs, args);
        const remotePath = normalizeRemotePath(parsed.path);
        const readCommand =
          parsed.encoding === "base64"
            ? `if [ -f ${shellQuote(remotePath)} ]; then base64 < ${shellQuote(remotePath)} | tr -d '\\n'; else echo 'File not found: ${remotePath}' >&2; exit 2; fi`
            : `if [ -f ${shellQuote(remotePath)} ]; then head -c ${parsed.max_bytes} ${shellQuote(remotePath)}; else echo 'File not found: ${remotePath}' >&2; exit 2; fi`;

        const result = await execReadCommand(readCommand, parsed.timeout_sec);
        if (!result.ok) {
          return withExecResult(result);
        }

        const payload = parsed.encoding === "base64" ? result.stdout.trim() : result.stdout;
        return textResult(
          [`path: ${remotePath}`, `encoding: ${parsed.encoding}`, "", payload].join("\n"),
          false,
        );
      }

      case "iphone_write_file": {
        const parsed = parseArgs(WriteFileArgs, args);
        const remotePath = normalizeRemotePath(parsed.path);
        ensureAllowedWritePaths([remotePath], config.allowedWriteRoots);

        const dir = path.posix.dirname(remotePath);
        const writeCommand =
          `mkdir -p ${shellQuote(dir)} && ` +
          `printf '%s' ${shellQuote(parsed.content)} > ${shellQuote(remotePath)} && ` +
          `chmod ${parsed.mode} ${shellQuote(remotePath)}`;

        const result = await execWriteCommand(writeCommand, [remotePath], parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_pull_file": {
        const parsed = parseArgs(PullFileArgs, args);
        const remotePath = normalizeRemotePath(parsed.remote_path);
        const localPath = ensureAllowedLocalPath(parsed.local_path, config.localArtifactRoots);

        await fs.mkdir(path.dirname(localPath), { recursive: true });
        const result = await ssh.copyFromRemote(remotePath, localPath, parsed.timeout_sec);

        const summary = result.ok
          ? `Pulled ${remotePath} -> ${localPath}`
          : `Failed pulling ${remotePath} -> ${localPath}`;

        return textResult(`${summary}\n\n${formatExecResult(result)}`, !result.ok);
      }

      case "iphone_push_file": {
        const parsed = parseArgs(PushFileArgs, args);
        const localPath = path.resolve(parsed.local_path);
        const remotePath = normalizeRemotePath(parsed.remote_path);
        ensureAllowedWritePaths([remotePath], config.allowedWriteRoots);

        await fs.access(localPath);
        const result = await ssh.copyToRemote(localPath, remotePath, parsed.timeout_sec);

        const summary = result.ok
          ? `Pushed ${localPath} -> ${remotePath}`
          : `Failed pushing ${localPath} -> ${remotePath}`;

        return textResult(`${summary}\n\n${formatExecResult(result)}`, !result.ok);
      }

      case "iphone_get_logs": {
        const parsed = parseArgs(LogsArgs, args);
        const base = `(log show --last ${parsed.minutes}m --style compact 2>/dev/null || tail -n ${parsed.lines} /var/log/syslog 2>/dev/null || echo 'No log source available')`;
        const filtered = parsed.filter ? `${base} | grep -i -- ${shellQuote(parsed.filter)}` : base;
        const command = `${filtered} | tail -n ${parsed.lines}`;

        const result = await execReadCommand(command, parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_get_crash_logs": {
        const parsed = parseArgs(CrashLogsArgs, args);
        const command = [
          "find /var/mobile/Library/Logs/CrashReporter -type f 2>/dev/null",
          `| grep -i -- ${shellQuote(parsed.app_name)}`,
          "| head -n 5",
          "| while read -r f; do",
          "echo \"== $f ==\";",
          `tail -n ${parsed.lines} \"$f\";`,
          "echo;",
          "done",
        ].join(" ");

        const result = await execReadCommand(command, parsed.timeout_sec);
        return withExecResult(result);
      }

      case "iphone_respring": {
        const parsed = parseArgs(RespringArgs, args);
        if (!parsed.confirm) {
          return textResult("Refused: set confirm=true to execute respring.", true);
        }

        const result = await ssh.execRemote("killall -9 SpringBoard", parsed.timeout_sec);
        if (
          !result.ok &&
          /connection to .* closed/i.test(result.stderr) &&
          result.exitCode === 255
        ) {
          return textResult("Respring command likely executed; SSH connection dropped as SpringBoard restarted.", false);
        }
        return withExecResult(result);
      }

      case "iphone_tweak_status": {
        const response = await tweak.request("/status");
        if (!response.ok) {
          return textResult(`Tweak status request failed: ${response.error ?? response.raw}`, true);
        }
        return textResult(`status=${response.status}\n${formatUnknown(response.data)}`, false);
      }

      case "iphone_tweak_request": {
        const parsed = parseArgs(TweakRequestArgs, args);
        if (!parsed.endpoint.startsWith("/")) {
          return textResult("Endpoint must start with '/'.", true);
        }
        const response = await tweak.request(parsed.endpoint, parsed.method, parsed.body);
        if (!response.ok) {
          return textResult(
            `Tweak request failed: endpoint=${parsed.endpoint} status=${response.status} error=${response.error ?? response.raw}`,
            true,
          );
        }
        return textResult(`status=${response.status}\n${formatUnknown(response.data)}`, false);
      }

      case "iphone_take_screenshot": {
        const parsed = parseArgs(ScreenshotArgs, args);
        const response = await tweak.request("/screenshot", "GET");
        if (!response.ok || typeof response.data !== "object" || response.data === null) {
          return textResult(`Screenshot request failed: ${response.error ?? response.raw}`, true);
        }

        const image = (response.data as { image?: unknown }).image;
        if (typeof image !== "string" || image.length === 0) {
          return textResult(`Screenshot endpoint did not return image payload. Raw: ${formatUnknown(response.data)}`, true);
        }

        if (parsed.save_path) {
          const localPath = ensureAllowedLocalPath(parsed.save_path, config.localArtifactRoots);
          await fs.mkdir(path.dirname(localPath), { recursive: true });
          await fs.writeFile(localPath, Buffer.from(image, "base64"));
          return textResult(`Screenshot saved to ${localPath}`, false);
        }

        return {
          content: [
            { type: "text", text: "Screenshot captured." },
            { type: "image", data: image, mimeType: "image/png" },
          ],
        } satisfies ToolResult;
      }

      default:
        return textResult(`Unknown tool: ${request.params.name}`, true);
    }
  } catch (error) {
    return textResult(formatError(error), true);
  }
});

function parseArgs<T extends z.ZodTypeAny>(schema: T, args: unknown): z.infer<T> {
  const parsed = schema.safeParse(args);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`);
    throw new Error(`Invalid arguments. ${issues.join("; ")}`);
  }
  return parsed.data;
}

async function execReadCommand(command: string, timeoutSec?: number): Promise<ExecResult> {
  const denied = matchDeniedPattern(command);
  if (denied) {
    throw new Error(`Blocked by denylist: ${denied.reason}`);
  }

  if (isLikelyWriteCommand(command)) {
    throw new Error(
      "Write-like command blocked in iphone_run_command/readonly context. Use iphone_run_write_command with write_paths.",
    );
  }

  return ssh.execRemote(command, timeoutSec);
}

async function execWriteCommand(
  command: string,
  writePaths: string[],
  timeoutSec?: number,
): Promise<ExecResult> {
  const denied = matchDeniedPattern(command);
  if (denied) {
    throw new Error(`Blocked by denylist: ${denied.reason}`);
  }

  ensureAllowedWritePaths(writePaths, config.allowedWriteRoots);
  return ssh.execRemote(command, timeoutSec);
}

function withExecResult(result: ExecResult): ToolResult {
  return textResult(formatExecResult(result), !result.ok);
}

function formatExecResult(result: ExecResult): string {
  const lines: string[] = [
    `auth_mode: ${result.authMode}`,
    `exit_code: ${result.exitCode}`,
  ];

  if (result.signal) {
    lines.push(`signal: ${result.signal}`);
  }

  if (result.stdout.trim()) {
    lines.push("stdout:", result.stdout.trimEnd());
  }

  if (result.stderr.trim()) {
    lines.push("stderr:", result.stderr.trimEnd());
  }

  return lines.join("\n");
}

function textResult(text: string, isError: boolean): ToolResult {
  return {
    content: [{ type: "text", text }],
    isError,
  };
}

function formatUnknown(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`iphone-ssh-mcp started: ${summarizeConfig(config)}`);
}

main().catch((error) => {
  console.error("Failed to start iphone-ssh-mcp", error);
  process.exitCode = 1;
});
