import path from "node:path";

export interface DenyPattern {
  regex: RegExp;
  reason: string;
}

export const DENY_PATTERNS: DenyPattern[] = [
  { regex: /\brm\s+-rf\s+\/(\s|$)/i, reason: "Refuses full filesystem deletion (rm -rf /)." },
  { regex: /\bmkfs\b/i, reason: "Refuses filesystem formatting command." },
  { regex: /\bdd\s+if=/i, reason: "Refuses raw disk overwrite command." },
  { regex: /\bshutdown\b/i, reason: "Refuses remote shutdown command." },
  { regex: /\breboot\b/i, reason: "Refuses remote reboot command." },
  { regex: /\bhalt\b/i, reason: "Refuses remote halt command." },
  { regex: /\blaunchctl\s+(bootout|remove)\b/i, reason: "Refuses launchctl destructive operation." },
  { regex: /\bapt(-get)?\s+(remove|purge)\b/i, reason: "Refuses package removal command." },
  { regex: /\bchflags\s+-R\s+uchg\b/i, reason: "Refuses recursive immutable flag write." },
];

const WRITE_COMMAND_PATTERNS: RegExp[] = [
  /\b(touch|mkdir|rmdir|mv|cp|rm|ln|install|tee|truncate|chmod|chown|chgrp)\b/i,
  /\bsed\s+-i\b/i,
  /\bperl\s+-i\b/i,
  /\bpython\d*(\.\d+)?\s+-m\s+pip\s+install\b/i,
  /\bapt(-get)?\s+install\b/i,
];

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function normalizeRemotePath(value: string): string {
  if (!value.startsWith("/")) {
    throw new Error(`Expected absolute remote path, got: ${value}`);
  }
  return path.posix.normalize(value);
}

export function normalizeLocalPath(value: string): string {
  return path.resolve(value);
}

export function pathWithinRoots(target: string, roots: string[]): boolean {
  return roots.some((root) => {
    const normalizedRoot = path.posix.normalize(root);
    return target === normalizedRoot || target.startsWith(`${normalizedRoot}/`);
  });
}

export function localPathWithinRoots(target: string, roots: string[]): boolean {
  return roots.some((root) => {
    const normalizedRoot = path.resolve(root);
    return target === normalizedRoot || target.startsWith(`${normalizedRoot}${path.sep}`);
  });
}

export function ensureAllowedWritePaths(paths: string[], allowedRoots: string[]): string[] {
  const normalized = paths.map(normalizeRemotePath);
  const denied = normalized.filter((entry) => !pathWithinRoots(entry, allowedRoots));
  if (denied.length > 0) {
    throw new Error(
      `Write path blocked by allowlist. Allowed roots: ${allowedRoots.join(", ")}. Blocked: ${denied.join(", ")}`,
    );
  }
  return normalized;
}

export function ensureAllowedLocalPath(pathname: string, allowedRoots: string[]): string {
  const normalized = normalizeLocalPath(pathname);
  if (!localPathWithinRoots(normalized, allowedRoots)) {
    throw new Error(
      `Local path blocked. Allowed local roots: ${allowedRoots.join(", ")}. Blocked: ${normalized}`,
    );
  }
  return normalized;
}

export function matchDeniedPattern(command: string, patterns: DenyPattern[] = DENY_PATTERNS): DenyPattern | null {
  for (const pattern of patterns) {
    if (pattern.regex.test(command)) {
      return pattern;
    }
  }
  return null;
}

export function isLikelyWriteCommand(command: string): boolean {
  return WRITE_COMMAND_PATTERNS.some((pattern) => pattern.test(command));
}

export function escapeScpRemotePath(pathname: string): string {
  // SCP path args are passed directly as argv (no local shell), so wrapping the
  // path in quotes makes those quotes literal on the remote side. Escape only
  // characters that SCP's remote shell parsing can treat specially.
  return pathname.replace(/([\\\s"'`$!#&*()[\]{};<>?|~:])/g, "\\$1");
}
