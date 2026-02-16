# iOS Python 3.14 - iPhone SSH MCP

Standalone MCP server that connects to a jailbroken iPhone over SSH and exposes practical iPhone tools to MCP clients.

## Features

- SSH command execution with key-first auth and password fallback (`sshpass`)
- Safety policy:
  - command denylist for destructive operations
  - write operations restricted to allowlisted remote roots
- File tools: read/write/list/push/pull
- Device and log inspection tools
- Tweak HTTP tools (`/status`, `/screenshot`, generic endpoint request)
- Stdio transport for MCP host compatibility

## Requirements

- Node.js 18+ (tested on Node 22)
- SSH access to device (`root@<iphone-ip>`)
- Optional: `sshpass` for password fallback auth

## Install

```bash
npm install
npm run build
```

## Run

```bash
npm start
```

For local development:

```bash
npm run dev
```

## Environment Variables

- `IPHONE_SSH_HOST` (default: `10.0.0.9`)
- `IPHONE_SSH_USER` (default: `root`)
- `IPHONE_SSH_PORT` (default: `22`)
- `IPHONE_SSH_KEY_PATH` (default: `~/.ssh/id_rsa`)
- `IPHONE_SSH_PASSWORD` (optional, used only with `sshpass`)
- `IPHONE_SSH_CONNECT_TIMEOUT_SEC` (default: `5`)
- `IPHONE_SSH_COMMAND_TIMEOUT_SEC` (default: `30`)
- `IPHONE_SSH_STRICT_HOST_KEY_CHECKING` (default: `accept-new`)
- `IPHONE_SSH_KNOWN_HOSTS_FILE` (default: `~/.ssh/known_hosts`)
- `IPHONE_TWEAK_PORT` (default: `8765`)
- `IPHONE_TWEAK_TIMEOUT_MS` (default: `8000`)
- `IPHONE_ALLOWED_WRITE_ROOTS` (CSV of remote roots)
- `IPHONE_LOCAL_ARTIFACT_ROOTS` (CSV of local roots where files/screenshots may be written)

## MCP Client Config Example

`mcp-config.example.json`:

```json
{
  "mcpServers": {
    "iphone-ssh": {
      "command": "node",
      "args": ["/Users/davgz/iphone-ssh-mcp/dist/server.js"],
      "env": {
        "IPHONE_SSH_HOST": "10.0.0.9",
        "IPHONE_SSH_USER": "root",
        "IPHONE_SSH_PASSWORD": "alpine"
      }
    }
  }
}
```

## Tools

- `iphone_get_device_info`
- `iphone_run_command`
- `iphone_run_write_command`
- `iphone_list_dir`
- `iphone_read_file`
- `iphone_write_file`
- `iphone_pull_file`
- `iphone_push_file`
- `iphone_get_logs`
- `iphone_get_crash_logs`
- `iphone_respring`
- `iphone_tweak_status`
- `iphone_tweak_request`
- `iphone_take_screenshot`

## Test

```bash
npm run check
```

## Notes

- `iphone_run_command` blocks write-like commands by design.
- Use `iphone_run_write_command` for write actions and provide `write_paths` in allowed roots.
- `iphone_respring` requires `confirm=true`.
