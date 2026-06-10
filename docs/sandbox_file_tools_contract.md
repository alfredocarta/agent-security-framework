# Sandboxed Hermes file tools native contract

Phase 2 routes `read_file`, `write_file`, `patch`, and `search_files` through the same sandbox runner used by `terminal` and `execute_code` when `ASF_HERMES_SANDBOX=true` and `ASF_HERMES_SANDBOX_FILE_TOOLS` is enabled. The worker must preserve the native Hermes result contract exactly from the agent and dashboard perspective.

Security scope: this phase does not claim read confinement. The current Seatbelt profile still allows broad reads via `(allow file-read*)`. The Phase 2 gains are write confinement to `WORKDIR`, out-of-process execution for the four file tools, explicit write path checks in the worker, and a single sandbox runner choke point.

## Native dispatch contract inspected

Source inspected: `~/.hermes/hermes-agent/tools/file_tools.py` and `~/.hermes/hermes-agent/tools/registry.py`.

Registry dispatch contract:

- `tools.registry.registry.dispatch(name, args, **kwargs) -> str`
- Handlers return a JSON string on success and error.
- Registry-level unknown tool errors return `{"error": "Unknown tool: <name>"}`.
- Registry-level exceptions return `{"error": "Tool execution failed: <ExceptionType>: <message>"}` after Hermes sanitization when available.

## `read_file`

Input args:

- `path: string` required
- `offset: integer` optional, default `1`
- `limit: integer` optional, default `500`, schema maximum `2000`
- `task_id` is accepted via dispatch kwargs and defaults to `"default"`.

Handler call:

`read_file_tool(path=args.get("path", ""), offset=args.get("offset", 1), limit=args.get("limit", 500), task_id=tid)`

Success output shape, native sample:

```json
{
  "content": "     1|alpha\n     2|beta\n     3|",
  "total_lines": 3,
  "file_size": 17,
  "truncated": true,
  "hint": "Use offset=3 to continue reading (showing 1-2 of 3 lines)",
  "is_binary": false,
  "is_image": false
}
```

Other possible keys from `ReadResult.to_dict()`:

- `base64_content`
- `mime_type`
- `dimensions`
- `error`
- `similar_files`
- `_hint`
- `_warning`
- repeated-read guard keys such as `path`, `already_read`, `status`, `message`, `dedup`, `content_returned`.

Missing-file error sample:

```json
{
  "content": "",
  "total_lines": 0,
  "file_size": 0,
  "truncated": false,
  "is_binary": false,
  "is_image": false,
  "error": "File not found: /path/to/missing.txt",
  "similar_files": ["/path/to/sample.txt"]
}
```

## `write_file`

Input args:

- `path: string` required
- `content: string` required
- `task_id` accepted via dispatch kwargs, default `"default"`.

Handler validates missing or non-string `path` and `content` before calling native write logic.

Success output shape, native sample:

```json
{
  "bytes_written": 8,
  "dirs_created": true,
  "lint": {
    "status": "skipped",
    "message": "No linter for .txt files"
  }
}
```

Other possible keys from `WriteResult.to_dict()`:

- `lsp_diagnostics`
- `error`
- `warning`
- `_warning`

Missing-content error sample:

```json
{
  "error": "write_file: missing required field 'content'. The tool call included a path but no content argument - this is almost always a dropped-arg bug under context pressure. Re-emit the tool call with the full content payload, or use execute_code with hermes_tools.write_file() for very large files."
}
```

Sensitive path denial sample:

```json
{
  "error": "Refusing to write to sensitive system path: /path/outside-safe-root\nUse the terminal tool with sudo if you need to modify system files."
}
```

## `patch`

Input args:

- `mode: "replace" | "patch"`, optional at handler level with default `"replace"`; schema marks it required.
- Replace mode:
  - `path: string` required
  - `old_string: string` required
  - `new_string: string` required
  - `replace_all: boolean` optional, default `false`
- Patch mode:
  - `patch: string` required, V4A format.
- `task_id` accepted via dispatch kwargs, default `"default"`.

Success output shape, replace mode native sample:

```json
{
  "success": true,
  "diff": "--- a//path/sample.txt\n+++ b//path/sample.txt\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+BETA\n gamma\n",
  "files_modified": ["/path/sample.txt"],
  "lint": {
    "status": "skipped",
    "message": "No linter for .txt files"
  }
}
```

Success output shape, V4A mode native sample:

```json
{
  "success": true,
  "diff": "--- a//path/sample.txt\n+++ b//path/sample.txt\n@@ -1,3 +1,3 @@\n-alpha\n+ALPHA\n BETA\n gamma\n",
  "files_modified": ["/path/sample.txt"],
  "lint": {
    "/path/sample.txt": {
      "status": "skipped",
      "message": "No linter for .txt files"
    }
  }
}
```

Other possible keys from `PatchResult.to_dict()`:

- `files_created`
- `files_deleted`
- `lsp_diagnostics`
- `error`
- `_warning`
- `_hint`

No-match error sample:

```json
{
  "success": false,
  "error": "Could not find a match for old_string in the file",
  "_hint": "old_string not found. Use read_file to verify the current content, or search_files to locate the text."
}
```

Parameter error samples:

```json
{"error": "path required"}
{"error": "old_string and new_string required"}
{"error": "patch content required"}
{"error": "Unknown mode: <mode>"}
```

## `search_files`

Input args:

- `pattern: string` required by schema, handler uses `""` if omitted.
- `target: "content" | "files"` optional, default `"content"`. Handler also maps legacy `"grep"` to `"content"` and `"find"` to `"files"`.
- `path: string` optional, default `"."`.
- `file_glob: string` optional.
- `limit: integer` optional, default `50`.
- `offset: integer` optional, default `0`.
- `output_mode: "content" | "files_only" | "count"` optional, default `"content"`.
- `context: integer` optional, default `0`.
- `task_id` accepted via dispatch kwargs, default `"default"`.

Content-search success sample:

```json
{
  "total_count": 2,
  "matches": [
    {"path": "/path/sample.txt", "line": 1, "content": "alpha"},
    {"path": "/path/other.py", "line": 1, "content": "print(\"alpha\")"}
  ]
}
```

File-search success sample:

```json
{
  "total_count": 1,
  "files": ["/path/sample.txt"]
}
```

Count output sample:

```json
{
  "total_count": 2,
  "counts": {
    "/path/sample.txt": 1,
    "/path/other.py": 1
  }
}
```

Other possible keys from `SearchResult.to_dict()`:

- `truncated`
- `error`
- `_warning`

When `truncated` is true, the native handler appends a textual hint after the JSON string:

`[Hint: Results truncated. Use offset=<next> to see more, or narrow with a more specific pattern or file_glob.]`

The worker should preserve the native output string for this case too.
