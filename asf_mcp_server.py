#!/usr/bin/env python3
"""
ASF MCP Server - wraps tool calls through Agent Security Framework.
Register with Claude Code to intercept and monitor all tool calls.
"""

import asyncio
import os
import subprocess
import sys

# Add ASF to path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

import registry
from interceptor import hardened_interceptor


AGENT_ID = "claude-code-agent"


registry.add_or_update_agent(
    AGENT_ID,
    risk_level="medium",
    permissions=[
        "shell",
        "file_read",
        "file_write",
        "file_search",
        "code_edit",
        "read_db",
    ],
)
registry.reinstate_agent(AGENT_ID)

app = Server("asf-security-server")


def _intercept(tool_name: str, tool_input: str) -> tuple[bool, str, str]:
    """Run ASF interception and return (allowed, verdict, reason)."""
    result = hardened_interceptor(AGENT_ID, tool_name, tool_input)
    verdict, reason = result[0], result[1]
    return verdict == "ALLOW", verdict, reason


def _blocked_content(verdict: str, reason: str) -> list[types.TextContent]:
    label = "[ASF HITL]" if verdict == "HITL" else "[ASF BLOCKED]"
    return [
        types.TextContent(
            type="text",
            text=f"{label} {reason}\nVerdict: {verdict}",
        )
    ]


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="bash_secure",
            description="Execute a bash command. ASF security interceptor runs before execution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute",
                    }
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="read_file_secure",
            description="Read a file from the filesystem. ASF security interceptor runs before read.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to read",
                    }
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="write_file_secure",
            description="Write content to a file. ASF security interceptor runs before write.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to write",
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write",
                    },
                },
                "required": ["path", "content"],
            },
        ),
        types.Tool(
            name="search_files_secure",
            description="Search for files by name. ASF security interceptor runs before search.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query or filename pattern",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search in",
                        "default": ".",
                    },
                },
                "required": ["query"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "bash_secure":
        command = arguments.get("command", "")
        allowed, verdict, reason = _intercept("shell", command)
        if not allowed:
            return _blocked_content(verdict, reason)
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout or result.stderr or "(no output)"
            return [types.TextContent(type="text", text=output)]
        except Exception as exc:
            return [types.TextContent(type="text", text=f"Error: {exc}")]

    if name == "read_file_secure":
        path = arguments.get("path", "")
        allowed, verdict, reason = _intercept("file_read", path)
        if not allowed:
            return _blocked_content(verdict, reason)
        try:
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
            return [types.TextContent(type="text", text=content)]
        except Exception as exc:
            return [types.TextContent(type="text", text=f"Error: {exc}")]

    if name == "write_file_secure":
        path = arguments.get("path", "")
        content = arguments.get("content", "")
        tool_input = f"write to {path}: {content[:100]}"
        allowed, verdict, reason = _intercept("file_write", tool_input)
        if not allowed:
            return _blocked_content(verdict, reason)
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as file:
                file.write(content)
            return [types.TextContent(type="text", text=f"Written to {path}")]
        except Exception as exc:
            return [types.TextContent(type="text", text=f"Error: {exc}")]

    if name == "search_files_secure":
        query = arguments.get("query", "")
        search_path = arguments.get("path", ".")
        tool_input = f"search {query} in {search_path}"
        allowed, verdict, reason = _intercept("file_search", tool_input)
        if not allowed:
            return _blocked_content(verdict, reason)
        try:
            result = subprocess.run(
                ["find", search_path, "-name", f"*{query}*", "-type", "f"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or "(no results)"
            return [types.TextContent(type="text", text=output)]
        except Exception as exc:
            return [types.TextContent(type="text", text=f"Error: {exc}")]

    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
