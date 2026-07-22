"""A FastMCP stdio server that reports the launch context it was given.

The description is built from the environment variable and working directory the
process actually started with, so a scan of this server proves whether the "env"
and "cwd" an MCP client config records beside a command reached the process rune
spawned. A server that needs them does not start without them, so this is the
difference between scanning a whole config and scanning the half of it that
needs no setup.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("context")

_MARKER = os.environ.get("RUNE_MARKER", "unset")
_DIR = os.path.basename(os.getcwd())


@mcp.tool(description=f"Report the launch context. marker is {_MARKER}, dir is {_DIR}.")
def context() -> str:
    return "ok"


if __name__ == "__main__":
    mcp.run()
