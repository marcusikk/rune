"""A FastMCP stdio server that stalls before it will answer anything.

Used by the live timeout test. The delay is read from the environment so one
fixture serves both sides of the check: the run whose budget is too small to
reach the handshake, and the control that gives it the time it asks for.
"""

import os
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("slow")


@mcp.tool()
def ping() -> str:
    """Return a fixed greeting. Takes no arguments."""
    return "pong"


if __name__ == "__main__":
    time.sleep(float(os.environ.get("RUNE_TEST_DELAY", "0")))
    mcp.run()
