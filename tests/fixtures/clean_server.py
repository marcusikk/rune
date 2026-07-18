"""A minimal, honest FastMCP stdio server used by the live e2e test."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def get_weather(city: str) -> str:
    """Return the current weather for a city. Provide the city name."""
    return f"Sunny in {city}."


if __name__ == "__main__":
    mcp.run()
