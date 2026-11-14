"""Standalone test-only MCP server. Not part of the installed tool catalog."""
from fastmcp import FastMCP
from verify_limitations import page

mcp = FastMCP("bounded-response-test")


@mcp.tool()
def bounded_page(offset: int = 0) -> dict:
    rows = [{"property": "\U0001f600" * 100, "offset": i} for i in range(100)]
    if not 0 <= offset <= len(rows):
        raise ValueError("Invalid offset")
    return page(rows, offset, 7, 4096)


if __name__ == "__main__":
    mcp.run()
