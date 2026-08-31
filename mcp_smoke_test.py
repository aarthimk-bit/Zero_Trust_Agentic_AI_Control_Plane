import asyncio

from mcp import Client
from mcp.server import MCPServer

mcp = MCPServer("Zero Trust MCP Pilot")


@mcp.tool()
def health_check() -> str:
    """Return a simple MCP connectivity confirmation."""
    return "MCP connection successful"


async def main():
    async with Client(mcp, raise_exceptions=True) as client:
        result = await client.call_tool("health_check", {})
        print("PASS: MCP in-memory client/server connection successful")
        print("Protocol version:", client.protocol_version)
        print("Tool result:", result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
