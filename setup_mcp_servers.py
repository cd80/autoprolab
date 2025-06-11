#!/usr/bin/env python3

import asyncio
import sys
import os
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from agents.mcp_server_manager import McpServerManager

async def setup_mcp_servers():
    """Set up real MCP servers to replace mock configurations."""
    print("Setting up real MCP servers...")
    
    try:
        manager = McpServerManager()
        
        print("Discovering available MCP servers...")
        discovery_result = await manager.discover_mcp_servers()
        
        servers_list = discovery_result.get("servers", [])
        print(f"Found {len(servers_list)} MCP servers:")
        for server in servers_list:
            name = server.get("name", "Unknown")
            description = server.get("description", "No description")
            print(f"  - {name}: {description}")
        
        print("Setting up recommended servers...")
        await manager.setup_recommended_servers()
        
        print("✅ MCP servers configured successfully!")
        print("Configuration saved to ~/.mcp/config.json")
        
        config_path = Path.home() / ".mcp" / "config.json"
        if config_path.exists():
            print(f"✅ MCP configuration file created at {config_path}")
        else:
            print("⚠️  MCP configuration file not found")
            
    except Exception as e:
        print(f"❌ Error setting up MCP servers: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = asyncio.run(setup_mcp_servers())
    sys.exit(0 if success else 1)
