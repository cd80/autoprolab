"""
Test script for all autoprolab agents and components.
"""

import asyncio
import sys
import os
import json
from pathlib import Path

sys.path.append(str(Path(__file__).parent / "agents"))

from agents.team_leader_agent import TeamLeaderAgent
from agents.network_scanner_agent import NetworkScannerAgent
from agents.recon_agent import ReconAgent
from agents.initial_access_agent import InitialAccessAgent
from agents.web_hacking_agent import WebHackingAgent
from agents.tool_selector_agent import ToolSelectorAgent
from agents.mcp_server_manager import McpServerManager
from agents.zep_integration import ZepKnowledgeAgent

async def test_tool_selector_agent():
    """Test the tool selector agent."""
    print("🔧 Testing Tool Selector Agent...")
    
    try:
        agent = ToolSelectorAgent()
        
        result = await agent.select_tool("I need to scan a network for live hosts", {"task": "network_scanning"})
        print(f"Tool selection result: {result}")
        
        help_result = await agent._get_tool_help("nmap")
        print(f"Tool usage help: {help_result}")
        
        return {"success": True, "agent": "tool_selector"}
        
    except Exception as e:
        print(f"❌ Tool Selector Agent test failed: {e}")
        return {"success": False, "agent": "tool_selector", "error": str(e)}

async def test_network_scanner_agent():
    """Test the network scanner agent."""
    print("🌐 Testing Network Scanner Agent...")
    
    try:
        agent = NetworkScannerAgent()
        
        result = await agent.discover_network("127.0.0.0/24")
        print(f"Network discovery result: {result}")
        
        scan_result = await agent.quick_scan("127.0.0.1")
        print(f"Quick scan result: {scan_result}")
        
        return {"success": True, "agent": "network_scanner"}
        
    except Exception as e:
        print(f"❌ Network Scanner Agent test failed: {e}")
        return {"success": False, "agent": "network_scanner", "error": str(e)}

async def test_recon_agent():
    """Test the reconnaissance agent."""
    print("🔍 Testing Reconnaissance Agent...")
    
    try:
        agent = ReconAgent()
        
        services = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}]
        result = await agent.enumerate_target("127.0.0.1", services)
        print(f"Service enumeration result: {result}")
        
        web_result = await agent.web_enumeration("127.0.0.1", 80)
        print(f"Web enumeration result: {web_result}")
        
        return {"success": True, "agent": "recon_agent"}
        
    except Exception as e:
        print(f"❌ Reconnaissance Agent test failed: {e}")
        return {"success": False, "agent": "recon_agent", "error": str(e)}

async def test_initial_access_agent():
    """Test the initial access agent."""
    print("🚪 Testing Initial Access Agent...")
    
    try:
        agent = InitialAccessAgent()
        
        vuln_data = {
            "target": "127.0.0.1",
            "service": "http",
            "port": 80,
            "vulnerability": "test_vuln"
        }
        recon_data = {"services": [{"port": 80, "service": "http"}], "vulnerabilities": []}
        result = await agent.attempt_initial_access(vuln_data, recon_data)
        print(f"Exploitation attempt result: {result}")
        
        cred_result = await agent.brute_force_service("127.0.0.1", "ssh", 22)
        print(f"Credential testing result: {cred_result}")
        
        return {"success": True, "agent": "initial_access"}
        
    except Exception as e:
        print(f"❌ Initial Access Agent test failed: {e}")
        return {"success": False, "agent": "initial_access", "error": str(e)}

async def test_web_hacking_agent():
    """Test the web hacking agent."""
    print("🌐 Testing Web Hacking Agent...")
    
    try:
        agent = WebHackingAgent()
        
        result = await agent.comprehensive_web_assessment("127.0.0.1", 80)
        print(f"Web assessment result: {result}")
        
        sql_result = await agent.sql_injection_testing("http://127.0.0.1", ["id", "user"])
        print(f"SQL injection test result: {sql_result}")
        
        return {"success": True, "agent": "web_hacking"}
        
    except Exception as e:
        print(f"❌ Web Hacking Agent test failed: {e}")
        return {"success": False, "agent": "web_hacking", "error": str(e)}

async def test_mcp_server_manager():
    """Test the MCP server manager."""
    print("📦 Testing MCP Server Manager...")
    
    try:
        agent = McpServerManager()
        
        result = await agent.discover_mcp_servers()
        print(f"MCP server discovery result: {result}")
        
        setup_result = await agent.setup_recommended_servers()
        print(f"Recommended servers setup result: {setup_result}")
        
        return {"success": True, "agent": "mcp_server_manager"}
        
    except Exception as e:
        print(f"❌ MCP Server Manager test failed: {e}")
        return {"success": False, "agent": "mcp_server_manager", "error": str(e)}

async def test_zep_integration():
    """Test the Zep knowledge base integration."""
    print("🧠 Testing Zep Knowledge Base Integration...")
    
    try:
        agent = ZepKnowledgeAgent()
        
        init_result = await agent.initialize_knowledge_base()
        print(f"Knowledge base initialization result: {init_result}")
        
        target_data = {
            "hostname": "test-target",
            "ipAddress": "127.0.0.1",
            "operatingSystem": "Linux",
            "status": "target"
        }
        store_result = await agent.store_target_intelligence(target_data)
        print(f"Target intelligence storage result: {store_result}")
        
        retrieve_result = await agent.retrieve_target_intelligence("test-target")
        print(f"Target intelligence retrieval result: {retrieve_result}")
        
        return {"success": True, "agent": "zep_integration"}
        
    except Exception as e:
        print(f"❌ Zep Integration test failed: {e}")
        return {"success": False, "agent": "zep_integration", "error": str(e)}

async def test_team_leader_agent():
    """Test the team leader agent."""
    print("👑 Testing Team Leader Agent...")
    
    try:
        agent = TeamLeaderAgent()
        
        lab_info = {
            "id": "test_lab",
            "name": "Test Lab",
            "network": "10.10.110.0/24"
        }
        objectives = ["Gain initial access", "Escalate privileges", "Capture flags"]
        
        result = await agent.start_operation(lab_info, objectives)
        print(f"Operation start result: {result}")
        
        coord_result = await agent.coordinate_agents(
            "Perform network reconnaissance", 
            {"lab_info": lab_info}
        )
        print(f"Agent coordination result: {coord_result}")
        
        return {"success": True, "agent": "team_leader"}
        
    except Exception as e:
        print(f"❌ Team Leader Agent test failed: {e}")
        return {"success": False, "agent": "team_leader", "error": str(e)}

async def test_agent_integration():
    """Test integration between agents."""
    print("🔗 Testing Agent Integration...")
    
    try:
        team_leader = TeamLeaderAgent()
        zep_agent = ZepKnowledgeAgent()
        
        await zep_agent.initialize_knowledge_base()
        
        lab_info = {
            "id": "integration_test",
            "name": "Integration Test Lab",
            "network": "10.10.110.0/24"
        }
        objectives = ["Test agent integration"]
        
        operation_result = await team_leader.start_operation(lab_info, objectives)
        
        await zep_agent.store_operation_data(operation_result)
        
        coord_result = await team_leader.coordinate_agents(
            "Perform comprehensive security assessment",
            {"lab_info": lab_info, "phase": "reconnaissance"}
        )
        
        print(f"Integration test result: {coord_result}")
        
        return {"success": True, "test": "agent_integration"}
        
    except Exception as e:
        print(f"❌ Agent Integration test failed: {e}")
        return {"success": False, "test": "agent_integration", "error": str(e)}

async def main():
    """Run all tests."""
    print("🚀 Starting Autoprolab Agent Testing Suite...")
    print("=" * 60)
    
    test_results = []
    
    test_functions = [
        test_tool_selector_agent,
        test_network_scanner_agent,
        test_recon_agent,
        test_initial_access_agent,
        test_web_hacking_agent,
        test_mcp_server_manager,
        test_zep_integration,
        test_team_leader_agent,
        test_agent_integration
    ]
    
    for test_func in test_functions:
        try:
            result = await test_func()
            test_results.append(result)
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed with exception: {e}")
            test_results.append({
                "success": False, 
                "test": test_func.__name__, 
                "error": str(e)
            })
        
        print("-" * 40)
    
    print("\n📊 Test Results Summary:")
    print("=" * 60)
    
    successful_tests = [r for r in test_results if r.get("success")]
    failed_tests = [r for r in test_results if not r.get("success")]
    
    print(f"✅ Successful tests: {len(successful_tests)}")
    print(f"❌ Failed tests: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            agent_name = test.get("agent", test.get("test", "unknown"))
            error = test.get("error", "Unknown error")
            print(f"  - {agent_name}: {error}")
    
    print(f"\n🎯 Overall success rate: {len(successful_tests)}/{len(test_results)} ({len(successful_tests)/len(test_results)*100:.1f}%)")
    
    return test_results

if __name__ == "__main__":
    asyncio.run(main())
