"""
Simple Operation Launcher - Streamlined interface for autonomous red team operations.
Replaces complex agent coordination with direct AI-powered execution.
"""

import asyncio
import logging
from agents.autonomous_redteam_agent import AutonomousRedTeamAgent

async def launch_autonomous_operation(lab_name: str = "APTLabs", target_flags: int = 3):
    """
    Launch completely autonomous red team operation.
    
    Args:
        lab_name: HTB Pro Lab to target
        target_flags: Number of flags to capture
        
    Returns:
        Operation results
    """
    print(f"🚀 Launching autonomous operation on {lab_name}")
    print(f"🎯 Target: Capture {target_flags} flags")
    print("🤖 Using AI-powered autonomous agent")
    
    agent = AutonomousRedTeamAgent()
    
    try:
        print("\n📋 Starting operation...")
        start_result = await agent.start_operation(
            lab_name=lab_name,
            objectives=[f"Capture {target_flags} flags autonomously", "Document attack paths", "Demonstrate AI reasoning"]
        )
        
        if not start_result["success"]:
            print(f"❌ Failed to start operation: {start_result.get('error', 'Unknown error')}")
            return start_result
        
        print("✅ Operation started successfully")
        print(f"📊 Status: {start_result['status']}")
        
        print("\n🤖 Beginning autonomous execution...")
        print("💭 AI agent will now determine optimal approach and execute autonomously")
        
        execution_result = await agent.execute_autonomous_operation()
        
        print("\n" + "="*60)
        print("🏁 OPERATION COMPLETE")
        print("="*60)
        
        if execution_result["success"]:
            print(f"✅ Operation completed successfully")
            print(f"🚩 Flags captured: {execution_result['flags_captured']}")
            print(f"🎯 Assets discovered: {len(execution_result['discovered_assets'])}")
            
            if execution_result["captured_flags"]:
                print("\n🏆 Captured Flags:")
                for i, flag_info in enumerate(execution_result["captured_flags"], 1):
                    print(f"  {i}. {flag_info['flag']} (from {flag_info.get('source', 'unknown')})")
            
            if execution_result["discovered_assets"]:
                print(f"\n🌐 Discovered Assets: {', '.join(execution_result['discovered_assets'])}")
            
            print(f"\n📝 Operation Notes:")
            for note in execution_result.get("operation_notes", []):
                print(f"  • {note}")
        else:
            print(f"❌ Operation failed: {execution_result.get('error', 'Unknown error')}")
            if execution_result.get("partial_results"):
                print("📊 Partial results available")
        
        return execution_result
        
    except Exception as e:
        print(f"💥 Operation crashed: {str(e)}")
        return {"success": False, "error": str(e)}

async def quick_status_check():
    """Quick status check of current operation."""
    agent = AutonomousRedTeamAgent()
    status = await agent.get_operation_status()
    
    print("📊 Current Operation Status:")
    print(f"  Status: {status['status']}")
    print(f"  Runtime: {status['runtime']}")
    print(f"  Lab: {status['current_lab']}")
    print(f"  VPN: {'Connected' if status['vpn_connected'] else 'Disconnected'}")
    print(f"  Assets: {status['discovered_assets']}")
    print(f"  Flags: {status['captured_flags']}")
    
    return status

async def main():
    """Main function for testing autonomous operations."""
    print("🤖 Autonomous Red Team Agent - AI-Powered HTB Pro Lab Operations")
    print("=" * 70)
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    try:
        result = await launch_autonomous_operation("APTLabs", 3)
        
        if result["success"]:
            print("\n🎉 Mission accomplished! AI agent successfully completed autonomous operation.")
        else:
            print(f"\n⚠️ Operation encountered issues: {result.get('error', 'Unknown')}")
            
    except KeyboardInterrupt:
        print("\n⏹️ Operation interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
