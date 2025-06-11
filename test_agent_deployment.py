#!/usr/bin/env python3
"""
Test APTLabs agent deployment functionality
"""
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def test_agent_deployment():
    """Test APTLabs agent deployment"""
    try:
        print("Testing APTLabs agent deployment...")
        
        from aptlabs_agent_config import AptlabsAgentDeployer
        
        deployer = AptlabsAgentDeployer()
        print("✅ Successfully created AptlabsAgentDeployer instance")
        
        deployment_result = await deployer.deploy_aptlabs_agents()
        print(f"✅ Agent deployment result: {deployment_result}")
        
        status_result = await deployer.get_operation_status()
        print(f"✅ Operation status: {status_result}")
        
        return True
        
    except Exception as e:
        print(f"❌ Agent deployment test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_agent_deployment())
    if success:
        print("\n🎉 APTLabs agent deployment test completed successfully!")
    else:
        print("\n💥 APTLabs agent deployment test failed!")
        sys.exit(1)
