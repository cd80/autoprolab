#!/usr/bin/env python3
"""
Execute autonomous flag capture operation on APTLabs Pro Lab
"""
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def main():
    """Execute flag capture operation"""
    try:
        print("🚀 Starting autonomous flag capture operation on APTLabs...")
        
        from aptlabs_agent_config import AptlabsAgentDeployer
        
        deployer = AptlabsAgentDeployer()
        
        print("📋 Deploying agents...")
        deploy_result = await deployer.deploy_aptlabs_agents()
        print(f"Deployment result: {deploy_result}")
        
        if deploy_result['success']:
            print("🎯 Executing flag capture operation...")
            capture_result = await deployer.execute_flag_capture()
            print(f"Flag capture result: {capture_result}")
            
            if capture_result.get('success'):
                print("✅ Flag capture operation completed successfully!")
                return True
            else:
                print(f"❌ Flag capture operation failed: {capture_result.get('error', 'Unknown error')}")
                return False
        else:
            print(f"❌ Agent deployment failed: {deploy_result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Flag capture operation failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    if success:
        print("\n🎉 APTLabs flag capture operation completed!")
    else:
        print("\n💥 APTLabs flag capture operation failed!")
        sys.exit(1)
