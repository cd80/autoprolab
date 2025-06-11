#!/usr/bin/env python3
"""
Test HTB API integration for APTLabs
"""
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def test_htb_api():
    """Test HTB API integration"""
    try:
        print("Testing HTB API integration...")
        
        htb_api_key = os.environ.get('HTB_API_KEY')
        if htb_api_key:
            print(f"✅ HTB_API_KEY is available (length: {len(htb_api_key)})")
        else:
            print("❌ HTB_API_KEY not found in environment")
            return False
        
        try:
            from agents.htb_aptlabs_agent import HtbAptlabsAgent
            print("✅ Successfully imported HtbAptlabsAgent")
            
            agent = HtbAptlabsAgent()
            print("✅ Successfully created HtbAptlabsAgent instance")
            
            result = await agent.get_lab_details()
            print(f"✅ APTLabs details retrieved: {result}")
            
            return True
            
        except ImportError as e:
            print(f"❌ Failed to import HtbAptlabsAgent: {e}")
            return False
        except Exception as e:
            print(f"❌ HTB API test failed: {e}")
            return False
            
    except Exception as e:
        print(f"❌ General test failure: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_htb_api())
    if success:
        print("\n🎉 HTB API integration test completed successfully!")
    else:
        print("\n💥 HTB API integration test failed!")
        sys.exit(1)
