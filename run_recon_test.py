#!/usr/bin/env python3
"""
Focused reconnaissance test against the first APTLabs host with proper tool integration.
"""

import asyncio
import sys
import os
import subprocess
import re

sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

from agents.recon_agent import ReconAgent

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else None

if not TARGET_HOST:
    print("Usage: python run_recon_test.py <target_host>")
    print("Example: python run_recon_test.py 10.10.110.13")
    sys.exit(1)
TARGET_SERVICES = [
    {"port": 53, "service": "DNS", "type": "general"},
    {"port": 443, "service": "HTTPS", "type": "web"}
]

async def run_focused_recon():
    """Run focused reconnaissance against the first APTLabs host."""
    print(f"🎯 APTLabs Focused Reconnaissance Test")
    print(f"Target: {TARGET_HOST}")
    print(f"Services: {[s['service'] for s in TARGET_SERVICES]}")
    print("=" * 50)
    
    recon_agent = ReconAgent()
    
    try:
        print(f"\n🔍 Starting detailed enumeration of {TARGET_HOST}")
        result = await recon_agent.enumerate_target(
            target=TARGET_HOST,
            services=TARGET_SERVICES,
            is_aptlabs=True
        )
        
        print(f"\n✅ Reconnaissance completed!")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Services enumerated: {len(result.get('services', []))}")
        
        print(f"\n🚩 Checking for flags in enumeration results...")
        flags_found = await recon_agent.check_for_flags_in_enumeration(result)
        
        if flags_found:
            print(f"🎉 Found {len(flags_found)} potential flags!")
            for i, flag in enumerate(flags_found, 1):
                if isinstance(flag, dict):
                    print(f"  {i}. Type: {flag.get('type', 'unknown')}")
                    print(f"     Location: {flag.get('location', 'unknown')}")
                    print(f"     Confidence: {flag.get('confidence', 'unknown')}")
                else:
                    print(f"  {i}. {flag}")
        else:
            print("No flags found during reconnaissance.")
        
        print(f"\n📤 Attempting to submit discovered information to HTB...")
        try:
            htb_result = await recon_agent.submit_discovered_info_to_htb(result)
            print(f"HTB submission result: {htb_result.get('status', 'unknown')}")
        except Exception as e:
            print(f"HTB submission failed: {e}")
        
        return result, flags_found
        
    except Exception as e:
        print(f"❌ Reconnaissance failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None

async def test_manual_flag_search():
    """Manually search for actual HTB flags on the target."""
    print(f"\n🔍 Manual flag search on {TARGET_HOST}")
    
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        url = f"https://{TARGET_HOST}"
        print(f"Testing {url}...")
        
        response = requests.get(url, verify=False, timeout=10)
        content = response.text
        
        flag_pattern = r'HTB\{[^}]+\}'
        flags = re.findall(flag_pattern, content)
        
        if flags:
            print(f"🚩 Found {len(flags)} HTB flags in web content!")
            for flag in flags:
                print(f"  Flag: {flag}")
                await submit_htb_flag(flag)
            return flags
        else:
            print("No HTB flags found in web content")
            print(f"Content preview: {content[:500]}...")
            
    except Exception as e:
        print(f"Manual web flag search failed: {e}")
    
    return []

async def submit_htb_flag(flag):
    """Submit a flag to HTB using htb-operator."""
    print(f"\n🚩 Submitting flag: {flag}")
    
    try:
        result = subprocess.run([
            "htb-operator", "prolabs", "submit",
            "--name", "APTLabs",
            "--flag", flag
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ Flag submitted successfully!")
            print(f"Response: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ Flag submission failed: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Flag submission error: {e}")
        return False

async def main():
    """Main reconnaissance test."""
    recon_result, agent_flags = await run_focused_recon()
    
    manual_flags = await test_manual_flag_search()
    
    print(f"\n{'='*50}")
    print("🏁 RECONNAISSANCE TEST SUMMARY")
    print(f"{'='*50}")
    print(f"Target: {TARGET_HOST}")
    print(f"Agent flags found: {len(agent_flags) if agent_flags else 0}")
    print(f"Manual flags found: {len(manual_flags)}")
    
    total_flags = len(manual_flags)
    if total_flags > 0:
        print(f"🎉 SUCCESS - Found {total_flags} actual HTB flags!")
        return True
    else:
        print("⚠️  No actual HTB flags captured, but reconnaissance completed")
        return False

if __name__ == "__main__":
    asyncio.run(main())
