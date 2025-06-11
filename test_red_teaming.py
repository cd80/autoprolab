#!/usr/bin/env python3
"""
Test red teaming capabilities against discovered APTLabs hosts.
"""

import asyncio
import sys
import os
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

from agents.recon_agent import ReconAgent
from agents.initial_access_agent import InitialAccessAgent
from agents.web_hacking_agent import WebHackingAgent

DISCOVERED_HOSTS = [
    {"ip": "10.10.110.13", "ports": [53, 443], "services": ["DNS", "HTTPS"]},
    {"ip": "10.10.110.88", "ports": [80], "services": ["HTTP"]},
    {"ip": "10.10.110.231", "ports": [443], "services": ["HTTPS"]},
    {"ip": "10.10.110.242", "ports": [80], "services": ["HTTP"]}
]

async def test_recon_agent(host_info):
    """Test reconnaissance agent against a host."""
    print(f"\n🔍 Testing ReconAgent against {host_info['ip']}")
    
    recon_agent = ReconAgent()
    
    try:
        mock_services = []
        for i, port in enumerate(host_info['ports']):
            mock_services.append({
                'port': port,
                'service': host_info['services'][i] if i < len(host_info['services']) else 'unknown',
                'type': 'web' if port in [80, 443] else 'general'
            })
        
        result = await recon_agent.enumerate_target(
            target=host_info['ip'],
            services=mock_services,
            is_aptlabs=True
        )
        
        print(f"✅ Recon completed for {host_info['ip']}")
        print(f"   - Services enumerated: {len(mock_services)}")
        print(f"   - Result status: {result.get('status', 'unknown')}")
        
        flags_found = await recon_agent.check_for_flags_in_enumeration(result)
        if flags_found:
            print(f"🚩 Flags discovered during recon: {len(flags_found)}")
            return flags_found
        
        return result
        
    except Exception as e:
        print(f"❌ Recon failed for {host_info['ip']}: {e}")
        return None

async def test_initial_access_agent(host_info, recon_data):
    """Test initial access agent against a host."""
    print(f"\n🎯 Testing InitialAccessAgent against {host_info['ip']}")
    
    access_agent = InitialAccessAgent()
    
    try:
        result = await access_agent.attempt_initial_access(
            target=host_info['ip'],
            recon_data=recon_data or {}
        )
        
        print(f"✅ Initial access attempt completed for {host_info['ip']}")
        print(f"   - Overall status: {result.get('overall_status', 'unknown')}")
        print(f"   - Successful exploits: {len(result.get('successful_exploits', []))}")
        
        if result.get('successful_exploits'):
            print(f"🎉 Access gained to {host_info['ip']}!")
            return result
        
        return result
        
    except Exception as e:
        print(f"❌ Initial access failed for {host_info['ip']}: {e}")
        return None

async def test_web_hacking_agent(host_info):
    """Test web hacking agent against web services."""
    if not any(port in [80, 443] for port in host_info['ports']):
        print(f"⏭️  Skipping web testing for {host_info['ip']} - no web services")
        return None
    
    print(f"\n🌐 Testing WebHackingAgent against {host_info['ip']}")
    
    web_agent = WebHackingAgent()
    
    try:
        protocol = "https" if 443 in host_info['ports'] else "http"
        port = 443 if 443 in host_info['ports'] else 80
        target_url = f"{protocol}://{host_info['ip']}:{port}"
        
        result = await web_agent.comprehensive_web_assessment(target_url)
        
        print(f"✅ Web assessment completed for {target_url}")
        print(f"   - Assessment status: {result.get('status', 'unknown')}")
        print(f"   - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
        
        return result
        
    except Exception as e:
        print(f"❌ Web assessment failed for {host_info['ip']}: {e}")
        return None

async def submit_flag_if_found(flag):
    """Submit a flag using htb-operator."""
    print(f"\n🚩 Attempting to submit flag: {flag}")
    
    try:
        import subprocess
        result = subprocess.run([
            "htb-operator", "prolabs", "submit",
            "--name", "APTLabs",
            "--flag", flag
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ Flag submitted successfully: {flag}")
            print(f"   Response: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ Flag submission failed: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Flag submission error: {e}")
        return False

async def main():
    """Run comprehensive red teaming test against all discovered hosts."""
    print("🎯 APTLabs Red Teaming Capabilities Test")
    print("=" * 50)
    print(f"Testing against {len(DISCOVERED_HOSTS)} discovered hosts")
    
    all_results = {}
    flags_captured = []
    
    for host_info in DISCOVERED_HOSTS:
        print(f"\n{'='*20} {host_info['ip']} {'='*20}")
        
        recon_result = await test_recon_agent(host_info)
        all_results[host_info['ip']] = {'recon': recon_result}
        
        if isinstance(recon_result, list):  # Flags found
            flags_captured.extend(recon_result)
        
        access_result = await test_initial_access_agent(host_info, recon_result)
        all_results[host_info['ip']]['initial_access'] = access_result
        
        web_result = await test_web_hacking_agent(host_info)
        all_results[host_info['ip']]['web_testing'] = web_result
        
        await asyncio.sleep(1)
    
    if flags_captured:
        print(f"\n🚩 Found {len(flags_captured)} flags during testing!")
        for flag in flags_captured:
            await submit_flag_if_found(flag)
    
    print(f"\n{'='*50}")
    print("🏁 RED TEAMING TEST SUMMARY")
    print(f"{'='*50}")
    print(f"Hosts tested: {len(DISCOVERED_HOSTS)}")
    print(f"Flags captured: {len(flags_captured)}")
    
    successful_recon = sum(1 for r in all_results.values() if r.get('recon'))
    successful_access = sum(1 for r in all_results.values() if r.get('initial_access', {}).get('overall_status') == 'success')
    successful_web = sum(1 for r in all_results.values() if r.get('web_testing'))
    
    print(f"Successful reconnaissance: {successful_recon}/{len(DISCOVERED_HOSTS)}")
    print(f"Successful initial access: {successful_access}/{len(DISCOVERED_HOSTS)}")
    print(f"Successful web testing: {successful_web}/{len(DISCOVERED_HOSTS)}")
    
    if flags_captured:
        print(f"\n🎉 RED TEAMING SUCCESS - Captured {len(flags_captured)} flags!")
        return True
    else:
        print(f"\n⚠️  No flags captured, but agents are functional")
        return False

if __name__ == "__main__":
    asyncio.run(main())
