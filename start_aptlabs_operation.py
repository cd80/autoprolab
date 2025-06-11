#!/usr/bin/env python3
"""
Start APTLabs Autonomous Operation
Executes the complete attack chain using the multi-agent system.
"""

import asyncio
import sys
import logging
from agents.aptlabs_operation import AptlabsOperationAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def start_aptlabs_operation():
    """Start the autonomous APTLabs operation."""
    print('🚀 Starting APTLabs Autonomous Operation...')
    print('=' * 60)
    
    try:
        print('📋 Initializing AptlabsOperationAgent...')
        operation_agent = AptlabsOperationAgent()
        
        print('⚔️ Executing full autonomous attack chain...')
        print('Phases: Network Discovery → Enumeration → Initial Access → Flag Hunting')
        print('=' * 60)
        
        result = await operation_agent.execute_full_attack_chain()
        
        print('=' * 60)
        print('📊 APTLabs Operation Results:')
        print(f'Status: {result.get("status", "unknown")}')
        print(f'Current Phase: {result.get("current_phase", "unknown")}')
        print(f'Discovered hosts: {len(result.get("discovered_hosts", []))}')
        print(f'Compromised hosts: {len(result.get("compromised_hosts", []))}')
        print(f'Captured flags: {len(result.get("captured_flags", []))}')
        
        if result.get('discovered_hosts'):
            print('\n🔍 Discovered Hosts:')
            for host in result['discovered_hosts']:
                print(f'  - {host}')
        
        if result.get('compromised_hosts'):
            print('\n💥 Compromised Hosts:')
            for host in result['compromised_hosts']:
                print(f'  - {host}')
        
        if result.get('captured_flags'):
            print('\n🏆 Captured Flags:')
            for flag in result['captured_flags']:
                print(f'  - {flag}')
        else:
            print('\n⚠️ No flags captured yet - operation may still be in progress')
        
        print('=' * 60)
        return result
        
    except Exception as e:
        print(f'❌ Operation failed with error: {str(e)}')
        logging.exception("APTLabs operation failed")
        return {"status": "failed", "error": str(e)}

if __name__ == "__main__":
    print("APTLabs Autonomous Red Team Operation")
    print("====================================")
    
    result = asyncio.run(start_aptlabs_operation())
    
    if result.get("status") == "failed":
        sys.exit(1)
    else:
        print("✅ Operation completed successfully")
        sys.exit(0)
