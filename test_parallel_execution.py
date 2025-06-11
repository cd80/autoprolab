#!/usr/bin/env python3
"""
Test parallel execution capabilities of the autoprolab system.

This script tests the parallel execution implementation by running reconnaissance
against multiple APTLabs hosts simultaneously and verifying that no entry point
assumptions remain in the system.
"""

import asyncio
import sys
import os
import time
from typing import List, Dict, Any

sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

from agents.recon_agent import ReconAgent
from agents.network_scanner_agent import NetworkScannerAgent
from agents.initial_access_agent import InitialAccessAgent
from agents.parallel_utils import (
    execute_parallel_with_timeout,
    execute_parallel_hosts,
    handle_parallel_exceptions
)

TEST_HOSTS = [
    "10.10.110.13",  # Known host with services
    "10.10.110.88",  # Additional test host
    "10.10.110.231", # Another test host
    "10.10.110.242"  # Final test host
]

async def test_parallel_reconnaissance():
    """Test parallel reconnaissance against multiple hosts."""
    print("🔍 Testing Parallel Reconnaissance")
    print("=" * 50)
    
    recon_agent = ReconAgent()
    start_time = time.time()
    
    print(f"Starting parallel reconnaissance on {len(TEST_HOSTS)} hosts:")
    for host in TEST_HOSTS:
        print(f"  - {host}")
    
    tasks = []
    for host in TEST_HOSTS:
        task = recon_agent.enumerate_target(target=host, is_aptlabs=True)
        tasks.append(task)
    
    try:
        results = await execute_parallel_with_timeout(tasks, timeout=120)
        execution_time = time.time() - start_time
        
        print(f"\n⏱️  Parallel execution completed in {execution_time:.2f} seconds")
        
        processed_results = handle_parallel_exceptions(results, TEST_HOSTS)
        
        successful_hosts = [host for host, result in processed_results.items() if result["success"]]
        failed_hosts = [host for host, result in processed_results.items() if not result["success"]]
        
        print(f"\n📊 Results Summary:")
        print(f"  ✅ Successful: {len(successful_hosts)}/{len(TEST_HOSTS)} hosts")
        print(f"  ❌ Failed: {len(failed_hosts)}/{len(TEST_HOSTS)} hosts")
        
        if successful_hosts:
            print(f"\n✅ Successfully processed hosts:")
            for host in successful_hosts:
                result = processed_results[host]["result"]
                potential_flags = result.get("potential_flags", [])
                print(f"  - {host}: {len(potential_flags)} potential flags found")
        
        if failed_hosts:
            print(f"\n❌ Failed hosts:")
            for host in failed_hosts:
                error = processed_results[host]["error"]
                print(f"  - {host}: {error}")
        
        return processed_results
        
    except Exception as e:
        print(f"❌ Parallel reconnaissance test failed: {e}")
        return None

async def test_parallel_network_scanning():
    """Test parallel network scanning capabilities."""
    print("\n🌐 Testing Parallel Network Scanning")
    print("=" * 50)
    
    scanner_agent = NetworkScannerAgent()
    start_time = time.time()
    
    results = await execute_parallel_hosts(
        agent_method=scanner_agent.quick_scan_single,
        hosts=TEST_HOSTS,
        method_kwargs={"is_aptlabs": True},
        timeout=180,
        max_concurrent=4
    )
    
    execution_time = time.time() - start_time
    print(f"⏱️  Parallel network scanning completed in {execution_time:.2f} seconds")
    
    successful_scans = [host for host, result in results.items() if not result.get("error")]
    failed_scans = [host for host, result in results.items() if result.get("error")]
    
    print(f"\n📊 Network Scanning Results:")
    print(f"  ✅ Successful scans: {len(successful_scans)}/{len(TEST_HOSTS)} hosts")
    print(f"  ❌ Failed scans: {len(failed_scans)}/{len(TEST_HOSTS)} hosts")
    
    if successful_scans:
        print(f"\n✅ Successfully scanned hosts:")
        for host in successful_scans:
            result = results[host]
            open_ports = result.get("open_ports", [])
            print(f"  - {host}: {len(open_ports)} open ports detected")
    
    return results

async def test_parallel_initial_access():
    """Test parallel initial access attempts."""
    print("\n⚔️ Testing Parallel Initial Access")
    print("=" * 50)
    
    access_agent = InitialAccessAgent()
    start_time = time.time()
    
    results = await execute_parallel_hosts(
        agent_method=access_agent.attempt_initial_access,
        hosts=TEST_HOSTS,
        method_kwargs={"recon_data": {}},
        timeout=240,
        max_concurrent=3
    )
    
    execution_time = time.time() - start_time
    print(f"⏱️  Parallel initial access completed in {execution_time:.2f} seconds")
    
    successful_access = [host for host, result in results.items() 
                        if not result.get("error") and result.get("success")]
    failed_access = [host for host, result in results.items() 
                    if result.get("error") or not result.get("success")]
    
    print(f"\n📊 Initial Access Results:")
    print(f"  ✅ Successful access: {len(successful_access)}/{len(TEST_HOSTS)} hosts")
    print(f"  ❌ Failed access: {len(failed_access)}/{len(TEST_HOSTS)} hosts")
    
    if successful_access:
        print(f"\n✅ Successfully accessed hosts:")
        for host in successful_access:
            result = results[host]
            print(f"  - {host}: Access method - {result.get('access_method', 'unknown')}")
    
    return results

async def test_no_entry_point_assumptions():
    """Verify that no entry point assumptions remain in the system."""
    print("\n🔍 Testing for Entry Point Assumptions")
    print("=" * 50)
    
    recon_agent = ReconAgent()
    
    import random
    shuffled_hosts = TEST_HOSTS.copy()
    random.shuffle(shuffled_hosts)
    
    print(f"Testing with shuffled host order: {shuffled_hosts}")
    
    tasks = []
    for host in shuffled_hosts:
        task = recon_agent.enumerate_target(target=host, is_aptlabs=True)
        tasks.append(task)
    
    results = await execute_parallel_with_timeout(tasks, timeout=120)
    processed_results = handle_parallel_exceptions(results, shuffled_hosts)
    
    all_equal_treatment = True
    for host, result in processed_results.items():
        if result["success"]:
            result_data = result["result"]
            if "entry_point" in str(result_data).lower():
                print(f"❌ Entry point assumption found for host {host}")
                all_equal_treatment = False
            elif "priority" in str(result_data).lower() and "high" in str(result_data).lower():
                if "apt-fw01" in str(result_data).lower() or "10.10.110.1" in str(result_data):
                    print(f"❌ Hardcoded entry point priority found for host {host}")
                    all_equal_treatment = False
    
    if all_equal_treatment:
        print("✅ No entry point assumptions detected - all hosts treated equally")
    else:
        print("❌ Entry point assumptions still present in system")
    
    return all_equal_treatment

async def test_error_handling():
    """Test that errors in one host don't affect others."""
    print("\n🛡️ Testing Error Handling")
    print("=" * 50)
    
    test_hosts_with_invalid = TEST_HOSTS + ["192.168.999.999", "invalid.host.test"]
    
    recon_agent = ReconAgent()
    tasks = []
    for host in test_hosts_with_invalid:
        task = recon_agent.enumerate_target(target=host, is_aptlabs=True)
        tasks.append(task)
    
    results = await execute_parallel_with_timeout(tasks, timeout=120)
    processed_results = handle_parallel_exceptions(results, test_hosts_with_invalid)
    
    valid_successful = sum(1 for host in TEST_HOSTS 
                          if processed_results[host]["success"])
    invalid_failed = sum(1 for host in ["192.168.999.999", "invalid.host.test"] 
                        if not processed_results[host]["success"])
    
    print(f"📊 Error Handling Results:")
    print(f"  ✅ Valid hosts successful: {valid_successful}/{len(TEST_HOSTS)}")
    print(f"  ❌ Invalid hosts failed (expected): {invalid_failed}/2")
    
    error_isolation_success = (valid_successful > 0 and invalid_failed == 2)
    
    if error_isolation_success:
        print("✅ Error isolation working - invalid hosts don't affect valid ones")
    else:
        print("❌ Error isolation failed - errors affecting other operations")
    
    return error_isolation_success

async def main():
    """Run all parallel execution tests."""
    print("🚀 APTLabs Parallel Execution Test Suite")
    print("=" * 60)
    print(f"Testing parallel execution against {len(TEST_HOSTS)} hosts")
    print("This test verifies that the system can handle multiple targets")
    print("simultaneously without entry point assumptions.\n")
    
    test_results = {}
    
    test_results["reconnaissance"] = await test_parallel_reconnaissance()
    test_results["network_scanning"] = await test_parallel_network_scanning()
    test_results["initial_access"] = await test_parallel_initial_access()
    test_results["no_entry_point"] = await test_no_entry_point_assumptions()
    test_results["error_handling"] = await test_error_handling()
    
    print("\n" + "=" * 60)
    print("🏁 TEST SUITE SUMMARY")
    print("=" * 60)
    
    passed_tests = 0
    total_tests = len(test_results)
    
    for test_name, result in test_results.items():
        if result:
            print(f"✅ {test_name.replace('_', ' ').title()}: PASSED")
            passed_tests += 1
        else:
            print(f"❌ {test_name.replace('_', ' ').title()}: FAILED")
    
    print(f"\nOverall Result: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All parallel execution tests PASSED!")
        print("✅ System ready for parallel APTLabs operations")
        return True
    else:
        print("⚠️  Some tests failed - review implementation")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
