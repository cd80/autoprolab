"""
Network Scanner Agent - Specialized agent for network discovery and scanning.
"""

import asyncio
import subprocess
import json
import ipaddress
from typing import Dict, List, Optional, Any
from .base_agent import Agent

class NetworkScannerAgent(Agent):
    """
    Specialized agent for network discovery and initial reconnaissance.
    Focuses on discovering live hosts and basic network topology.
    """
    
    def __init__(self):
        super().__init__(name="network_scanner")
        self.description = "Performs network discovery and host enumeration"
        self.instructions = """
            You are the network scanner agent responsible for:
            1. Discovering live hosts in target networks
            2. Performing initial network reconnaissance
            3. Identifying network topology and segments
            4. Providing target prioritization recommendations
            5. Starting with the default HTB Pro Lab network 10.10.110.0/24
            """
        
        self.default_network = "10.10.110.0/24"
        self.discovered_hosts = []
        self.scan_results = {}
        
        self.aptlabs_config = {
            "expected_machines": 18,
            "machine_types": ["FreeBSD", "Windows"],
            "domain_environment": True,
            "priority_services": ["ssh", "http", "https", "smb", "rdp", "ldap", "kerberos"],
            "common_windows_ports": [135, 139, 445, 389, 636, 88, 3389, 5985, 5986],
            "common_freebsd_ports": [22, 80, 443, 21, 25, 53, 110, 143]
        }
    
    async def configure(self, config: dict):
        """Configure the agent with specific parameters"""
        if 'network' in config:
            self.default_network = config['network']
        if 'target_machines' in config:
            self.aptlabs_config["expected_machines"] = config['target_machines']
        
        self.logger.info(f"NetworkScannerAgent configured for network {self.default_network}")
        return {"success": True, "configured": True}
    
    async def discover_network(self, network: str = None) -> Dict:
        """
        Discover live hosts in the specified network.
        
        Args:
            network: Network CIDR to scan (defaults to 10.10.110.0/24)
            
        Returns:
            Dictionary containing discovered hosts and scan results
        """
        target_network = network or self.default_network
        is_aptlabs = target_network == "10.10.110.0/24"
        
        print(f"🔍 Starting network discovery for {target_network}")
        if is_aptlabs:
            print(f"🎯 APTLabs mode: Expecting {self.aptlabs_config['expected_machines']} machines")
        
        try:
            ipaddress.ip_network(target_network, strict=False)
        except ValueError:
            return {
                "error": f"Invalid network format: {target_network}",
                "status": "failed"
            }
        
        discovery_results = await self._perform_host_discovery(target_network, is_aptlabs)
        
        analysis = await self._analyze_discovered_hosts(discovery_results, is_aptlabs)
        
        self.discovered_hosts = discovery_results.get("live_hosts", [])
        self.scan_results[target_network] = discovery_results
        
        return {
            "network": target_network,
            "discovery_results": discovery_results,
            "analysis": analysis,
            "status": "completed",
            "recommendations": analysis.get("recommendations", []),
            "aptlabs_specific": analysis.get("aptlabs_analysis", {}) if is_aptlabs else None
        }
    
    async def quick_scan_single(self, target: str, is_aptlabs: bool = False) -> Dict:
        """
        Perform a quick scan of a single target (wrapper for parallel execution).
        
        Args:
            target: IP address or hostname to scan
            is_aptlabs: Whether this is an APTLabs target
            
        Returns:
            Quick scan results for the single target
        """
        result = await self._quick_host_scan(target)
        return {
            "scan_type": "quick_scan_single",
            "target": target,
            "result": result,
            "is_aptlabs": is_aptlabs
        }

    async def quick_scan(self, targets: List[str]) -> Dict:
        """
        Perform a quick scan of specific targets.
        
        Args:
            targets: List of IP addresses or hostnames to scan
            
        Returns:
            Quick scan results
        """
        print(f"⚡ Performing quick scan of {len(targets)} targets")
        
        results = {}
        for target in targets:
            try:
                result = await self._quick_host_scan(target)
                results[target] = result
            except Exception as e:
                results[target] = {"error": str(e), "status": "failed"}
        
        return {
            "scan_type": "quick_scan",
            "targets": targets,
            "results": results,
            "summary": await self._summarize_quick_scan(results)
        }
    
    async def _perform_host_discovery(self, network: str, is_aptlabs: bool = False) -> Dict:
        """Perform host discovery using multiple techniques."""
        results = {
            "network": network,
            "live_hosts": [],
            "scan_methods": [],
            "timing": {},
            "aptlabs_specific": {} if is_aptlabs else None
        }
        
        ping_results = await self._nmap_ping_sweep(network)
        results["scan_methods"].append("nmap_ping_sweep")
        results["live_hosts"].extend(ping_results.get("hosts", []))
        
        if self._is_local_network(network):
            arp_results = await self._arp_scan(network)
            results["scan_methods"].append("arp_scan")
            for host in arp_results.get("hosts", []):
                if host not in results["live_hosts"]:
                    results["live_hosts"].append(host)
        
        if is_aptlabs:
            aptlabs_syn_results = await self._aptlabs_tcp_discovery(network)
            results["scan_methods"].append("aptlabs_tcp_discovery")
            for host in aptlabs_syn_results.get("hosts", []):
                if host not in results["live_hosts"]:
                    results["live_hosts"].append(host)
            
            results["aptlabs_specific"]["tcp_discovery"] = aptlabs_syn_results
            
            udp_results = await self._aptlabs_udp_discovery(network)
            results["scan_methods"].append("aptlabs_udp_discovery")
            for host in udp_results.get("hosts", []):
                if host not in results["live_hosts"]:
                    results["live_hosts"].append(host)
            
            results["aptlabs_specific"]["udp_discovery"] = udp_results
        
        # Fallback TCP SYN discovery if few hosts found
        elif len(results["live_hosts"]) < 5:
            syn_results = await self._tcp_syn_discovery(network)
            results["scan_methods"].append("tcp_syn_discovery")
            for host in syn_results.get("hosts", []):
                if host not in results["live_hosts"]:
                    results["live_hosts"].append(host)
        
        results["live_hosts"] = sorted(list(set(results["live_hosts"])))
        
        if is_aptlabs:
            results["aptlabs_specific"]["discovery_validation"] = await self._validate_aptlabs_discovery(results["live_hosts"])
        
        return results
    
    async def _nmap_ping_sweep(self, network: str) -> Dict:
        """Perform nmap ping sweep."""
        try:
            cmd = ["nmap", "-sn", "-T4", "--min-rate", "1000", network]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_ping_output(stdout.decode())
                return {
                    "method": "nmap_ping_sweep",
                    "hosts": hosts,
                    "status": "success"
                }
            else:
                return {
                    "method": "nmap_ping_sweep",
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "method": "nmap_ping_sweep",
                "error": str(e),
                "status": "failed"
            }
    
    async def _arp_scan(self, network: str) -> Dict:
        """Perform ARP scan for local network discovery."""
        try:
            cmd = ["nmap", "-PR", "-sn", network]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_ping_output(stdout.decode())
                return {
                    "method": "arp_scan",
                    "hosts": hosts,
                    "status": "success"
                }
            else:
                return {
                    "method": "arp_scan",
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "method": "arp_scan",
                "error": str(e),
                "status": "failed"
            }
    
    async def _tcp_syn_discovery(self, network: str) -> Dict:
        """Perform TCP SYN scan on common ports for host discovery."""
        try:
            common_ports = "22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6000,8000,8080"
            
            cmd = ["nmap", "-sS", "-T4", "-p", common_ports, "--open", network]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_scan_output(stdout.decode())
                return {
                    "method": "tcp_syn_discovery",
                    "hosts": hosts,
                    "status": "success"
                }
            else:
                return {
                    "method": "tcp_syn_discovery",
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "method": "tcp_syn_discovery",
                "error": str(e),
                "status": "failed"
            }
    
    async def _quick_host_scan(self, target: str) -> Dict:
        """Perform a quick scan of a single host."""
        try:
            cmd = ["nmap", "-T4", "--top-ports", "100", target]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                result = self._parse_nmap_port_scan(stdout.decode())
                return {
                    "target": target,
                    "scan_type": "quick_port_scan",
                    "result": result,
                    "status": "success"
                }
            else:
                return {
                    "target": target,
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "target": target,
                "error": str(e),
                "status": "failed"
            }
    
    def _parse_nmap_ping_output(self, output: str) -> List[str]:
        """Parse nmap ping sweep output to extract live hosts."""
        hosts = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        hosts.append(part)
                        break
                    elif '(' in part and ')' in part:
                        ip = part.strip('()')
                        if self._is_valid_ip(ip):
                            hosts.append(ip)
                            break
        
        return hosts
    
    def _parse_nmap_scan_output(self, output: str) -> List[str]:
        """Parse nmap scan output to extract hosts with open ports."""
        hosts = []
        lines = output.split('\n')
        
        current_host = None
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        current_host = part
                        break
                    elif '(' in part and ')' in part:
                        ip = part.strip('()')
                        if self._is_valid_ip(ip):
                            current_host = ip
                            break
            elif current_host and '/tcp' in line and 'open' in line:
                if current_host not in hosts:
                    hosts.append(current_host)
        
        return hosts
    
    def _parse_nmap_port_scan(self, output: str) -> Dict:
        """Parse nmap port scan output."""
        result = {
            "open_ports": [],
            "filtered_ports": [],
            "closed_ports": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line:
                parts = line.split()
                if len(parts) >= 2:
                    port = parts[0]
                    state = parts[1]
                    
                    if state == 'open':
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        result["open_ports"].append({
                            "port": port,
                            "service": service
                        })
                    elif state == 'filtered':
                        result["filtered_ports"].append(port)
            elif 'closed ports' in line.lower():
                import re
                match = re.search(r'(\d+) closed ports', line)
                if match:
                    result["closed_ports"] = int(match.group(1))
        
        return result
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _is_local_network(self, network: str) -> bool:
        """Check if network is a local/private network."""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return net.is_private
        except ValueError:
            return False
    
    async def _analyze_discovered_hosts(self, discovery_results: Dict, is_aptlabs: bool = False) -> Dict:
        """Analyze discovered hosts and provide recommendations."""
        hosts = discovery_results.get("live_hosts", [])
        
        analysis = {
            "total_hosts": len(hosts),
            "host_distribution": {},
            "recommendations": [],
            "priority_targets": []
        }
        
        if len(hosts) == 0:
            analysis["recommendations"].append("No live hosts discovered. Consider expanding scan scope or checking network connectivity.")
            return analysis
        
        # Host distribution analysis
        for host in hosts:
            try:
                ip = ipaddress.ip_address(host)
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
                analysis["host_distribution"][subnet] = analysis["host_distribution"].get(subnet, 0) + 1
            except ValueError:
                continue
        
        if is_aptlabs:
            analysis["aptlabs_analysis"] = await self._analyze_aptlabs_hosts(hosts, discovery_results)
            
            infrastructure_candidates = [host for host in hosts if host.endswith('.1') or host.endswith('.10')]
            domain_controllers = []
            windows_hosts = []
            freebsd_hosts = []
            
            for host in hosts:
                last_octet = int(host.split('.')[-1])
                if last_octet in [10, 11, 12]:  # Likely domain controllers
                    domain_controllers.append(host)
                elif last_octet < 50:  # Likely infrastructure
                    analysis["priority_targets"].append(host)
                else:  # All other hosts including .1 addresses
                    analysis["priority_targets"].append(host)
            
            analysis["priority_targets"].extend(domain_controllers)
            
            remaining_hosts = [h for h in hosts if h not in analysis["priority_targets"]]
            analysis["priority_targets"].extend(remaining_hosts[:10 - len(analysis["priority_targets"])])
            
            analysis["recommendations"].extend([
                f"APTLabs Discovery: Found {len(hosts)}/{self.aptlabs_config['expected_machines']} expected machines",
                "Target all discovered hosts in parallel for comprehensive coverage",
                "Identify Windows domain controllers for AD enumeration",
                "Prepare for mixed FreeBSD/Windows environment",
                "Plan for domain privilege escalation attacks"
            ])
            
        else:
            if len(hosts) <= 5:
                analysis["recommendations"].append("Small number of hosts discovered. Perform detailed scanning on all targets.")
                analysis["priority_targets"] = hosts
            else:
                analysis["recommendations"].append("Multiple hosts discovered. Prioritize based on common services and accessibility.")
                priority_ips = [host for host in hosts if host.split('.')[-1] in ['1', '10', '100', '101', '200', '254']]
                analysis["priority_targets"] = priority_ips[:5] if priority_ips else hosts[:5]
        
        analysis["recommendations"].extend([
            "Proceed with detailed port scanning on priority targets",
            "Consider service enumeration and vulnerability assessment"
        ])
        
        return analysis
    
    async def _summarize_quick_scan(self, results: Dict) -> Dict:
        """Summarize quick scan results."""
        summary = {
            "total_targets": len(results),
            "successful_scans": 0,
            "failed_scans": 0,
            "total_open_ports": 0,
            "interesting_services": []
        }
        
        for target, result in results.items():
            if result.get("status") == "success":
                summary["successful_scans"] += 1
                scan_result = result.get("result", {})
                open_ports = scan_result.get("open_ports", [])
                summary["total_open_ports"] += len(open_ports)
                
                for port_info in open_ports:
                    service = port_info.get("service", "").lower()
                    if any(interesting in service for interesting in ["http", "ssh", "ftp", "smb", "rdp", "sql"]):
                        summary["interesting_services"].append({
                            "target": target,
                            "port": port_info.get("port"),
                            "service": service
                        })
            else:
                summary["failed_scans"] += 1
        
        return summary
    
    async def _aptlabs_tcp_discovery(self, network: str) -> Dict:
        """Perform APTLabs-specific TCP discovery targeting Windows and FreeBSD services."""
        try:
            windows_ports = ",".join(map(str, self.aptlabs_config["common_windows_ports"]))
            freebsd_ports = ",".join(map(str, self.aptlabs_config["common_freebsd_ports"]))
            all_ports = f"{windows_ports},{freebsd_ports}"
            
            cmd = ["nmap", "-sS", "-T4", "-p", all_ports, "--open", network]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_scan_output(stdout.decode())
                service_info = self._parse_aptlabs_services(stdout.decode())
                
                return {
                    "method": "aptlabs_tcp_discovery",
                    "hosts": hosts,
                    "service_info": service_info,
                    "status": "success"
                }
            else:
                return {
                    "method": "aptlabs_tcp_discovery",
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "method": "aptlabs_tcp_discovery",
                "error": str(e),
                "status": "failed"
            }
    
    async def _aptlabs_udp_discovery(self, network: str) -> Dict:
        """Perform UDP discovery for domain services (DNS, LDAP, Kerberos)."""
        try:
            udp_ports = "53,88,123,135,137,138,389,464"
            
            cmd = ["nmap", "-sU", "-T4", "-p", udp_ports, "--open", network]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_udp_output(stdout.decode())
                
                return {
                    "method": "aptlabs_udp_discovery",
                    "hosts": hosts,
                    "status": "success"
                }
            else:
                return {
                    "method": "aptlabs_udp_discovery",
                    "error": stderr.decode(),
                    "status": "failed"
                }
                
        except Exception as e:
            return {
                "method": "aptlabs_udp_discovery",
                "error": str(e),
                "status": "failed"
            }
    
    async def _validate_aptlabs_discovery(self, hosts: List[str]) -> Dict:
        """Validate APTLabs discovery results against expected configuration."""
        validation = {
            "expected_machines": self.aptlabs_config["expected_machines"],
            "discovered_machines": len(hosts),
            "discovery_completeness": (len(hosts) / self.aptlabs_config["expected_machines"]) * 100,
            "missing_machines": max(0, self.aptlabs_config["expected_machines"] - len(hosts)),
            "all_hosts_discovered": hosts,
            "infrastructure_candidates": []
        }
        
        for host in hosts:
            last_octet = int(host.split('.')[-1])
            if last_octet == 1:
                validation["infrastructure_candidates"].append({"ip": host, "type": "gateway", "confidence": "high"})
            elif last_octet == 10:
                validation["infrastructure_candidates"].append({"ip": host, "type": "infrastructure", "confidence": "medium"})
        
        return validation
    
    async def _analyze_aptlabs_hosts(self, hosts: List[str], discovery_results: Dict) -> Dict:
        """Perform APTLabs-specific host analysis."""
        analysis = {
            "machine_categorization": {
                "infrastructure": [],
                "domain_controllers": [],
                "workstations": [],
                "servers": [],
                "unknown": []
            },
            "infrastructure_analysis": {},
            "domain_environment_indicators": [],
            "next_steps": []
        }
        
        for host in hosts:
            last_octet = int(host.split('.')[-1])
            
            if last_octet == 1:
                analysis["machine_categorization"]["infrastructure"].append(host)
                analysis["infrastructure_analysis"][host] = {
                    "type": "firewall_gateway",
                    "confidence": "medium",
                    "notes": "Potential gateway/firewall host"
                }
            elif last_octet in range(10, 20):
                analysis["machine_categorization"]["domain_controllers"].append(host)
            elif last_octet in range(100, 200):
                analysis["machine_categorization"]["workstations"].append(host)
            elif last_octet in range(200, 250):
                analysis["machine_categorization"]["servers"].append(host)
            else:
                analysis["machine_categorization"]["unknown"].append(host)
        
        if discovery_results.get("aptlabs_specific", {}).get("udp_discovery", {}).get("hosts"):
            analysis["domain_environment_indicators"].append("UDP domain services detected")
        
        analysis["next_steps"] = [
            "Perform detailed port scanning on all discovered hosts in parallel",
            "Enumerate SMB shares on Windows hosts",
            "Check for anonymous LDAP access on domain controllers",
            "Identify services on all infrastructure hosts"
        ]
        
        return analysis
    
    def _parse_aptlabs_services(self, nmap_output: str) -> Dict:
        """Parse nmap output to identify APTLabs-specific services."""
        services = {
            "windows_services": [],
            "freebsd_services": [],
            "domain_services": [],
            "web_services": []
        }
        
        lines = nmap_output.split('\n')
        current_host = None
        
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        current_host = part
                        break
            elif current_host and '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    port_num = int(port)
                    service_info = {"host": current_host, "port": port_num, "service": service}
                    
                    if port_num in self.aptlabs_config["common_windows_ports"]:
                        services["windows_services"].append(service_info)
                    elif port_num in self.aptlabs_config["common_freebsd_ports"]:
                        services["freebsd_services"].append(service_info)
                    
                    if port_num in [389, 636, 88, 135, 445]:
                        services["domain_services"].append(service_info)
                    elif port_num in [80, 443, 8080, 8443]:
                        services["web_services"].append(service_info)
        
        return services
    
    def _parse_nmap_udp_output(self, output: str) -> List[str]:
        """Parse nmap UDP scan output to extract hosts with open UDP ports."""
        hosts = []
        lines = output.split('\n')
        
        current_host = None
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        current_host = part
                        break
            elif current_host and '/udp' in line and ('open' in line or 'open|filtered' in line):
                if current_host not in hosts:
                    hosts.append(current_host)
        
        return hosts
