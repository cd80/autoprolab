"""
Reconnaissance Agent - Specialized agent for detailed target reconnaissance.
"""

import asyncio
import subprocess
import json
import re
from typing import Dict, List, Optional, Any
from .base_agent import Agent

class ReconAgent(Agent):
    """
    Specialized agent for detailed reconnaissance and information gathering.
    Focuses on service enumeration, version detection, and vulnerability identification.
    """
    
    def __init__(self):
        super().__init__(
            name="recon_agent",
            description="Performs detailed reconnaissance and service enumeration",
            instructions="""
            You are the reconnaissance agent responsible for:
            1. Detailed service enumeration on discovered targets
            2. Version detection and banner grabbing
            3. Directory and subdomain enumeration for web services
            4. SMB, DNS, and other protocol-specific enumeration
            5. Gathering detailed target intelligence for exploitation planning
            """
        )
        
        self.recon_results = {}
        self.enumeration_tools = {
            'web': ['gobuster', 'ffuf', 'dirb', 'nikto', 'whatweb'],
            'smb': ['enum4linux', 'smbclient', 'rpcclient', 'crackmapexec'],
            'dns': ['dnsrecon', 'fierce', 'dnsmap'],
            'general': ['nmap', 'masscan', 'rustscan'],
            'ldap': ['ldapsearch', 'ldapdomaindump'],
            'kerberos': ['kerbrute', 'impacket-GetNPUsers'],
            'freebsd': ['nmap', 'gobuster', 'nikto']
        }
        
        self.aptlabs_config = {
            "network": "10.10.110.0/24",
            "entry_point": "APT-FW01",
            "domain_environment": True,
            "machine_types": ["FreeBSD", "Windows"],
            "common_ad_ports": [88, 135, 139, 389, 445, 464, 636, 3268, 3269],
            "freebsd_services": ["ssh", "http", "https", "ftp", "smtp", "dns"],
            "windows_services": ["smb", "ldap", "kerberos", "rdp", "winrm"],
            "domain_enumeration_priority": ["ldap", "smb", "kerberos", "dns"]
        }
    
    async def enumerate_target(self, target: str, services: List[Dict] = None, is_aptlabs: bool = False) -> Dict:
        """
        Perform comprehensive enumeration of a target.
        
        Args:
            target: IP address or hostname to enumerate
            services: List of known services from initial scanning
            is_aptlabs: Whether this is APTLabs-specific enumeration
            
        Returns:
            Detailed enumeration results
        """
        print(f"🔍 Starting detailed enumeration of {target}")
        if is_aptlabs:
            print(f"🎯 APTLabs mode: Enhanced enumeration for mixed FreeBSD/Windows environment")
        
        results = {
            "target": target,
            "enumeration_results": {},
            "vulnerabilities": [],
            "recommendations": [],
            "next_steps": [],
            "aptlabs_specific": {} if is_aptlabs else None
        }
        
        if not services:
            services = await self._discover_services(target, is_aptlabs)
            results["discovered_services"] = services
        
        # APTLabs-specific enumeration
        if is_aptlabs:
            aptlabs_results = await self._aptlabs_enumeration(target, services)
            results["aptlabs_specific"] = aptlabs_results
        
        for service in services:
            service_type = self._categorize_service(service, is_aptlabs)
            if service_type:
                enum_result = await self._enumerate_service(target, service, service_type, is_aptlabs)
                results["enumeration_results"][f"{service.get('port')}_{service_type}"] = enum_result
        
        analysis = await self._analyze_enumeration_results(results, is_aptlabs)
        results.update(analysis)
        
        if is_aptlabs:
            htb_submission = await self.submit_discovered_info_to_htb(target, results)
            results["htb_submission"] = htb_submission
            
            potential_flags = await self.check_for_flags_in_enumeration(results)
            results["potential_flags"] = potential_flags
            
            if potential_flags:
                results["recommendations"].append(f"Found {len(potential_flags)} potential flag locations")
                results["next_steps"].append("Investigate potential flag locations for actual flags")
        
        self.recon_results[target] = results
        
        return results
    
    async def web_enumeration(self, target: str, port: int = 80, ssl: bool = False, is_aptlabs: bool = False) -> Dict:
        """
        Perform detailed web application enumeration.
        
        Args:
            target: Target IP or hostname
            port: Web service port
            ssl: Whether to use HTTPS
            
        Returns:
            Web enumeration results
        """
        protocol = "https" if ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        print(f"🌐 Starting web enumeration of {base_url}")
        
        results = {
            "target": base_url,
            "web_server": {},
            "directories": [],
            "files": [],
            "technologies": [],
            "vulnerabilities": []
        }
        
        server_info = await self._identify_web_server(base_url)
        results["web_server"] = server_info
        
        directories = await self._enumerate_directories(base_url)
        results["directories"] = directories
        
        technologies = await self._detect_technologies(base_url)
        results["technologies"] = technologies
        
        vulns = await self._scan_web_vulnerabilities(base_url)
        results["vulnerabilities"] = vulns
        
        return results
    
    async def smb_enumeration(self, target: str, is_aptlabs: bool = False) -> Dict:
        """
        Perform SMB enumeration.
        
        Args:
            target: Target IP address
            
        Returns:
            SMB enumeration results
        """
        print(f"📁 Starting SMB enumeration of {target}")
        
        results = {
            "target": target,
            "smb_version": "",
            "shares": [],
            "users": [],
            "groups": [],
            "policies": {},
            "vulnerabilities": []
        }
        
        version_info = await self._detect_smb_version(target)
        results["smb_version"] = version_info
        
        shares = await self._enumerate_smb_shares(target)
        results["shares"] = shares
        
        users = await self._enumerate_smb_users(target)
        results["users"] = users
        
        policies = await self._get_smb_policies(target)
        results["policies"] = policies
        
        return results
    
    async def _discover_services(self, target: str, is_aptlabs: bool = False) -> List[Dict]:
        """Discover services on target using nmap."""
        try:
            if is_aptlabs:
                ad_ports = ",".join(map(str, self.aptlabs_config["common_ad_ports"]))
                cmd = ["nmap", "-sV", "-sC", "-p", f"1-1000,{ad_ports}", target]
            else:
                cmd = ["nmap", "-sV", "-sC", "--top-ports", "1000", target]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_nmap_services(stdout.decode())
            else:
                print(f"Service discovery failed: {stderr.decode()}")
                return []
                
        except Exception as e:
            print(f"Error during service discovery: {e}")
            return []
    
    def _categorize_service(self, service: Dict, is_aptlabs: bool = False) -> Optional[str]:
        """Categorize service for appropriate enumeration."""
        port = service.get('port', '')
        service_name = service.get('service', '').lower()
        port_num = int(str(port).split('/')[0]) if port else 0
        
        if any(web in service_name for web in ['http', 'https', 'web']):
            return 'web'
        elif any(smb in service_name for smb in ['smb', 'netbios', 'microsoft-ds']):
            return 'smb'
        elif any(dns in service_name for dns in ['dns', 'domain']):
            return 'dns'
        elif any(ssh in service_name for ssh in ['ssh', 'openssh']):
            return 'ssh'
        elif any(ftp in service_name for ftp in ['ftp', 'ftps']):
            return 'ftp'
        elif any(mail in service_name for mail in ['smtp', 'pop3', 'imap']):
            return 'mail'
        
        if is_aptlabs:
            if port_num == 389 or port_num == 636 or 'ldap' in service_name:
                return 'ldap'
            elif port_num == 88 or 'kerberos' in service_name:
                return 'kerberos'
            elif port_num == 3389 or 'rdp' in service_name:
                return 'rdp'
            elif port_num in [5985, 5986] or 'winrm' in service_name:
                return 'winrm'
        
        return 'general'
    
    async def _enumerate_service(self, target: str, service: Dict, service_type: str, is_aptlabs: bool = False) -> Dict:
        """Enumerate specific service type."""
        if service_type == 'web':
            port_value = service.get('port', '80')
            if isinstance(port_value, int):
                port = port_value
            else:
                port = int(str(port_value).split('/')[0])
            ssl = 'ssl' in service.get('service', '').lower() or port == 443
            return await self.web_enumeration(target, port, ssl, is_aptlabs)
        elif service_type == 'smb':
            return await self.smb_enumeration(target, is_aptlabs)
        elif service_type == 'ldap':
            return await self._enumerate_ldap(target, service)
        elif service_type == 'kerberos':
            return await self._enumerate_kerberos(target, service)
        elif service_type == 'rdp':
            return await self._enumerate_rdp(target, service)
        elif service_type == 'winrm':
            return await self._enumerate_winrm(target, service)
        elif service_type == 'ssh':
            return await self._enumerate_ssh(target, service, is_aptlabs)
        elif service_type == 'ftp':
            return await self._enumerate_ftp(target, service)
        else:
            return await self._general_enumeration(target, service)
    
    async def _identify_web_server(self, url: str) -> Dict:
        """Identify web server and basic information."""
        try:
            cmd = ["curl", "-I", "-s", "--connect-timeout", "10", url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                headers = stdout.decode()
                return self._parse_http_headers(headers)
            else:
                return {"error": "Failed to connect"}
                
        except Exception as e:
            return {"error": str(e)}
    
    async def _enumerate_directories(self, url: str) -> List[str]:
        """Enumerate directories using gobuster."""
        try:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_gobuster_output(stdout.decode())
            else:
                return await self._basic_directory_check(url)
                
        except Exception as e:
            print(f"Directory enumeration error: {e}")
            return []
    
    async def _detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies using whatweb."""
        try:
            cmd = ["whatweb", "--color=never", "--no-errors", url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_whatweb_output(stdout.decode())
            else:
                return []
                
        except Exception as e:
            print(f"Technology detection error: {e}")
            return []
    
    async def _scan_web_vulnerabilities(self, url: str) -> List[Dict]:
        """Basic web vulnerability scanning with nikto."""
        try:
            cmd = ["nikto", "-h", url, "-Format", "txt", "-nointeractive"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_nikto_output(stdout.decode())
            else:
                return []
                
        except Exception as e:
            print(f"Web vulnerability scanning error: {e}")
            return []
    
    async def _enumerate_smb_shares(self, target: str) -> List[Dict]:
        """Enumerate SMB shares."""
        try:
            cmd = ["smbclient", "-L", target, "-N"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_smbclient_shares(stdout.decode())
            else:
                return []
                
        except Exception as e:
            print(f"SMB share enumeration error: {e}")
            return []
    
    def _parse_nmap_services(self, output: str) -> List[Dict]:
        """Parse nmap service detection output."""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    
                    services.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'version': version
                    })
        
        return services
    
    def _parse_http_headers(self, headers: str) -> Dict:
        """Parse HTTP response headers."""
        result = {}
        lines = headers.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.strip().lower()] = value.strip()
        
        return result
    
    def _parse_gobuster_output(self, output: str) -> List[str]:
        """Parse gobuster directory enumeration output."""
        directories = []
        lines = output.split('\n')
        
        for line in lines:
            if line.startswith('/'):
                path = line.split()[0]
                directories.append(path)
        
        return directories
    
    async def _basic_directory_check(self, url: str) -> List[str]:
        """Basic directory existence check."""
        common_dirs = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/backup', '/config']
        found_dirs = []
        
        for directory in common_dirs:
            try:
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"{url}{directory}"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    status_code = stdout.decode().strip()
                    if status_code in ['200', '301', '302', '403']:
                        found_dirs.append(directory)
                        
            except Exception:
                continue
        
        return found_dirs
    
    async def _analyze_enumeration_results(self, results: Dict, is_aptlabs: bool = False) -> Dict:
        """Analyze enumeration results and generate recommendations."""
        analysis = {
            "risk_assessment": "medium",
            "attack_vectors": [],
            "recommendations": [],
            "next_steps": []
        }
        
        for key, enum_result in results.get("enumeration_results", {}).items():
            if "web" in key:
                if enum_result.get("directories"):
                    analysis["attack_vectors"].append("Directory traversal and file disclosure")
                if enum_result.get("vulnerabilities"):
                    analysis["attack_vectors"].extend([v.get("description", "") for v in enum_result["vulnerabilities"]])
            
            elif "smb" in key:
                shares = enum_result.get("shares", [])
                if any("write" in str(share).lower() for share in shares):
                    analysis["attack_vectors"].append("SMB share write access")
                if enum_result.get("users"):
                    analysis["attack_vectors"].append("User enumeration via SMB")
        
        if is_aptlabs and results.get("aptlabs_specific"):
            aptlabs_data = results["aptlabs_specific"]
            machine_type = aptlabs_data.get("machine_type_detection", {}).get("type")
            
            if machine_type == "Windows":
                analysis["attack_vectors"].append("Active Directory exploitation")
                analysis["recommendations"].append("Focus on domain enumeration and Kerberoasting")
                analysis["next_steps"].append("Attempt domain privilege escalation")
            elif machine_type == "FreeBSD":
                analysis["attack_vectors"].append("FreeBSD system exploitation")
                analysis["recommendations"].append("Focus on web services and SSH access")
                analysis["next_steps"].append("Look for FreeBSD-specific vulnerabilities")
            
            if aptlabs_data.get("entry_point_analysis"):
                analysis["recommendations"].append("This appears to be the entry point (APT-FW01)")
                analysis["next_steps"].append("Prioritize gaining initial access through this machine")
        
        if analysis["attack_vectors"]:
            analysis["risk_assessment"] = "high"
            analysis["recommendations"].append("Prioritize this target for exploitation")
            analysis["next_steps"].append("Proceed with vulnerability exploitation")
        else:
            analysis["recommendations"].append("Continue with deeper enumeration")
            analysis["next_steps"].append("Try alternative enumeration techniques")
        
        return analysis
    
    def _parse_whatweb_output(self, output: str) -> List[str]:
        """Parse whatweb technology detection output."""
        technologies = []
        if '[' in output and ']' in output:
            tech_section = output.split('[')[1].split(']')[0]
            technologies = [tech.strip() for tech in tech_section.split(',')]
        return technologies
    
    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse nikto vulnerability scan output."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+ ' in line and any(vuln_word in line.lower() for vuln_word in ['vulnerability', 'exploit', 'disclosure']):
                vulnerabilities.append({
                    "description": line.strip(),
                    "severity": "medium"
                })
        
        return vulnerabilities
    
    def _parse_smbclient_shares(self, output: str) -> List[Dict]:
        """Parse smbclient share enumeration output."""
        shares = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Disk' in line or 'IPC' in line:
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({
                        "name": parts[0],
                        "type": parts[1] if len(parts) > 1 else "Unknown",
                        "comment": ' '.join(parts[2:]) if len(parts) > 2 else ""
                    })
        
        return shares
    
    async def _enumerate_ssh(self, target: str, service: Dict, is_aptlabs: bool = False) -> Dict:
        """Enumerate SSH service."""
        recommendations = ["Check for weak credentials", "Look for SSH key files"]
        
        if is_aptlabs:
            recommendations.extend([
                "Test common FreeBSD default credentials",
                "Check for SSH key-based authentication",
                "Look for SSH configuration misconfigurations"
            ])
        
        return {
            "service": "ssh",
            "version": service.get("version", ""),
            "recommendations": recommendations
        }
    
    async def _enumerate_ftp(self, target: str, service: Dict) -> Dict:
        """Enumerate FTP service."""
        return {
            "service": "ftp",
            "version": service.get("version", ""),
            "recommendations": ["Check for anonymous access", "Test for weak credentials"]
        }
    
    async def _general_enumeration(self, target: str, service: Dict) -> Dict:
        """General service enumeration."""
        return {
            "service": service.get("service", "unknown"),
            "version": service.get("version", ""),
            "recommendations": ["Research service-specific vulnerabilities"]
        }
    
    async def _detect_smb_version(self, target: str) -> str:
        """Detect SMB version."""
        try:
            cmd = ["nmap", "-p", "445", "--script", "smb-protocols", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                for line in output.split('\n'):
                    if 'SMB' in line and ('2.' in line or '3.' in line):
                        return line.strip()
            
            return "Unknown"
            
        except Exception as e:
            return f"Error: {e}"
    
    async def _enumerate_smb_users(self, target: str) -> List[str]:
        """Enumerate SMB users."""
        try:
            cmd = ["enum4linux", "-U", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_enum4linux_users(stdout.decode())
            
            return []
            
        except Exception as e:
            return []
    
    async def _get_smb_policies(self, target: str) -> Dict:
        """Get SMB password policies."""
        try:
            cmd = ["enum4linux", "-P", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_enum4linux_policies(stdout.decode())
            
            return {}
            
        except Exception as e:
            return {}
    
    def _parse_enum4linux_users(self, output: str) -> List[str]:
        """Parse enum4linux user enumeration output."""
        users = []
        lines = output.split('\n')
        
        for line in lines:
            if 'user:' in line.lower():
                parts = line.split()
                for part in parts:
                    if not part.startswith('[') and not part.endswith(']') and len(part) > 2:
                        users.append(part)
        
        return list(set(users))  # Remove duplicates
    
    def _parse_enum4linux_policies(self, output: str) -> Dict:
        """Parse enum4linux password policy output."""
        policies = {}
        lines = output.split('\n')
        
        for line in lines:
            if 'password' in line.lower() and ':' in line:
                key_value = line.split(':', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip()
                    policies[key] = value
        
        return policies
    
    async def _aptlabs_enumeration(self, target: str, services: List[Dict]) -> Dict:
        """
        Perform APTLabs-specific enumeration techniques.
        
        Args:
            target: Target IP address
            services: Discovered services
            
        Returns:
            APTLabs-specific enumeration results
        """
        results = {
            "machine_type_detection": {},
            "domain_enumeration": {},
            "entry_point_analysis": {},
            "privilege_escalation_vectors": []
        }
        
        results["machine_type_detection"] = await self._detect_machine_type(target, services)
        
        # If Windows machine, perform domain enumeration
        if results["machine_type_detection"].get("type") == "Windows":
            results["domain_enumeration"] = await self._enumerate_active_directory(target, services)
        
        if target.endswith('.1'):
            results["entry_point_analysis"] = await self._analyze_entry_point(target, services)
        
        results["privilege_escalation_vectors"] = await self._identify_privesc_vectors(target, services, results["machine_type_detection"])
        
        return results
    
    async def _detect_machine_type(self, target: str, services: List[Dict]) -> Dict:
        """
        Detect if target is FreeBSD or Windows based on services and OS fingerprinting.
        """
        detection = {
            "type": "Unknown",
            "confidence": "low",
            "indicators": []
        }
        
        windows_indicators = []
        freebsd_indicators = []
        
        for service in services:
            service_name = service.get('service', '').lower()
            port = service.get('port', '')
            
            if any(win_svc in service_name for win_svc in ['microsoft-ds', 'netbios', 'ldap', 'kerberos']):
                windows_indicators.append(f"Windows service: {service_name} on port {port}")
            elif any(bsd_svc in service_name for bsd_svc in ['openssh', 'apache', 'nginx']):
                freebsd_indicators.append(f"FreeBSD service: {service_name} on port {port}")
        
        try:
            cmd = ["nmap", "-O", "--osscan-guess", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode().lower()
                if 'windows' in output:
                    windows_indicators.append("OS fingerprinting indicates Windows")
                elif 'freebsd' in output or 'bsd' in output:
                    freebsd_indicators.append("OS fingerprinting indicates FreeBSD")
        except Exception:
            pass
        
        if len(windows_indicators) > len(freebsd_indicators):
            detection["type"] = "Windows"
            detection["confidence"] = "high" if len(windows_indicators) >= 2 else "medium"
            detection["indicators"] = windows_indicators
        elif len(freebsd_indicators) > 0:
            detection["type"] = "FreeBSD"
            detection["confidence"] = "high" if len(freebsd_indicators) >= 2 else "medium"
            detection["indicators"] = freebsd_indicators
        
        return detection
    
    async def _enumerate_active_directory(self, target: str, services: List[Dict]) -> Dict:
        """
        Enumerate Active Directory services on Windows machines.
        """
        ad_results = {
            "domain_info": {},
            "users": [],
            "groups": [],
            "computers": [],
            "shares": [],
            "policies": {},
            "vulnerabilities": []
        }
        
        ldap_service = None
        for service in services:
            if service.get('port') in ['389', '636'] or 'ldap' in service.get('service', '').lower():
                ldap_service = service
                break
        
        if ldap_service:
            # Anonymous LDAP enumeration
            ldap_info = await self._enumerate_ldap_anonymous(target)
            ad_results["domain_info"] = ldap_info
        
        # SMB enumeration for domain info
        smb_service = None
        for service in services:
            if service.get('port') in ['445', '139'] or 'smb' in service.get('service', '').lower():
                smb_service = service
                break
        
        if smb_service:
            smb_domain_info = await self._enumerate_smb_domain(target)
            ad_results.update(smb_domain_info)
        
        return ad_results
    
    async def _analyze_entry_point(self, target: str, services: List[Dict]) -> Dict:
        """
        Analyze the entry point machine (likely APT-FW01).
        """
        analysis = {
            "is_entry_point": True,
            "machine_role": "firewall_gateway",
            "attack_vectors": [],
            "recommendations": []
        }
        
        web_services = [s for s in services if 'http' in s.get('service', '').lower()]
        if web_services:
            analysis["attack_vectors"].append("Web interface exploitation")
            analysis["recommendations"].append("Enumerate web directories and check for default credentials")
        
        ssh_services = [s for s in services if 'ssh' in s.get('service', '').lower()]
        if ssh_services:
            analysis["attack_vectors"].append("SSH brute force or key-based attacks")
            analysis["recommendations"].append("Check for weak SSH credentials or exposed keys")
        
        return analysis
    
    async def _identify_privesc_vectors(self, target: str, services: List[Dict], machine_type: Dict) -> List[Dict]:
        """
        Identify potential privilege escalation vectors.
        """
        vectors = []
        
        if machine_type.get("type") == "Windows":
            vectors.extend([
                {
                    "type": "Windows Service Exploitation",
                    "description": "Check for vulnerable Windows services",
                    "tools": ["winpeas", "powerup", "seatbelt"]
                },
                {
                    "type": "Kerberoasting",
                    "description": "Extract service account hashes",
                    "tools": ["impacket-GetUserSPNs", "rubeus"]
                },
                {
                    "type": "DCSync Attack",
                    "description": "Replicate domain controller data",
                    "tools": ["impacket-secretsdump", "mimikatz"]
                }
            ])
        elif machine_type.get("type") == "FreeBSD":
            vectors.extend([
                {
                    "type": "SUID Binary Exploitation",
                    "description": "Find and exploit SUID binaries",
                    "tools": ["find", "gtfobins"]
                },
                {
                    "type": "Kernel Exploitation",
                    "description": "Check for FreeBSD kernel vulnerabilities",
                    "tools": ["uname", "searchsploit"]
                },
                {
                    "type": "Configuration File Analysis",
                    "description": "Analyze system configuration files",
                    "tools": ["cat", "grep", "find"]
                }
            ])
        
        return vectors
    
    async def _enumerate_ldap(self, target: str, service: Dict) -> Dict:
        """
        Enumerate LDAP service.
        """
        results = {
            "service": "ldap",
            "port": service.get("port"),
            "anonymous_access": False,
            "domain_info": {},
            "users": [],
            "groups": []
        }
        
        ldap_info = await self._enumerate_ldap_anonymous(target)
        results.update(ldap_info)
        
        return results
    
    async def _enumerate_ldap_anonymous(self, target: str) -> Dict:
        """
        Attempt anonymous LDAP enumeration.
        """
        try:
            cmd = ["ldapsearch", "-x", "-h", target, "-s", "base", "namingcontexts"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                return {
                    "anonymous_access": True,
                    "ldap_info": output,
                    "domain_info": self._parse_ldap_naming_contexts(output)
                }
            else:
                return {"anonymous_access": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"anonymous_access": False, "error": str(e)}
    
    async def _enumerate_kerberos(self, target: str, service: Dict) -> Dict:
        """
        Enumerate Kerberos service.
        """
        return {
            "service": "kerberos",
            "port": service.get("port"),
            "version": service.get("version", ""),
            "recommendations": [
                "Attempt Kerberoasting attacks",
                "Check for AS-REP roasting opportunities",
                "Enumerate service principal names (SPNs)"
            ]
        }
    
    async def _enumerate_rdp(self, target: str, service: Dict) -> Dict:
        """
        Enumerate RDP service.
        """
        return {
            "service": "rdp",
            "port": service.get("port"),
            "version": service.get("version", ""),
            "recommendations": [
                "Check for weak RDP credentials",
                "Test for RDP vulnerabilities (BlueKeep, etc.)",
                "Attempt RDP brute force with common credentials"
            ]
        }
    
    async def _enumerate_winrm(self, target: str, service: Dict) -> Dict:
        """
        Enumerate WinRM service.
        """
        return {
            "service": "winrm",
            "port": service.get("port"),
            "version": service.get("version", ""),
            "recommendations": [
                "Test WinRM authentication with discovered credentials",
                "Check for WinRM misconfigurations",
                "Attempt PowerShell remoting"
            ]
        }
    
    async def _enumerate_smb_domain(self, target: str) -> Dict:
        """
        Enumerate SMB for domain information.
        """
        try:
            cmd = ["enum4linux", "-a", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                return {
                    "domain_info": self._parse_enum4linux_domain(output),
                    "users": self._parse_enum4linux_users(output),
                    "groups": self._parse_enum4linux_groups(output)
                }
            else:
                return {"error": stderr.decode()}
                
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_ldap_naming_contexts(self, output: str) -> Dict:
        """
        Parse LDAP naming contexts to extract domain information.
        """
        domain_info = {}
        lines = output.split('\n')
        
        for line in lines:
            if 'namingcontexts:' in line.lower():
                context = line.split(':', 1)[1].strip()
                if 'DC=' in context:
                    domain_info["domain_dn"] = context
                    dc_parts = [part.split('=')[1] for part in context.split(',') if part.strip().startswith('DC=')]
                    domain_info["domain_name"] = '.'.join(dc_parts)
        
        return domain_info
    
    def _parse_enum4linux_domain(self, output: str) -> Dict:
        """
        Parse enum4linux output for domain information.
        """
        domain_info = {}
        lines = output.split('\n')
        
        for line in lines:
            if 'domain name:' in line.lower():
                domain_info["domain_name"] = line.split(':', 1)[1].strip()
            elif 'domain sid:' in line.lower():
                domain_info["domain_sid"] = line.split(':', 1)[1].strip()
        
        return domain_info
    
    def _parse_enum4linux_groups(self, output: str) -> List[str]:
        """
        Parse enum4linux output for group information.
        """
        groups = []
        lines = output.split('\n')
        
        for line in lines:
            if 'group:' in line.lower() and '[' in line and ']' in line:
                group_name = line.split('[')[1].split(']')[0]
                if group_name and group_name not in groups:
                    groups.append(group_name)
        
        return groups
    
    async def submit_discovered_info_to_htb(self, target: str, enumeration_results: Dict) -> Dict:
        """
        Submit discovered information to HTB for tracking and potential flag discovery.
        
        Args:
            target: Target IP address
            enumeration_results: Results from enumeration
            
        Returns:
            Submission result
        """
        try:
            machine_info = {
                "target": target,
                "services": enumeration_results.get("discovered_services", []),
                "vulnerabilities": enumeration_results.get("vulnerabilities", []),
                "machine_type": enumeration_results.get("aptlabs_specific", {}).get("machine_type_detection", {})
            }
            
            import subprocess
            import json
            
            recon_data = json.dumps(machine_info, indent=2)
            
            return {
                "success": True,
                "message": f"Reconnaissance data prepared for {target}",
                "data": machine_info,
                "htb_integration": "ready_for_submission"
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to prepare HTB submission: {str(e)}"
            }
    
    async def check_for_flags_in_enumeration(self, enumeration_results: Dict) -> List[Dict]:
        """
        Check enumeration results for potential flags or flag locations.
        
        Args:
            enumeration_results: Results from target enumeration
            
        Returns:
            List of potential flag locations
        """
        potential_flags = []
        
        for key, result in enumeration_results.get("enumeration_results", {}).items():
            if "web" in key:
                directories = result.get("directories", [])
                for directory in directories:
                    if any(flag_hint in directory.lower() for flag_hint in ['flag', 'user', 'root', 'admin']):
                        potential_flags.append({
                            "type": "web_directory",
                            "location": f"{result.get('target', '')}{directory}",
                            "confidence": "medium",
                            "method": "directory_enumeration"
                        })
            
            elif "smb" in key:
                shares = result.get("shares", [])
                for share in shares:
                    if isinstance(share, dict) and share.get("name"):
                        share_name = share["name"].lower()
                        if any(flag_hint in share_name for flag_hint in ['users', 'admin', 'backup']):
                            potential_flags.append({
                                "type": "smb_share",
                                "location": f"\\\\{enumeration_results['target']}\\{share['name']}",
                                "confidence": "high",
                                "method": "smb_enumeration"
                            })
        
        common_flag_paths = [
            "/home/*/user.txt",
            "/root/root.txt", 
            "/Users/*/Desktop/user.txt",
            "C:\\Users\\*\\Desktop\\user.txt",
            "C:\\Users\\Administrator\\Desktop\\root.txt"
        ]
        
        for path in common_flag_paths:
            potential_flags.append({
                "type": "file_system",
                "location": path,
                "confidence": "low",
                "method": "common_locations"
            })
        
        return potential_flags
    
    async def integrate_with_htb_operator(self, command: str, args: List[str] = None) -> Dict:
        """
        Integrate with htb-operator for various operations.
        
        Args:
            command: HTB-operator command to execute
            args: Additional arguments for the command
            
        Returns:
            Command execution result
        """
        try:
            cmd = ["htb-operator", command]
            if args:
                cmd.extend(args)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode(),
                    "command": " ".join(cmd)
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode(),
                    "command": " ".join(cmd)
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": " ".join(cmd) if 'cmd' in locals() else command
            }
