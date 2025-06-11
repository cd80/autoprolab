"""
Autonomous Red Team Agent - Single flexible AI agent for HTB Pro Lab operations.
Replaces all specialized agents with one AI-powered agent that uses reasoning to determine optimal approaches.
"""

import asyncio
import json
import subprocess
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from agno.agent import Agent

class AutonomousRedTeamAgent(Agent):
    """
    Single autonomous agent that leverages AI reasoning for red team operations.
    Replaces rigid specialized agents with flexible AI-driven decision making.
    """
    
    def __init__(self):
        super().__init__(
            name="autonomous_redteam_agent",
            instructions="""
            You are an autonomous red team agent with full flexibility to approach HTB Pro Labs.
            
            Your capabilities:
            - Network discovery and reconnaissance 
            - Service enumeration and analysis
            - Vulnerability assessment and exploitation
            - Flag hunting and submission
            - HTB operator integration
            
            Key principles:
            - Use your reasoning to determine the best approach for each situation
            - Adapt your strategy based on discoveries and results
            - Focus on flag capture as the primary objective
            - Leverage all available tools creatively and efficiently
            - No rigid phases - let the situation guide your actions
            
            Available tools:
            - nmap: Network scanning and service detection
            - gobuster: Directory and file enumeration  
            - nikto: Web vulnerability scanning
            - whatweb: Web technology identification
            - smbclient: SMB enumeration
            - enum4linux: Linux/Samba enumeration
            - htb-operator: HTB Pro Lab management and flag submission
            
            Remember: You have complete autonomy to determine the optimal approach.
            Trust your reasoning over any predefined methodologies.
            """
        )
        
        self.operation_state = {
            "status": "initialized",
            "start_time": None,
            "current_objectives": [],
            "discovered_assets": [],
            "captured_flags": [],
            "notes": []
        }
        
        self.htb_config = {
            "api_key": os.getenv("HTB_API_KEY"),
            "current_lab": None,
            "vpn_connected": False
        }
    
    async def start_operation(self, lab_name: str = "APTLabs", objectives: Optional[List[str]] = None) -> Dict:
        """
        Start autonomous red team operation on specified HTB Pro Lab.
        
        Args:
            lab_name: Name of HTB Pro Lab to target
            objectives: Optional specific objectives (defaults to flag capture)
            
        Returns:
            Operation initialization result
        """
        if not objectives:
            objectives = ["Capture as many flags as possible", "Document attack paths", "Achieve domain compromise if applicable"]
        
        self.operation_state.update({
            "status": "starting",
            "start_time": datetime.now(),
            "current_objectives": objectives,
            "target_lab": lab_name
        })
        
        init_result = await self._initialize_htb_operator()
        if not init_result["success"]:
            return init_result
        
        lab_result = await self._start_lab(lab_name)
        if not lab_result["success"]:
            return lab_result
        
        vpn_result = await self._connect_vpn()
        if not vpn_result["success"]:
            return vpn_result
        
        self.operation_state["status"] = "active"
        
        return {
            "success": True,
            "message": f"Operation started on {lab_name}",
            "objectives": objectives,
            "status": "ready_for_autonomous_execution"
        }
    
    async def execute_autonomous_operation(self) -> Dict:
        """
        Execute completely autonomous red team operation.
        Uses AI reasoning to determine optimal approach without rigid phases.
        
        Returns:
            Complete operation results
        """
        try:
            initial_plan = await self._assess_situation_and_plan()
            self.operation_state["notes"].append(f"Initial AI assessment: {initial_plan}")
            
            while len(self.operation_state["captured_flags"]) < 3:  # Target first 3 flags
                
                next_action = await self._determine_next_action()
                
                if not next_action:
                    break
                
                result = await self._execute_action(next_action)
                
                await self._update_state_from_results(result)
                
                if result.get("flags_found"):
                    for flag in result["flags_found"]:
                        submission_result = await self._submit_flag(flag)
                        if submission_result["success"]:
                            self.operation_state["captured_flags"].append({
                                "flag": flag,
                                "timestamp": datetime.now().isoformat(),
                                "source": result.get("source", "unknown")
                            })
            
            return {
                "success": True,
                "operation_completed": True,
                "flags_captured": len(self.operation_state["captured_flags"]),
                "captured_flags": self.operation_state["captured_flags"],
                "discovered_assets": self.operation_state["discovered_assets"],
                "operation_notes": self.operation_state["notes"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Autonomous operation failed: {str(e)}",
                "partial_results": self.operation_state
            }
    
    async def _assess_situation_and_plan(self) -> str:
        """
        Use AI reasoning to assess the current situation and create initial plan.
        No rigid methodology - pure AI decision making.
        """
        return "Initial assessment: Starting with network discovery to understand the environment, then adapting approach based on findings."
    
    async def _determine_next_action(self) -> Optional[Dict]:
        """
        AI determines the next optimal action based on current state.
        No predefined phases or rigid sequences.
        """
        current_assets = len(self.operation_state["discovered_assets"])
        captured_flags = len(self.operation_state["captured_flags"])
        
        if current_assets == 0:
            return {
                "type": "network_discovery",
                "description": "Discover network assets and topology",
                "priority": "high"
            }
        elif captured_flags == 0:
            return {
                "type": "initial_access_attempt",
                "description": "Attempt to gain initial access to discovered assets",
                "priority": "high"
            }
        elif captured_flags < 3:
            return {
                "type": "expand_access",
                "description": "Expand access and hunt for additional flags",
                "priority": "medium"
            }
        else:
            return None  # Operation complete
    
    async def _execute_action(self, action: Dict) -> Dict:
        """
        Execute the AI-determined action using available tools.
        """
        action_type = action["type"]
        
        if action_type == "network_discovery":
            return await self._discover_network()
        elif action_type == "initial_access_attempt":
            return await self._attempt_initial_access()
        elif action_type == "expand_access":
            return await self._expand_access()
        else:
            return {"success": False, "error": f"Unknown action type: {action_type}"}
    
    async def _discover_network(self) -> Dict:
        """
        Flexible network discovery using AI-chosen techniques.
        """
        try:
            cmd = ["nmap", "-sn", "10.10.110.0/24"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hosts = self._parse_nmap_hosts(stdout.decode())
                self.operation_state["discovered_assets"].extend(hosts)
                
                return {
                    "success": True,
                    "action": "network_discovery",
                    "discovered_hosts": hosts,
                    "total_assets": len(self.operation_state["discovered_assets"])
                }
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _attempt_initial_access(self) -> Dict:
        """
        AI-driven initial access attempts on discovered assets.
        """
        results = []
        flags_found = []
        
        for asset in self.operation_state["discovered_assets"]:
            try:
                port_result = await self._scan_asset_ports(asset)
                
                access_result = await self._check_easy_access(asset, port_result.get("open_ports", []))
                
                if access_result.get("flags"):
                    flags_found.extend(access_result["flags"])
                
                results.append({
                    "asset": asset,
                    "port_scan": port_result,
                    "access_attempt": access_result
                })
                
            except Exception as e:
                results.append({"asset": asset, "error": str(e)})
        
        return {
            "success": True,
            "action": "initial_access_attempt",
            "results": results,
            "flags_found": flags_found
        }
    
    async def _expand_access(self) -> Dict:
        """
        AI-driven access expansion and flag hunting.
        """
        return {
            "success": True,
            "action": "expand_access",
            "flags_found": []  # Placeholder
        }
    
    async def _scan_asset_ports(self, asset: str) -> Dict:
        """
        Flexible port scanning based on AI assessment.
        """
        try:
            cmd = ["nmap", "-T4", "--top-ports", "1000", asset]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "open_ports": self._parse_nmap_ports(stdout.decode())
                }
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _check_easy_access(self, asset: str, ports: List[Dict]) -> Dict:
        """
        Check for easy access opportunities (web apps, default creds, etc.)
        """
        flags = []
        
        for port in ports:
            if port.get("service") in ["http", "https"]:
                web_flags = await self._check_web_flags(asset, port["port"])
                flags.extend(web_flags)
        
        return {"flags": flags}
    
    async def _check_web_flags(self, asset: str, port: int) -> List[str]:
        """
        Simple web flag checking.
        """
        flags = []
        try:
            flag_paths = ["/flag.txt", "/user.txt", "/root.txt", "/flag"]
            
            for path in flag_paths:
                cmd = ["curl", "-s", f"http://{asset}:{port}{path}"]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    content = stdout.decode().strip()
                    if content.startswith("HTB{") and content.endswith("}"):
                        flags.append(content)
                        
        except Exception:
            pass
        
        return flags
    
    def _parse_nmap_hosts(self, output: str) -> List[str]:
        """Parse nmap host discovery output."""
        hosts = []
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        hosts.append(part)
                        break
        return hosts
    
    def _parse_nmap_ports(self, output: str) -> List[Dict]:
        """Parse nmap port scan output."""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    ports.append({
                        "port": parts[0].split('/')[0],
                        "service": parts[2]
                    })
        return ports
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is valid IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    async def _initialize_htb_operator(self) -> Dict:
        """Initialize HTB operator."""
        try:
            if not self.htb_config["api_key"]:
                return {"success": False, "error": "HTB_API_KEY not found"}
            
            cmd = ["htb-operator", "init", "-api", self.htb_config["api_key"]]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode() if process.returncode == 0 else stderr.decode()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _start_lab(self, lab_name: str) -> Dict:
        """Start HTB Pro Lab."""
        try:
            cmd = ["htb-operator", "prolabs", "start", "--name", lab_name]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.htb_config["current_lab"] = lab_name
                return {"success": True, "output": stdout.decode()}
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _connect_vpn(self) -> Dict:
        """Connect to HTB Pro Lab VPN."""
        try:
            cmd = ["htb-operator", "vpn", "start", "--prolabs"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.htb_config["vpn_connected"] = True
                return {"success": True, "output": stdout.decode()}
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _submit_flag(self, flag: str) -> Dict:
        """Submit captured flag to HTB."""
        try:
            cmd = [
                "htb-operator", "prolabs", "submit",
                "--name", self.htb_config["current_lab"],
                "--flag", flag
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode() if process.returncode == 0 else stderr.decode()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _update_state_from_results(self, result: Dict):
        """Update operation state based on action results."""
        if result.get("discovered_hosts"):
            for host in result["discovered_hosts"]:
                if host not in self.operation_state["discovered_assets"]:
                    self.operation_state["discovered_assets"].append(host)
        
        if result.get("notes"):
            self.operation_state["notes"].append(result["notes"])
    
    async def get_operation_status(self) -> Dict:
        """Get current operation status."""
        return {
            "status": self.operation_state["status"],
            "runtime": str(datetime.now() - self.operation_state["start_time"]) if self.operation_state["start_time"] else "Not started",
            "objectives": self.operation_state["current_objectives"],
            "discovered_assets": len(self.operation_state["discovered_assets"]),
            "captured_flags": len(self.operation_state["captured_flags"]),
            "current_lab": self.htb_config["current_lab"],
            "vpn_connected": self.htb_config["vpn_connected"]
        }
