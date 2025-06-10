"""
HTB APTLabs Agent - Specialized agent for HackTheBox APTLabs ProLab operations.
"""

import asyncio
import subprocess
import json
import os
from typing import Dict, List, Optional, Any
from .base_agent import Agent

class HtbAptlabsAgent(Agent):
    """
    Specialized agent for HackTheBox APTLabs ProLab operations.
    Handles VPN management, network discovery, and flag submission.
    """
    
    def __init__(self):
        super().__init__(
            name="htb_aptlabs_agent",
            description="Specialized agent for HackTheBox APTLabs ProLab penetration testing",
            instructions="""
            You are the HTB APTLabs agent. Your role is to:
            1. Manage VPN connections to APTLabs ProLab
            2. Perform network discovery on 10.10.110.0/24
            3. Coordinate with other agents for comprehensive testing
            4. Submit captured flags to HTB platform
            5. Track progress and maintain operation state
            """
        )
        
        self.lab_name = "APTLabs"
        self.network_range = "10.10.110.0/24"
        self.htb_api_key = os.getenv("HTB_API_KEY")
        self.vpn_connected = False
        self.discovered_hosts = []
        self.captured_flags = []
        
        self.lab_info = {
            "id": "5",
            "name": "APTLabs",
            "network": "10.10.110.0/24",
            "machines": 18,
            "flags": 20,
            "difficulty": "Expert",
            "entry_point": "APT-FW01"
        }
    
    async def initialize_aptlabs_operation(self) -> Dict[str, Any]:
        """
        Initialize APTLabs operation by setting up VPN and basic reconnaissance.
        """
        try:
            await self._ensure_htb_operator_initialized()
            
            vpn_result = await self.connect_vpn()
            if not vpn_result["success"]:
                return {
                    "success": False,
                    "message": f"Failed to connect to VPN: {vpn_result['message']}"
                }
            
            discovery_result = await self.discover_network()
            
            lab_details = await self.get_lab_details()
            
            return {
                "success": True,
                "message": "APTLabs operation initialized successfully",
                "vpn_status": vpn_result,
                "network_discovery": discovery_result,
                "lab_details": lab_details,
                "next_steps": [
                    "Perform detailed port scanning on discovered hosts",
                    "Enumerate services on APT-FW01 (entry point)",
                    "Begin vulnerability assessment"
                ]
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to initialize APTLabs operation: {str(e)}"
            }
    
    async def connect_vpn(self) -> Dict[str, Any]:
        """
        Connect to APTLabs VPN using htb-operator.
        """
        try:
            status_result = await self._run_htb_command("vpn status")
            
            if "Connected" in status_result or "Active" in status_result:
                self.vpn_connected = True
                return {
                    "success": True,
                    "message": "VPN already connected",
                    "status": status_result
                }
            
            vpn_list = await self._run_htb_command("vpn list --prolabs")
            
            start_result = await self._run_htb_command("vpn start")
            
            await asyncio.sleep(10)
            
            verify_result = await self._run_htb_command("vpn status")
            
            if "Connected" in verify_result or "Active" in verify_result:
                self.vpn_connected = True
                return {
                    "success": True,
                    "message": "VPN connected successfully",
                    "status": verify_result
                }
            else:
                return {
                    "success": False,
                    "message": "VPN connection failed to establish"
                }
                
        except Exception as e:
            return {
                "success": False,
                "message": f"VPN connection error: {str(e)}"
            }
    
    async def disconnect_vpn(self) -> Dict[str, Any]:
        """
        Disconnect from APTLabs VPN.
        """
        try:
            result = await self._run_htb_command("vpn stop")
            self.vpn_connected = False
            
            return {
                "success": True,
                "message": "VPN disconnected successfully",
                "result": result
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"VPN disconnection error: {str(e)}"
            }
    
    async def discover_network(self) -> Dict[str, Any]:
        """
        Perform network discovery on APTLabs network (10.10.110.0/24).
        """
        try:
            if not self.vpn_connected:
                return {
                    "success": False,
                    "message": "VPN not connected. Cannot perform network discovery."
                }
            
            ping_sweep_result = await self._run_nmap_command(f"-sn {self.network_range}")
            
            live_hosts = self._parse_nmap_ping_sweep(ping_sweep_result)
            self.discovered_hosts = live_hosts
            
            host_details = []
            for host in live_hosts[:5]:  # Limit to first 5 hosts for initial discovery
                port_scan = await self._run_nmap_command(f"-sS -T4 --top-ports 1000 {host}")
                host_details.append({
                    "ip": host,
                    "scan_result": port_scan
                })
            
            return {
                "success": True,
                "message": f"Network discovery completed. Found {len(live_hosts)} live hosts.",
                "live_hosts": live_hosts,
                "host_details": host_details,
                "network_range": self.network_range
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Network discovery error: {str(e)}"
            }
    
    async def submit_flag(self, flag: str) -> Dict[str, Any]:
        """
        Submit a captured flag to HTB APTLabs.
        """
        try:
            if not flag.startswith("HTB{") or not flag.endswith("}"):
                return {
                    "success": False,
                    "message": "Invalid flag format. Flags should be in format HTB{...}"
                }
            
            result = await self._run_htb_command(f'prolabs submit --name "{self.lab_name}" --flag \'{flag}\'')
            
            if flag not in self.captured_flags:
                self.captured_flags.append({
                    "flag": flag,
                    "submitted_at": asyncio.get_event_loop().time(),
                    "result": result
                })
            
            return {
                "success": True,
                "message": f"Flag {flag} submitted successfully",
                "result": result,
                "total_flags_captured": len(self.captured_flags)
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Flag submission error: {str(e)}"
            }
    
    async def get_lab_details(self) -> Dict[str, Any]:
        """
        Get detailed information about APTLabs ProLab.
        """
        try:
            result = await self._run_htb_command(f'prolabs info --name {self.lab_name}')
            
            return {
                "success": True,
                "lab_info": self.lab_info,
                "detailed_info": result,
                "captured_flags": len(self.captured_flags),
                "vpn_connected": self.vpn_connected
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to get lab details: {str(e)}"
            }
    
    async def coordinate_with_team_leader(self, task: str, context: Dict) -> Dict[str, Any]:
        """
        Coordinate with team leader agent for APTLabs operations.
        """
        try:
            from agents.team_leader_agent import TeamLeaderAgent
            
            team_leader = TeamLeaderAgent()
            
            aptlabs_context = {
                **context,
                "lab_name": self.lab_name,
                "network_range": self.network_range,
                "vpn_connected": self.vpn_connected,
                "discovered_hosts": self.discovered_hosts,
                "captured_flags": len(self.captured_flags),
                "lab_info": self.lab_info
            }
            
            result = await team_leader.coordinate_agents(task, aptlabs_context)
            
            return {
                "success": True,
                "coordination_result": result,
                "message": "Successfully coordinated with team leader"
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Coordination error: {str(e)}"
            }
    
    async def get_operation_status(self) -> Dict[str, Any]:
        """
        Get current status of APTLabs operation.
        """
        return {
            "lab_name": self.lab_name,
            "network_range": self.network_range,
            "vpn_connected": self.vpn_connected,
            "discovered_hosts": len(self.discovered_hosts),
            "captured_flags": len(self.captured_flags),
            "lab_info": self.lab_info,
            "operation_active": self.vpn_connected,
            "next_targets": self.discovered_hosts[:3] if self.discovered_hosts else []
        }
    
    async def _ensure_htb_operator_initialized(self) -> None:
        """
        Ensure htb-operator is initialized with API key.
        """
        try:
            await self._run_htb_command(f"init -api {self.htb_api_key}")
        except Exception:
            pass
    
    async def _run_htb_command(self, command: str) -> str:
        """
        Run htb-operator command with proper environment.
        """
        full_command = f"htb-operator {command}"
        
        process = await asyncio.create_subprocess_shell(
            full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HTB_API_KEY": self.htb_api_key}
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"HTB command failed: {stderr.decode()}")
        
        return stdout.decode()
    
    async def _run_nmap_command(self, args: str) -> str:
        """
        Run nmap command for network scanning.
        """
        full_command = f"nmap {args}"
        
        process = await asyncio.create_subprocess_shell(
            full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Nmap command failed: {stderr.decode()}")
        
        return stdout.decode()
    
    def _parse_nmap_ping_sweep(self, nmap_output: str) -> List[str]:
        """
        Parse nmap ping sweep output to extract live host IPs.
        """
        live_hosts = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if 'Nmap scan report for' in line:
                parts = line.split()
                for part in parts:
                    if self._is_valid_ip(part):
                        live_hosts.append(part)
                        break
        
        return live_hosts
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if string is a valid IP address.
        """
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
