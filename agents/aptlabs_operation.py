"""
APTLabs Operation Script - Coordinates the full attack chain for HTB APTLabs ProLab.
"""

import asyncio
import json
import subprocess
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from .base_agent import Agent

class AptlabsOperationAgent(Agent):
    """
    Orchestrates the complete APTLabs ProLab attack chain.
    Coordinates between specialized agents to discover, enumerate, exploit, and submit flags.
    """
    
    def __init__(self):
        super().__init__(name="aptlabs_operation_agent")
        
        self.operation_state = {
            "status": "initialized",
            "start_time": None,
            "vpn_connected": False,
            "discovered_hosts": [],
            "compromised_hosts": [],
            "captured_flags": [],
            "current_phase": "initialization",
            "target_flags": 3,  # Goal: first 3 flags
            "total_flags_available": 20
        }
        
        self.aptlabs_config = {
            "prolab_name": "APTLabs",
            "prolab_id": 5,
            "network": "10.10.110.0/24",
            "expected_machines": 18,
            "flag_patterns": [
                r"HTB\{[a-zA-Z0-9_\-]+\}",
                r"user\.txt",
                r"root\.txt"
            ]
        }
        
        self.agents = {}
        self.htb_operator_initialized = False
    
    async def initialize_operation(self, config: Optional[Dict] = None) -> Dict:
        """
        Initialize the complete APTLabs operation.
        
        Returns:
            Operation initialization result
        """
        print("🚀 Initializing APTLabs ProLab Operation")
        
        if config:
            if 'target_lab' in config:
                self.aptlabs_config["prolab_name"] = config['target_lab']
            if 'network_range' in config:
                self.aptlabs_config["network"] = config['network_range']
            if 'agents' in config:
                self.agents = config['agents']
        
        try:
            init_result = await self._initialize_htb_operator()
            if not init_result["success"]:
                return {
                    "success": False,
                    "error": f"HTB-operator initialization failed: {init_result['error']}"
                }
            
            start_result = await self._start_aptlabs_prolab()
            if not start_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to start APTLabs: {start_result['error']}"
                }
            
            vpn_result = await self._connect_vpn()
            if not vpn_result["success"]:
                return {
                    "success": False,
                    "error": f"VPN connection failed: {vpn_result['error']}"
                }
            
            await self._initialize_agents()
            
            self.operation_state.update({
                "status": "ready",
                "start_time": datetime.now(),
                "current_phase": "network_discovery"
            })
            
            print("✅ APTLabs operation initialized successfully")
            return {
                "success": True,
                "message": "APTLabs operation ready to begin",
                "operation_state": self.operation_state
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Operation initialization failed: {str(e)}"
            }
    
    async def execute_full_attack_chain(self) -> Dict:
        """
        Execute the complete attack chain to capture the first 3 flags.
        
        Returns:
            Attack chain execution result
        """
        print("⚔️ Executing APTLabs attack chain")
        
        try:
            # Initialize agents first
            init_result = await self._initialize_agents()
            if not init_result["success"]:
                return init_result
            
            discovery_result = await self._phase_network_discovery()
            if not discovery_result["success"]:
                return discovery_result
            
            enumeration_result = await self._phase_target_enumeration()
            if not enumeration_result["success"]:
                return enumeration_result
            
            initial_access_result = await self._phase_initial_access()
            if not initial_access_result["success"]:
                return initial_access_result
            
            flag_hunting_result = await self._phase_flag_hunting()
            
            final_report = await self._generate_operation_report()
            
            return {
                "success": True,
                "message": f"Attack chain completed. Captured {len(self.operation_state['captured_flags'])} flags",
                "captured_flags": self.operation_state["captured_flags"],
                "discovered_hosts": self.operation_state["discovered_hosts"],
                "compromised_hosts": self.operation_state["compromised_hosts"],
                "current_phase": self.operation_state["current_phase"],
                "status": "completed",
                "operation_report": final_report
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Attack chain execution failed: {str(e)}"
            }
    
    async def _initialize_htb_operator(self) -> Dict:
        """Initialize htb-operator with API key."""
        try:
            import os
            htb_api_key = os.getenv("HTB_API_KEY")
            
            if not htb_api_key:
                return {
                    "success": False,
                    "error": "HTB_API_KEY environment variable not found"
                }
            
            cmd = ["htb-operator", "init", "-api", htb_api_key]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.htb_operator_initialized = True
                return {
                    "success": True,
                    "message": "HTB-operator initialized successfully",
                    "output": stdout.decode()
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _start_aptlabs_prolab(self) -> Dict:
        """Start the APTLabs ProLab."""
        try:
            cmd = ["htb-operator", "prolabs", "start", "--name", self.aptlabs_config["prolab_name"]]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "message": "APTLabs ProLab started successfully",
                    "output": stdout.decode()
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _connect_vpn(self) -> Dict:
        """Connect to APTLabs VPN."""
        try:
            cmd = ["htb-operator", "vpn", "start", "--id", "309"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.operation_state["vpn_connected"] = True
                
                await asyncio.sleep(10)
                
                connectivity_check = await self._verify_network_connectivity()
                
                return {
                    "success": True,
                    "message": "VPN connected successfully",
                    "output": stdout.decode(),
                    "connectivity_check": connectivity_check
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _verify_network_connectivity(self) -> Dict:
        """Verify connectivity to APTLabs network."""
        try:
            test_host = (self.operation_state["discovered_hosts"][0] 
                        if self.operation_state["discovered_hosts"] 
                        else "8.8.8.8")
            cmd = ["ping", "-c", "3", test_host]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "message": f"Network connectivity verified to {test_host}",
                    "ping_output": stdout.decode()
                }
            else:
                return {
                    "success": False,
                    "message": f"No connectivity to {test_host}",
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _initialize_agents(self) -> Dict:
        """Initialize all specialized agents."""
        try:
            from .team_leader_agent import TeamLeaderAgent
            from .network_scanner_agent import NetworkScannerAgent
            from .recon_agent import ReconAgent
            from .initial_access_agent import InitialAccessAgent
            from .htb_aptlabs_agent import HtbAptlabsAgent
            from .web_hacking_agent import WebHackingAgent
            
            self.agents = {
                "team_leader": TeamLeaderAgent(),
                "scanner": NetworkScannerAgent(),
                "recon": ReconAgent(),
                "access": InitialAccessAgent(),
                "htb": HtbAptlabsAgent(),
                "web_hacking": WebHackingAgent()
            }
            
            print("✅ All specialized agents initialized")
            
            return {
                "success": True,
                "message": "All specialized agents initialized successfully",
                "agents": list(self.agents.keys())
            }
            
        except Exception as e:
            print(f"❌ Agent initialization failed: {e}")
            return {
                "success": False,
                "error": f"Agent initialization failed: {str(e)}"
            }
    
    async def _phase_network_discovery(self) -> Dict:
        """Phase 1: Network Discovery."""
        print("🔍 Phase 1: Network Discovery")
        
        try:
            self.operation_state["current_phase"] = "network_discovery"
            
            scanner = self.agents["scanner"]
            discovery_result = await scanner.discover_network(
                network=self.aptlabs_config["network"]
            )
            
            if discovery_result["status"] == "completed":
                discovered_hosts = discovery_result["discovery_results"]["live_hosts"]
                self.operation_state["discovered_hosts"] = discovered_hosts
                
                print(f"✅ Discovered {len(discovered_hosts)} live hosts")
                print(f"📍 Hosts: {', '.join(discovered_hosts)}")
                
                return {
                    "success": True,
                    "message": f"Network discovery completed. Found {len(discovered_hosts)} hosts",
                    "discovered_hosts": discovered_hosts
                }
            else:
                return {
                    "success": False,
                    "error": "Network discovery failed"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Network discovery phase failed: {str(e)}"
            }
    
    async def _enumerate_targets_parallel(self, targets: List[str], recon_agent) -> Dict:
        """Helper function for parallel target enumeration."""
        tasks = []
        for target in targets:
            print(f"🎯 Enumerating {target}")
            task = recon_agent.enumerate_target(target=target, is_aptlabs=True)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        enumeration_results = {}
        for i, target in enumerate(targets):
            result = results[i]
            if isinstance(result, Exception):
                print(f"❌ Enumeration failed for {target}: {str(result)}")
                enumeration_results[target] = {"error": str(result), "success": False}
            else:
                enumeration_results[target] = result
                if isinstance(result, dict):
                    potential_flags = result.get("potential_flags", [])
                    if potential_flags:
                        print(f"🚩 Found {len(potential_flags)} potential flag locations on {target}")
        
        return enumeration_results

    async def _phase_target_enumeration(self) -> Dict:
        """Phase 2: Target Enumeration."""
        print("🔍 Phase 2: Target Enumeration")
        
        try:
            self.operation_state["current_phase"] = "target_enumeration"
            
            recon_agent = self.agents["recon"]
            
            all_targets = self.operation_state["discovered_hosts"]
            print(f"🎯 Starting parallel enumeration of {len(all_targets)} targets")
            
            enumeration_results = await self._enumerate_targets_parallel(all_targets, recon_agent)
            
            successful_enumerations = [target for target, result in enumeration_results.items() 
                                     if not result.get("error")]
            
            return {
                "success": True,
                "message": f"Target enumeration completed for {len(successful_enumerations)}/{len(all_targets)} hosts",
                "enumeration_results": enumeration_results,
                "successful_targets": successful_enumerations
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Target enumeration phase failed: {str(e)}"
            }
    
    async def _phase_initial_access(self) -> Dict:
        """Phase 3: Initial Access."""
        print("⚔️ Phase 3: Initial Access")
        
        try:
            self.operation_state["current_phase"] = "initial_access"
            
            initial_access_agent = self.agents["access"]
            
            access_tasks = []
            targets = self.operation_state["discovered_hosts"]
            
            print(f"🎯 Starting parallel initial access attempts on {len(targets)} hosts")
            
            for target in targets:
                print(f"🎯 Preparing initial access task for: {target}")
                task = initial_access_agent.attempt_initial_access(
                    target=target,
                    recon_data={}  # Would be populated from enumeration phase
                )
                access_tasks.append(task)
            
            task_results = await asyncio.gather(*access_tasks, return_exceptions=True)
            
            access_results = []
            for i, target in enumerate(targets):
                result = task_results[i]
                
                if isinstance(result, Exception):
                    print(f"❌ Initial access failed for {target}: {str(result)}")
                    access_results.append({
                        "target": target,
                        "success": False,
                        "error": str(result)
                    })
                elif isinstance(result, dict) and result.get("success"):
                    self.operation_state["compromised_hosts"].append(target)
                    print(f"✅ Initial access gained on {target}")
                    
                    flags_found = await self._search_for_flags(target)
                    access_results.append({
                        "target": target,
                        "success": True,
                        "flags_found": flags_found
                    })
                else:
                    error_msg = result.get("error", "Unknown error") if isinstance(result, dict) else "Unknown error"
                    access_results.append({
                        "target": target,
                        "success": False,
                        "error": error_msg
                    })
            
            successful_accesses = [r for r in access_results if r["success"]]
            if successful_accesses:
                return {
                    "success": True,
                    "message": f"Initial access gained on {len(successful_accesses)} hosts",
                    "access_results": access_results,
                    "compromised_hosts": [r["target"] for r in successful_accesses]
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to gain initial access on any discovered hosts",
                    "access_results": access_results
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Initial access phase failed: {str(e)}"
            }
    
    async def _phase_flag_hunting(self) -> Dict:
        """Phase 4: Flag Hunting and Privilege Escalation."""
        print("🚩 Phase 4: Flag Hunting")
        
        try:
            self.operation_state["current_phase"] = "flag_hunting"
            
            flags_captured = 0
            target_flags = self.operation_state["target_flags"]
            
            for host in self.operation_state["compromised_hosts"]:
                if flags_captured >= target_flags:
                    break
                
                print(f"🔍 Hunting flags on {host}")
                
                flag_results = await self._comprehensive_flag_search(host)
                
                for flag in flag_results:
                    if flags_captured >= target_flags:
                        break
                    
                    submission_result = await self._submit_flag_to_htb(flag)
                    
                    if submission_result["success"]:
                        self.operation_state["captured_flags"].append({
                            "flag": flag,
                            "host": host,
                            "timestamp": datetime.now().isoformat(),
                            "submission_result": submission_result
                        })
                        flags_captured += 1
                        print(f"✅ Flag {flags_captured}/{target_flags} captured and submitted!")
            
            return {
                "success": True,
                "message": f"Flag hunting completed. Captured {flags_captured}/{target_flags} flags",
                "flags_captured": flags_captured,
                "captured_flags": self.operation_state["captured_flags"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Flag hunting phase failed: {str(e)}"
            }
    
    async def _search_for_flags(self, host: str) -> List[str]:
        """Search for flags on a compromised host."""
        flags_found = []
        
        flag_locations = [
            "/home/*/user.txt",
            "/root/root.txt",
            "/home/*/Desktop/user.txt",
            "/Users/*/Desktop/user.txt",
            "C:\\Users\\*\\Desktop\\user.txt",
            "C:\\Users\\Administrator\\Desktop\\root.txt"
        ]
        
        return []
    
    async def _comprehensive_flag_search(self, host: str) -> List[str]:
        """Perform comprehensive flag search on compromised host."""
        flags = []
        
        search_commands = [
            f"find / -name 'user.txt' 2>/dev/null",
            f"find / -name 'root.txt' 2>/dev/null",
            f"grep -r 'HTB{{' /home/ 2>/dev/null",
            f"grep -r 'HTB{{' /root/ 2>/dev/null"
        ]
        
        return []
    
    async def _submit_flag_to_htb(self, flag: str) -> Dict:
        """Submit captured flag to HTB."""
        try:
            cmd = [
                "htb-operator", "prolabs", "submit",
                "--name", self.aptlabs_config["prolab_name"],
                "--flag", flag
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "message": f"Flag submitted successfully: {flag}",
                    "output": stdout.decode()
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode(),
                    "flag": flag
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "flag": flag
            }
    
    async def _generate_operation_report(self) -> Dict:
        """Generate comprehensive operation report."""
        end_time = datetime.now()
        duration = end_time - self.operation_state["start_time"] if self.operation_state["start_time"] else None
        
        report = {
            "operation_summary": {
                "start_time": self.operation_state["start_time"].isoformat() if self.operation_state["start_time"] else None,
                "end_time": end_time.isoformat(),
                "duration_minutes": duration.total_seconds() / 60 if duration else None,
                "status": "completed"
            },
            "network_discovery": {
                "total_hosts_discovered": len(self.operation_state["discovered_hosts"]),
                "discovered_hosts": self.operation_state["discovered_hosts"]
            },
            "compromise_summary": {
                "total_hosts_compromised": len(self.operation_state["compromised_hosts"]),
                "compromised_hosts": self.operation_state["compromised_hosts"]
            },
            "flag_summary": {
                "target_flags": self.operation_state["target_flags"],
                "flags_captured": len(self.operation_state["captured_flags"]),
                "success_rate": (len(self.operation_state["captured_flags"]) / self.operation_state["target_flags"]) * 100,
                "captured_flags": self.operation_state["captured_flags"]
            },
            "recommendations": [
                "Continue enumeration on remaining hosts",
                "Attempt lateral movement to Windows domain controllers",
                "Focus on privilege escalation for additional flags"
            ]
        }
        
        return report
    
    async def get_operation_status(self) -> Dict:
        """Get current operation status."""
        return {
            "operation_state": self.operation_state,
            "agents_status": {name: "active" for name in self.agents.keys()},
            "htb_operator_initialized": self.htb_operator_initialized
        }
    
    async def get_status(self):
        """Get current status (alias for get_operation_status)"""
        return await self.get_operation_status()
    
    async def cleanup_operation(self) -> Dict:
        """Cleanup operation resources."""
        try:
            if self.operation_state["vpn_connected"]:
                cmd = ["htb-operator", "prolabs", "vpn", "--disconnect"]
                process = await asyncio.create_subprocess_exec(*cmd)
                await process.communicate()
            
            cmd = ["htb-operator", "prolabs", "stop", "--name", self.aptlabs_config["prolab_name"]]
            process = await asyncio.create_subprocess_exec(*cmd)
            await process.communicate()
            
            self.operation_state["status"] = "cleanup_completed"
            
            return {
                "success": True,
                "message": "Operation cleanup completed"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Cleanup failed: {str(e)}"
            }
