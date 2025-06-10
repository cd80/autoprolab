"""
Team Leader Agent - Central orchestrator for the red team operations.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from .base_agent import Agent
from .tool_selector_agent import ToolSelectorAgent

class TeamLeaderAgent(Agent):
    """
    Central orchestrator agent that manages the entire red team operation.
    Coordinates between different specialized agents and maintains overall strategy.
    """
    
    def __init__(self):
        super().__init__(
            name="team_leader",
            description="Central orchestrator for red team operations",
            instructions="""
            You are the team leader agent responsible for:
            1. Orchestrating the entire red team operation
            2. Coordinating between specialized agents
            3. Maintaining overall strategy and objectives
            4. Making high-level decisions about target prioritization
            5. Ensuring proper documentation and reporting
            6. Managing the attack timeline and phases
            """
        )
        
        self.tool_selector = ToolSelectorAgent()
        self.active_agents = {}
        self.operation_state = {
            "phase": "reconnaissance",  # reconnaissance, initial_access, lateral_movement, persistence, exfiltration
            "targets": [],
            "compromised_hosts": [],
            "objectives": [],
            "timeline": [],
            "flags": {
                "captured": [],
                "total_expected": 20,
                "submission_history": []
            }
        }
        
        self.aptlabs_config = {
            "lab_id": "5",
            "lab_name": "APTLabs",
            "network": "10.10.110.0/24",
            "total_machines": 18,
            "total_flags": 20,
            "difficulty": "Expert",
            "entry_point": "APT-FW01",
            "machine_types": ["FreeBSD", "Windows"],
            "domain_environment": True
        }
    
    async def start_operation(self, lab_info: Dict, objectives: List[str]) -> Dict:
        """
        Start a new red team operation.
        
        Args:
            lab_info: Information about the HTB lab
            objectives: List of operation objectives
            
        Returns:
            Operation status and initial plan
        """
        self.operation_state = {
            "phase": "reconnaissance",
            "targets": [],
            "compromised_hosts": [],
            "objectives": objectives,
            "timeline": [{"phase": "reconnaissance", "started_at": "now", "status": "active"}],
            "lab_info": lab_info,
            "flags": {
                "captured": [],
                "total_expected": self.aptlabs_config["total_flags"],
                "submission_history": []
            }
        }
        
        if lab_info.get("name") == "APTLabs" or lab_info.get("id") == "5":
            await self._initialize_aptlabs_operation()
        
        recon_plan = await self._create_reconnaissance_plan(lab_info)
        
        return {
            "operation_id": f"op_{lab_info.get('id', 'unknown')}",
            "status": "started",
            "current_phase": "reconnaissance",
            "initial_plan": recon_plan,
            "objectives": objectives,
            "flag_tracking": self.operation_state["flags"]
        }
    
    async def coordinate_agents(self, task: str, context: Dict) -> Dict:
        """
        Coordinate multiple agents to accomplish a complex task.
        
        Args:
            task: High-level task description
            context: Current operation context
            
        Returns:
            Coordination results and next steps
        """
        required_agents = await self._analyze_task_requirements(task, context)
        
        results = {}
        for agent_type, agent_task in required_agents.items():
            if agent_type not in self.active_agents:
                self.active_agents[agent_type] = await self._initialize_agent(agent_type)
            
            agent = self.active_agents[agent_type]
            results[agent_type] = await agent.execute_task(agent_task, context)
        
        synthesis = await self._synthesize_results(results, task, context)
        
        return {
            "task": task,
            "agent_results": results,
            "synthesis": synthesis,
            "next_actions": synthesis.get("next_actions", [])
        }
    
    async def update_operation_state(self, updates: Dict) -> Dict:
        """
        Update the current operation state based on new information.
        
        Args:
            updates: Dictionary of state updates
            
        Returns:
            Updated operation state
        """
        if "new_targets" in updates:
            for target in updates["new_targets"]:
                if target not in self.operation_state["targets"]:
                    self.operation_state["targets"].append(target)
        
        if "compromised_host" in updates:
            host = updates["compromised_host"]
            if host not in self.operation_state["compromised_hosts"]:
                self.operation_state["compromised_hosts"].append(host)
                
                await self._evaluate_phase_transition()
        
        if "timeline_event" in updates:
            self.operation_state["timeline"].append(updates["timeline_event"])
        
        return self.operation_state
    
    async def _create_reconnaissance_plan(self, lab_info: Dict) -> Dict:
        """Create initial reconnaissance plan for the lab."""
        network = lab_info.get("network", "10.10.110.0/24")
        is_aptlabs = lab_info.get("name") == "APTLabs" or lab_info.get("id") == "5"
        
        if is_aptlabs:
            plan = {
                "phase": "reconnaissance",
                "lab_type": "APTLabs",
                "steps": [
                    {
                        "step": 1,
                        "action": "vpn_connection",
                        "description": "Establish VPN connection to APTLabs",
                        "agent": "htb_aptlabs_agent",
                        "tools": ["htb-operator"],
                        "priority": "critical"
                    },
                    {
                        "step": 2,
                        "action": "network_discovery",
                        "description": f"Discover live hosts in {network} (expecting 18 machines)",
                        "agent": "network_scanner",
                        "tools": ["nmap", "masscan"],
                        "priority": "high",
                        "target_count": 18
                    },
                    {
                        "step": 3,
                        "action": "entry_point_analysis",
                        "description": "Focus on APT-FW01 (FreeBSD firewall) as entry point",
                        "agent": "recon_agent",
                        "tools": ["nmap", "gobuster"],
                        "priority": "high",
                        "target": "APT-FW01"
                    },
                    {
                        "step": 4,
                        "action": "domain_enumeration",
                        "description": "Enumerate Windows domain environment",
                        "agent": "recon_agent",
                        "tools": ["enum4linux", "ldapsearch", "rpcclient"],
                        "priority": "high"
                    },
                    {
                        "step": 5,
                        "action": "service_enumeration",
                        "description": "Enumerate services on all discovered hosts",
                        "agent": "recon_agent",
                        "tools": ["nmap", "nikto", "gobuster"],
                        "priority": "medium"
                    }
                ],
                "estimated_duration": "60-90 minutes",
                "success_criteria": [
                    "VPN connection established",
                    "All 18 machines discovered",
                    "APT-FW01 entry point analyzed",
                    "Domain structure identified",
                    "Initial attack vectors identified"
                ],
                "flag_objectives": [
                    "Capture first flag from entry point",
                    "Identify path to domain compromise",
                    "Document privilege escalation opportunities"
                ]
            }
        else:
            plan = {
                "phase": "reconnaissance",
                "steps": [
                    {
                        "step": 1,
                        "action": "network_discovery",
                        "description": f"Discover live hosts in {network}",
                        "agent": "network_scanner",
                        "tools": ["nmap", "masscan"],
                        "priority": "high"
                    },
                    {
                        "step": 2,
                        "action": "port_scanning",
                        "description": "Perform detailed port scans on discovered hosts",
                        "agent": "host_scanner", 
                        "tools": ["nmap"],
                        "priority": "high"
                    },
                    {
                        "step": 3,
                        "action": "service_enumeration",
                        "description": "Enumerate services and versions",
                        "agent": "host_scanner",
                        "tools": ["nmap", "enum4linux"],
                        "priority": "medium"
                    },
                    {
                        "step": 4,
                        "action": "vulnerability_assessment",
                        "description": "Identify potential vulnerabilities",
                        "agent": "vulnerability_analysis_agent",
                        "tools": ["nmap", "nikto"],
                        "priority": "medium"
                    }
                ],
                "estimated_duration": "30-60 minutes",
                "success_criteria": [
                    "All live hosts discovered",
                    "Open ports identified",
                    "Services enumerated",
                    "Initial vulnerabilities identified"
                ]
            }
        
        return plan
    
    async def _analyze_task_requirements(self, task: str, context: Dict) -> Dict[str, str]:
        """Analyze a task and determine which agents are needed."""
        task_lower = task.lower()
        required_agents = {}
        
        if any(word in task_lower for word in ["scan", "discover", "enumerate", "recon"]):
            if "network" in task_lower:
                required_agents["network_scanner"] = f"Perform network discovery: {task}"
            if "port" in task_lower or "service" in task_lower:
                required_agents["host_scanner"] = f"Perform host scanning: {task}"
            if "web" in task_lower or "http" in task_lower:
                required_agents["web_hacking_agent"] = f"Perform web reconnaissance: {task}"
        
        if any(word in task_lower for word in ["exploit", "attack", "compromise"]):
            required_agents["exploitation_agent"] = f"Perform exploitation: {task}"
            
        if any(word in task_lower for word in ["vulnerability", "cve", "assess"]):
            required_agents["vulnerability_analysis_agent"] = f"Analyze vulnerabilities: {task}"
            
        if any(word in task_lower for word in ["pivot", "lateral", "movement"]):
            required_agents["pivot_engineer"] = f"Perform lateral movement: {task}"
        
        required_agents["tool_selector"] = f"Select appropriate tools for: {task}"
        
        return required_agents
    
    async def _initialize_agent(self, agent_type: str):
        """Initialize a specialized agent."""
        try:
            if agent_type == "htb_aptlabs_agent":
                from .htb_aptlabs_agent import HtbAptlabsAgent
                return HtbAptlabsAgent()
            elif agent_type == "network_scanner":
                from .network_scanner_agent import NetworkScannerAgent
                return NetworkScannerAgent()
            elif agent_type == "recon_agent":
                from .recon_agent import ReconAgent
                return ReconAgent()
            elif agent_type == "initial_access_agent":
                from .initial_access_agent import InitialAccessAgent
                return InitialAccessAgent()
            elif agent_type == "web_hacking_agent":
                from .web_hacking_agent import WebHackingAgent
                return WebHackingAgent()
            else:
                return MockAgent(agent_type)
        except ImportError:
            return MockAgent(agent_type)
    
    async def _synthesize_results(self, results: Dict, task: str, context: Dict) -> Dict:
        """Synthesize results from multiple agents."""
        synthesis = {
            "summary": f"Completed task: {task}",
            "key_findings": [],
            "next_actions": [],
            "recommendations": []
        }
        
        for agent_type, result in results.items():
            if isinstance(result, dict) and "findings" in result:
                synthesis["key_findings"].extend(result["findings"])
            
            if isinstance(result, dict) and "recommendations" in result:
                synthesis["recommendations"].extend(result["recommendations"])
        
        if self.operation_state["phase"] == "reconnaissance":
            if any("vulnerability" in str(finding).lower() for finding in synthesis["key_findings"]):
                synthesis["next_actions"].append("transition_to_initial_access")
        
        return synthesis
    
    async def submit_flag(self, flag: str, source_host: str = None, points: int = None) -> Dict[str, Any]:
        """
        Submit a captured flag to HTB APTLabs.
        
        Args:
            flag: The captured flag (format: HTB{...})
            source_host: Host where flag was captured
            points: Points value of the flag
            
        Returns:
            Submission result
        """
        try:
            from .htb_aptlabs_agent import HtbAptlabsAgent
            
            htb_agent = HtbAptlabsAgent()
            result = await htb_agent.submit_flag(flag)
            
            if result["success"]:
                flag_entry = {
                    "flag": flag,
                    "source_host": source_host,
                    "points": points,
                    "submitted_at": asyncio.get_event_loop().time(),
                    "submission_result": result
                }
                
                self.operation_state["flags"]["captured"].append(flag_entry)
                self.operation_state["flags"]["submission_history"].append(flag_entry)
                
                self.operation_state["timeline"].append({
                    "event": "flag_captured",
                    "flag": flag,
                    "source_host": source_host,
                    "timestamp": "now"
                })
                
                await self._evaluate_flag_based_transitions()
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Flag submission error: {str(e)}"
            }
    
    async def get_flag_progress(self) -> Dict[str, Any]:
        """
        Get current flag capture progress.
        
        Returns:
            Flag progress information
        """
        captured_count = len(self.operation_state["flags"]["captured"])
        total_expected = self.operation_state["flags"]["total_expected"]
        
        return {
            "captured_flags": captured_count,
            "total_flags": total_expected,
            "completion_percentage": (captured_count / total_expected) * 100 if total_expected > 0 else 0,
            "flags_remaining": total_expected - captured_count,
            "captured_flag_details": self.operation_state["flags"]["captured"],
            "submission_history": self.operation_state["flags"]["submission_history"]
        }
    
    async def _initialize_aptlabs_operation(self) -> Dict[str, Any]:
        """
        Initialize APTLabs-specific operation setup.
        """
        try:
            from .htb_aptlabs_agent import HtbAptlabsAgent
            
            htb_agent = HtbAptlabsAgent()
            self.active_agents["htb_aptlabs"] = htb_agent
            
            # Initialize the APTLabs operation
            result = await htb_agent.initialize_aptlabs_operation()
            
            if result["success"]:
                self.operation_state["lab_info"].update(self.aptlabs_config)
                
                self.operation_state["timeline"].append({
                    "event": "aptlabs_initialized",
                    "timestamp": "now",
                    "result": result
                })
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "message": f"APTLabs initialization error: {str(e)}"
            }
    
    async def _evaluate_flag_based_transitions(self):
        """
        Evaluate phase transitions based on flag capture progress.
        """
        captured_count = len(self.operation_state["flags"]["captured"])
        current_phase = self.operation_state["phase"]
        
        if current_phase == "reconnaissance" and captured_count >= 1:
            self.operation_state["phase"] = "initial_access"
            self.operation_state["timeline"].append({
                "phase": "initial_access",
                "started_at": "now",
                "status": "active",
                "trigger": "first_flag_captured"
            })
        
        elif current_phase == "initial_access" and captured_count >= 3:
            self.operation_state["phase"] = "lateral_movement"
            self.operation_state["timeline"].append({
                "phase": "lateral_movement",
                "started_at": "now",
                "status": "active",
                "trigger": "multiple_flags_captured"
            })
        
        elif current_phase == "lateral_movement" and captured_count >= 10:
            self.operation_state["phase"] = "persistence"
            self.operation_state["timeline"].append({
                "phase": "persistence",
                "started_at": "now",
                "status": "active",
                "trigger": "domain_compromise_progress"
            })
    
    async def _evaluate_phase_transition(self):
        """Evaluate if we should transition to the next operation phase."""
        current_phase = self.operation_state["phase"]
        
        if current_phase == "reconnaissance":
            if len(self.operation_state["targets"]) > 0:
                self.operation_state["phase"] = "initial_access"
                self.operation_state["timeline"].append({
                    "phase": "initial_access",
                    "started_at": "now",
                    "status": "active"
                })
        
        elif current_phase == "initial_access":
            if len(self.operation_state["compromised_hosts"]) > 0:
                self.operation_state["phase"] = "lateral_movement"
                self.operation_state["timeline"].append({
                    "phase": "lateral_movement", 
                    "started_at": "now",
                    "status": "active"
                })

class MockAgent:
    """Mock agent for testing purposes."""
    
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
    
    async def execute_task(self, task: str, context: Dict) -> Dict:
        return {
            "agent": self.agent_type,
            "task": task,
            "status": "completed",
            "findings": [f"Mock finding from {self.agent_type}"],
            "recommendations": [f"Mock recommendation from {self.agent_type}"]
        }
