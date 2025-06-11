"""
Tool Selector Agent - Default agent that analyzes requests and selects appropriate tools.
"""

import subprocess
import json
from typing import Dict, List, Optional
from .base_agent import Agent

class ToolSelectorAgent(Agent):
    """
    Agent that receives requests from other agents and selects the most appropriate tool.
    Provides recursive --help command parsing for complex tools.
    """
    
    def __init__(self):
        super().__init__(name="tool_selector_agent")
        
        self.available_tools = [
            "nmap", "masscan", "rustscan",
            "gobuster", "ffuf", "dirb",
            "sqlmap", "burpsuite", "nikto",
            "metasploit", "msfconsole", "msfvenom",
            "john", "hashcat", "hydra",
            "wireshark", "tcpdump", "netcat",
            "curl", "wget", "whatweb",
            "enum4linux", "smbclient", "rpcclient",
            "bloodhound", "crackmapexec", "impacket"
        ]
    
    async def select_tool(self, request: str, context: Dict) -> Dict:
        """
        Select the most appropriate tool for a given request.
        
        Args:
            request: The task description from another agent
            context: Additional context about the target/environment
            
        Returns:
            Dictionary containing tool selection and usage information
        """
        tool_category = self._categorize_request(request)
        recommended_tools = self._get_tools_for_category(tool_category)
        
        tool_help = {}
        for tool in recommended_tools[:3]:  # Limit to top 3 tools
            help_info = await self._get_tool_help(tool)
            if help_info:
                tool_help[tool] = help_info
        
        return {
            "category": tool_category,
            "recommended_tools": recommended_tools,
            "tool_help": tool_help,
            "selection_reasoning": self._explain_selection(request, recommended_tools)
        }
    
    def _categorize_request(self, request: str) -> str:
        """Categorize the request to determine tool type needed."""
        request_lower = request.lower()
        
        if any(word in request_lower for word in ["scan", "port", "discovery", "enumerate"]):
            return "reconnaissance"
        elif any(word in request_lower for word in ["exploit", "vulnerability", "cve"]):
            return "exploitation"
        elif any(word in request_lower for word in ["web", "http", "directory", "subdomain"]):
            return "web_testing"
        elif any(word in request_lower for word in ["password", "hash", "crack", "brute"]):
            return "password_attacks"
        elif any(word in request_lower for word in ["lateral", "pivot", "movement"]):
            return "lateral_movement"
        else:
            return "general"
    
    def _get_tools_for_category(self, category: str) -> List[str]:
        """Get recommended tools for a specific category."""
        tool_mapping = {
            "reconnaissance": ["nmap", "masscan", "rustscan", "enum4linux"],
            "exploitation": ["metasploit", "msfconsole", "sqlmap"],
            "web_testing": ["gobuster", "ffuf", "nikto", "whatweb"],
            "password_attacks": ["john", "hashcat", "hydra"],
            "lateral_movement": ["crackmapexec", "impacket", "bloodhound"],
            "general": ["nmap", "metasploit", "gobuster"]
        }
        return tool_mapping.get(category, ["nmap"])
    
    async def _get_tool_help(self, tool: str) -> Optional[Dict]:
        """
        Get comprehensive help information for a tool, including subcommands.
        """
        try:
            result = subprocess.run([tool, "--help"], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                for flag in ["-h", "help", "-help"]:
                    result = subprocess.run([tool, flag], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        break
            
            if result.returncode == 0:
                help_text = result.stdout or result.stderr
                
                subcommands = self._extract_subcommands(help_text)
                subcommand_help = {}
                
                for subcmd in subcommands[:5]:  # Limit to 5 subcommands
                    subcmd_help = await self._get_subcommand_help(tool, subcmd)
                    if subcmd_help:
                        subcommand_help[subcmd] = subcmd_help
                
                return {
                    "main_help": help_text,
                    "subcommands": subcommand_help,
                    "usage_examples": self._generate_usage_examples(tool, help_text)
                }
        
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None
        
        return None
    
    async def _get_subcommand_help(self, tool: str, subcommand: str) -> Optional[str]:
        """Get help for a specific subcommand."""
        try:
            result = subprocess.run([tool, subcommand, "--help"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout or result.stderr
        except:
            pass
        return None
    
    def _extract_subcommands(self, help_text: str) -> List[str]:
        """Extract subcommands from help text."""
        subcommands = []
        lines = help_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('-') and ' ' in line:
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith('-'):
                    subcommands.append(parts[0])
        
        return list(set(subcommands))[:10]  # Remove duplicates, limit to 10
    
    def _generate_usage_examples(self, tool: str, help_text: str) -> List[str]:
        """Generate practical usage examples for the tool."""
        examples = {
            "nmap": [
                "nmap -sS -sV -O target_ip",
                "nmap -sC -sV -p- target_ip",
                "nmap --script vuln target_ip"
            ],
            "gobuster": [
                "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
                "gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt"
            ],
            "sqlmap": [
                "sqlmap -u 'http://target/page?id=1' --dbs",
                "sqlmap -u 'http://target/page?id=1' --dump -D database_name"
            ]
        }
        return examples.get(tool, [f"{tool} --help"])
    
    def _explain_selection(self, request: str, tools: List[str]) -> str:
        """Provide reasoning for tool selection."""
        return f"Based on the request '{request}', I recommend {', '.join(tools[:3])} as they are most suitable for this type of task."
