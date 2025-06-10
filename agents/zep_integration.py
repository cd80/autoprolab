"""
Zep Knowledge Base Integration - Integrates Zep for persistent memory and knowledge management.
"""

import asyncio
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from agno.agent import Agent
from agno.tools.zep import ZepTools

class ZepKnowledgeAgent(Agent):
    """
    Agent responsible for integrating Zep knowledge base for persistent memory.
    Manages agent memories, target intelligence, and operational knowledge.
    """
    
    def __init__(self):
        super().__init__(
            name="zep_knowledge_agent",
            description="Manages persistent memory and knowledge using Zep",
            instructions="""
            You are the Zep knowledge agent responsible for:
            1. Managing persistent memory for all agents
            2. Storing and retrieving target intelligence
            3. Maintaining operational knowledge base
            4. Tracking agent interactions and learnings
            5. Providing contextual information to other agents
            6. Managing session data and conversation history
            """
        )
        
        # Initialize Zep tools for different agent sessions
        self.agent_sessions = {}
        self.session_prefix = "autoprolab_"
    
    async def initialize_knowledge_base(self) -> Dict:
        """
        Initialize the Zep knowledge base with agent sessions.
        
        Returns:
            Initialization results
        """
        print("🧠 Initializing Zep knowledge base...")
        
        results = {
            "sessions_created": [],
            "errors": []
        }
        
        try:
            # Initialize sessions for different agent types
            agent_types = [
                "team_leader", "network_scanner", "recon_agent", 
                "initial_access", "web_hacking", "tool_selector"
            ]
            
            for agent_type in agent_types:
                try:
                    session_id = f"{self.session_prefix}{agent_type}"
                    zep_tools = ZepTools(
                        user_id="autoprolab_system",
                        session_id=session_id,
                        api_key=os.getenv('ZEP_API_KEY'),
                        add_instructions=True
                    )
                    
                    self.agent_sessions[agent_type] = zep_tools
                    results["sessions_created"].append(agent_type)
                    
                    await self._add_initial_context(agent_type)
                    
                except Exception as e:
                    results["errors"].append(f"Error creating session for {agent_type}: {str(e)}")
            
        except Exception as e:
            results["errors"].append(f"Initialization error: {str(e)}")
        
        return results
    
    async def store_target_intelligence(self, target_data: Dict, agent_type: str = "team_leader") -> Dict:
        """
        Store target intelligence in the knowledge base.
        
        Args:
            target_data: Target information to store
            
        Returns:
            Storage results
        """
        print(f"📊 Storing target intelligence for {target_data.get('hostname', 'unknown')}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent type: {agent_type}",
                    "target": target_data.get("hostname", "unknown")
                }
            
            content = f"TARGET INTELLIGENCE: {json.dumps(target_data, indent=2)}"
            
            result = zep_tools.add_zep_message(
                role="assistant",
                content=content
            )
            
            return {
                "success": True,
                "result": result,
                "target": target_data.get("hostname", "unknown"),
                "agent_type": agent_type
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target_data.get("hostname", "unknown")
            }
    
    async def store_vulnerability_data(self, vulnerability_data: Dict, agent_type: str = "recon_agent") -> Dict:
        """
        Store vulnerability information in the knowledge base.
        
        Args:
            vulnerability_data: Vulnerability information to store
            
        Returns:
            Storage results
        """
        print(f"🔍 Storing vulnerability data: {vulnerability_data.get('name', 'unknown')}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent type: {agent_type}",
                    "vulnerability": vulnerability_data.get("name", "unknown")
                }
            
            content = f"VULNERABILITY DISCOVERED: {json.dumps(vulnerability_data, indent=2)}"
            
            result = zep_tools.add_zep_message(
                role="assistant",
                content=content
            )
            
            return {
                "success": True,
                "result": result,
                "vulnerability": vulnerability_data.get("name", "unknown"),
                "agent_type": agent_type
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerability": vulnerability_data.get("name", "unknown")
            }
    
    async def store_agent_memory(self, agent_name: str, memory_data: Dict, role: str = "assistant") -> Dict:
        """
        Store agent memory and interaction data.
        
        Args:
            agent_name: Name of the agent
            session_id: Session identifier
            memory_data: Memory data to store
            
        Returns:
            Storage results
        """
        print(f"💭 Storing memory for agent {agent_name}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_name)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent: {agent_name}",
                    "agent": agent_name
                }
            
            content = f"AGENT MEMORY [{datetime.now().isoformat()}]: {json.dumps(memory_data, indent=2)}"
            
            result = zep_tools.add_zep_message(
                role=role,
                content=content
            )
            
            return {
                "success": True,
                "result": result,
                "agent": agent_name
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "agent": agent_name
            }
    
    async def retrieve_target_intelligence(self, query: str, agent_type: str = "team_leader") -> Dict:
        """
        Retrieve target intelligence based on query.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            Retrieved intelligence
        """
        print(f"🔎 Retrieving target intelligence for: {query}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent type: {agent_type}",
                    "query": query,
                    "results": [],
                    "count": 0
                }
            
            # Search memory for target intelligence
            search_query = f"TARGET INTELLIGENCE {query}"
            results = zep_tools.search_zep_memory(
                query=search_query,
                search_scope="messages"
            )
            
            return {
                "success": True,
                "query": query,
                "results": results,
                "agent_type": agent_type
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "query": query,
                "results": [],
                "count": 0
            }
    
    async def retrieve_vulnerability_data(self, query: str, agent_type: str = "recon_agent") -> Dict:
        """
        Retrieve vulnerability data based on query.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            Retrieved vulnerability data
        """
        print(f"🔍 Retrieving vulnerability data for: {query}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent type: {agent_type}",
                    "query": query,
                    "results": [],
                    "count": 0
                }
            
            # Search memory for vulnerability data
            search_query = f"VULNERABILITY {query}"
            results = zep_tools.search_zep_memory(
                query=search_query,
                search_scope="messages"
            )
            
            return {
                "success": True,
                "query": query,
                "results": results,
                "agent_type": agent_type
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "query": query,
                "results": [],
                "count": 0
            }
    
    async def get_agent_context(self, agent_name: str, memory_type: str = "context") -> Dict:
        """
        Get contextual information for an agent from its memory.
        
        Args:
            agent_name: Name of the agent
            session_id: Session identifier
            limit: Maximum number of memory items
            
        Returns:
            Agent context
        """
        print(f"🧠 Getting context for agent {agent_name}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_name)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent: {agent_name}",
                    "agent": agent_name
                }
            
            memory = zep_tools.get_zep_memory(memory_type=memory_type)
            
            return {
                "success": True,
                "agent": agent_name,
                "memory_type": memory_type,
                "memory": memory
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "agent": agent_name
            }
    
    async def store_operation_data(self, operation_data: Dict, agent_type: str = "team_leader") -> Dict:
        """
        Store operation data and results.
        
        Args:
            operation_data: Operation information to store
            
        Returns:
            Storage results
        """
        print(f"📋 Storing operation data: {operation_data.get('operation_id', 'unknown')}")
        
        try:
            # Get the appropriate Zep tools for the agent
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return {
                    "success": False,
                    "error": f"No session found for agent type: {agent_type}",
                    "operation_id": operation_data.get("operation_id", "unknown")
                }
            
            content = f"OPERATION DATA: {json.dumps(operation_data, indent=2)}"
            
            result = zep_tools.add_zep_message(
                role="assistant",
                content=content
            )
            
            return {
                "success": True,
                "result": result,
                "operation_id": operation_data.get("operation_id", "unknown"),
                "agent_type": agent_type
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "operation_id": operation_data.get("operation_id", "unknown")
            }
    
    async def _add_initial_context(self, agent_type: str):
        """Add initial context for an agent session."""
        try:
            zep_tools = self.agent_sessions.get(agent_type)
            if not zep_tools:
                return
            
            context_messages = {
                "team_leader": "I am the team leader agent responsible for orchestrating red team operations.",
                "network_scanner": "I am the network scanner agent responsible for discovering live hosts and network topology.",
                "recon_agent": "I am the reconnaissance agent responsible for detailed target enumeration and vulnerability identification.",
                "initial_access": "I am the initial access agent responsible for gaining initial foothold on target systems.",
                "web_hacking": "I am the web hacking agent responsible for web application security testing and exploitation.",
                "tool_selector": "I am the tool selector agent responsible for choosing appropriate cybersecurity tools for tasks."
            }
            
            initial_message = context_messages.get(agent_type, f"I am the {agent_type} agent.")
            
            zep_tools.add_zep_message(
                role="assistant",
                content=initial_message
            )
            
        except Exception as e:
            print(f"Error adding initial context for {agent_type}: {e}")
    
    async def _populate_default_knowledge(self):
        """Populate default knowledge base with common cybersecurity information."""
        try:
            team_leader_tools = self.agent_sessions.get("team_leader")
            if team_leader_tools:
                techniques = [
                    "SQL Injection: Injection of malicious SQL code into application queries",
                    "Cross-Site Scripting (XSS): Injection of malicious scripts into web applications", 
                    "Buffer Overflow: Overwriting memory buffers to execute arbitrary code",
                    "Directory Traversal: Accessing files outside the web root directory",
                    "Command Injection: Executing arbitrary commands on the target system"
                ]
                
                for technique in techniques:
                    team_leader_tools.add_zep_message(
                        role="assistant",
                        content=f"ATTACK TECHNIQUE: {technique}"
                    )
            
        except Exception as e:
            print(f"Error populating default knowledge: {e}")
    
    async def search_knowledge(self, query: str, agent_types: List[str] = None, search_scope: str = "messages") -> Dict:
        """
        Search across agent memories for knowledge.
        
        Args:
            query: Search query
            agent_types: List of agent types to search (None for all)
            search_scope: Scope of search ("messages" or "summary")
            
        Returns:
            Search results
        """
        print(f"🔍 Searching knowledge base for: {query}")
        
        results = {
            "query": query,
            "results": [],
            "agents_searched": []
        }
        
        try:
            if agent_types is None:
                agent_types = list(self.agent_sessions.keys())
            
            for agent_type in agent_types:
                try:
                    zep_tools = self.agent_sessions.get(agent_type)
                    if not zep_tools:
                        continue
                    
                    search_results = zep_tools.search_zep_memory(
                        query=query,
                        search_scope=search_scope
                    )
                    
                    results["agents_searched"].append(agent_type)
                    
                    if search_results:
                        results["results"].append({
                            "agent_type": agent_type,
                            "results": search_results
                        })
                            
                except Exception as e:
                    print(f"Error searching agent {agent_type}: {e}")
                    continue
            
            results["success"] = True
            results["count"] = len(results["results"])
            
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
        
        return results
    
    def get_agent_zep_tools(self, agent_type: str) -> Optional[ZepTools]:
        """
        Get ZepTools instance for a specific agent type.
        
        Args:
            agent_type: Type of agent
            
        Returns:
            ZepTools instance or None
        """
        return self.agent_sessions.get(agent_type)
