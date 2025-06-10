"""
Base Agent class to replace Agno framework dependency for testing purposes.
Provides minimal agent functionality to allow system testing.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

class Agent:
    """
    Base agent class that provides core functionality for autonomous agents.
    Replaces agno.agent.Agent for testing purposes.
    """
    
    def __init__(self, name: str = None):
        self.name = name or self.__class__.__name__
        self.logger = logging.getLogger(self.name)
        self.state = {}
        self.tools = []
        self.memory = []
        
    async def execute(self, task: str, context: Dict = None) -> Dict:
        """Execute a task with given context."""
        self.logger.info(f"Executing task: {task}")
        
        try:
            result = await self._process_task(task, context or {})
            self._log_execution(task, result)
            return result
        except Exception as e:
            self.logger.error(f"Task execution failed: {e}")
            return {"error": str(e), "success": False}
    
    async def _process_task(self, task: str, context: Dict) -> Dict:
        """Override this method in subclasses to implement specific agent logic."""
        return {
            "task": task,
            "context": context,
            "timestamp": datetime.now().isoformat(),
            "success": True,
            "agent": self.name
        }
    
    def _log_execution(self, task: str, result: Dict):
        """Log task execution for debugging and monitoring."""
        self.memory.append({
            "timestamp": datetime.now().isoformat(),
            "task": task,
            "result": result,
            "agent": self.name
        })
    
    def get_state(self) -> Dict:
        """Get current agent state."""
        return {
            "name": self.name,
            "state": self.state,
            "memory_count": len(self.memory),
            "tools_count": len(self.tools)
        }
    
    def update_state(self, updates: Dict):
        """Update agent state."""
        self.state.update(updates)
        self.logger.debug(f"State updated: {updates}")
    
    async def coordinate_with(self, other_agent: 'Agent', message: str) -> Dict:
        """Coordinate with another agent."""
        self.logger.info(f"Coordinating with {other_agent.name}: {message}")
        
        coordination_result = {
            "from_agent": self.name,
            "to_agent": other_agent.name,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "success": True
        }
        
        self.memory.append(coordination_result)
        other_agent.memory.append(coordination_result)
        
        return coordination_result
