"""
MCP Server Manager - Automatically sets up MCP servers using OpenAI API to read READMEs.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import requests
from typing import Dict, List, Optional, Any
from pathlib import Path
from agno.agent import Agent
import openai

class McpServerManager(Agent):
    """
    Agent responsible for automatically setting up MCP servers.
    Uses OpenAI API to read and understand MCP server READMEs for setup instructions.
    """
    
    def __init__(self):
        super().__init__(
            name="mcp_server_manager",
            description="Automatically sets up MCP servers by reading their documentation",
            instructions="""
            You are the MCP server manager responsible for:
            1. Discovering available MCP servers from repositories
            2. Reading and understanding MCP server documentation
            3. Automatically setting up MCP servers based on their requirements
            4. Configuring MCP client connections
            5. Testing MCP server functionality
            6. Managing MCP server lifecycle
            """
        )
        
        self.openai_client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.mcp_servers_dir = Path.home() / "mcp_servers"
        self.mcp_config_file = Path.home() / ".mcp" / "config.json"
        self.installed_servers = {}
        
        self.mcp_server_repos = [
            "modelcontextprotocol/servers",
            "modelcontextprotocol/python-sdk",
            "anthropics/mcp-server-git",
            "anthropics/mcp-server-filesystem",
            "anthropics/mcp-server-sqlite"
        ]
    
    async def discover_mcp_servers(self) -> Dict:
        """
        Discover available MCP servers from known repositories.
        
        Returns:
            Dictionary of discovered MCP servers
        """
        print("🔍 Discovering available MCP servers...")
        
        discovered_servers = {
            "repositories": [],
            "servers": [],
            "categories": {}
        }
        
        for repo in self.mcp_server_repos:
            try:
                repo_info = await self._analyze_repository(repo)
                if repo_info:
                    discovered_servers["repositories"].append(repo_info)
                    
                    servers = repo_info.get("servers", [])
                    discovered_servers["servers"].extend(servers)
                    
                    for server in servers:
                        category = server.get("category", "general")
                        if category not in discovered_servers["categories"]:
                            discovered_servers["categories"][category] = []
                        discovered_servers["categories"][category].append(server)
                        
            except Exception as e:
                print(f"Error analyzing repository {repo}: {e}")
                continue
        
        return discovered_servers
    
    async def auto_setup_mcp_server(self, server_name: str, repo_url: str = None) -> Dict:
        """
        Automatically set up an MCP server by reading its documentation.
        
        Args:
            server_name: Name of the MCP server
            repo_url: Repository URL (optional)
            
        Returns:
            Setup results
        """
        print(f"🚀 Auto-setting up MCP server: {server_name}")
        
        setup_result = {
            "server_name": server_name,
            "status": "failed",
            "steps_completed": [],
            "configuration": {},
            "errors": []
        }
        
        try:
            repo_path = await self._clone_server_repository(server_name, repo_url)
            if not repo_path:
                setup_result["errors"].append("Failed to clone repository")
                return setup_result
            
            setup_result["steps_completed"].append("repository_cloned")
            
            documentation = await self._read_server_documentation(repo_path)
            if not documentation:
                setup_result["errors"].append("No documentation found")
                return setup_result
            
            setup_result["steps_completed"].append("documentation_read")
            
            setup_instructions = await self._analyze_setup_instructions(server_name, documentation)
            if not setup_instructions:
                setup_result["errors"].append("Failed to analyze setup instructions")
                return setup_result
            
            setup_result["steps_completed"].append("instructions_analyzed")
            
            execution_result = await self._execute_setup_steps(repo_path, setup_instructions)
            setup_result["steps_completed"].extend(execution_result.get("completed_steps", []))
            setup_result["errors"].extend(execution_result.get("errors", []))
            
            if execution_result.get("success"):
                config_result = await self._configure_mcp_client(server_name, setup_instructions)
                if config_result.get("success"):
                    setup_result["configuration"] = config_result.get("configuration", {})
                    setup_result["steps_completed"].append("client_configured")
                    setup_result["status"] = "success"
                else:
                    setup_result["errors"].extend(config_result.get("errors", []))
            
            if setup_result["status"] == "success":
                test_result = await self._test_mcp_server(server_name)
                if test_result.get("success"):
                    setup_result["steps_completed"].append("server_tested")
                else:
                    setup_result["errors"].append("Server test failed")
                    setup_result["status"] = "partial"
            
        except Exception as e:
            setup_result["errors"].append(f"Unexpected error: {str(e)}")
        
        return setup_result
    
    async def setup_recommended_servers(self) -> Dict:
        """
        Set up a recommended set of MCP servers for red teaming.
        
        Returns:
            Setup results for all recommended servers
        """
        print("📦 Setting up recommended MCP servers for red teaming...")
        
        recommended_servers = [
            {
                "name": "filesystem",
                "repo": "anthropics/mcp-server-filesystem",
                "description": "File system operations"
            },
            {
                "name": "sqlite",
                "repo": "anthropics/mcp-server-sqlite", 
                "description": "SQLite database operations"
            },
            {
                "name": "git",
                "repo": "anthropics/mcp-server-git",
                "description": "Git repository operations"
            }
        ]
        
        results = {
            "total_servers": len(recommended_servers),
            "successful_setups": 0,
            "failed_setups": 0,
            "server_results": {}
        }
        
        for server in recommended_servers:
            server_name = server["name"]
            repo_url = f"https://github.com/{server['repo']}"
            
            setup_result = await self.auto_setup_mcp_server(server_name, repo_url)
            results["server_results"][server_name] = setup_result
            
            if setup_result["status"] == "success":
                results["successful_setups"] += 1
                self.installed_servers[server_name] = setup_result
            else:
                results["failed_setups"] += 1
        
        return results
    
    async def _analyze_repository(self, repo_path: str) -> Optional[Dict]:
        """Analyze a repository to extract MCP server information."""
        try:
            api_url = f"https://api.github.com/repos/{repo_path}"
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                repo_data = response.json()
                
                contents_url = f"https://api.github.com/repos/{repo_path}/contents"
                contents_response = requests.get(contents_url, timeout=10)
                
                servers = []
                if contents_response.status_code == 200:
                    contents = contents_response.json()
                    
                    for item in contents:
                        if item["type"] == "dir" and any(keyword in item["name"].lower() 
                                                       for keyword in ["server", "mcp"]):
                            servers.append({
                                "name": item["name"],
                                "path": item["path"],
                                "category": self._categorize_server(item["name"])
                            })
                
                return {
                    "repository": repo_path,
                    "name": repo_data["name"],
                    "description": repo_data.get("description", ""),
                    "language": repo_data.get("language", ""),
                    "servers": servers,
                    "clone_url": repo_data["clone_url"]
                }
            
            return None
            
        except Exception as e:
            print(f"Error analyzing repository {repo_path}: {e}")
            return None
    
    def _categorize_server(self, server_name: str) -> str:
        """Categorize MCP server based on name."""
        name_lower = server_name.lower()
        
        if any(keyword in name_lower for keyword in ["file", "fs", "filesystem"]):
            return "filesystem"
        elif any(keyword in name_lower for keyword in ["db", "database", "sql"]):
            return "database"
        elif any(keyword in name_lower for keyword in ["git", "version"]):
            return "version_control"
        elif any(keyword in name_lower for keyword in ["web", "http", "api"]):
            return "web"
        elif any(keyword in name_lower for keyword in ["security", "pentest", "hack"]):
            return "security"
        else:
            return "general"
    
    async def _clone_server_repository(self, server_name: str, repo_url: str) -> Optional[Path]:
        """Clone MCP server repository."""
        try:
            self.mcp_servers_dir.mkdir(parents=True, exist_ok=True)
            
            server_path = self.mcp_servers_dir / server_name
            
            if server_path.exists():
                import shutil
                shutil.rmtree(server_path)
            
            cmd = ["git", "clone", repo_url, str(server_path)]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return server_path
            else:
                print(f"Git clone failed: {stderr.decode()}")
                return None
                
        except Exception as e:
            print(f"Error cloning repository: {e}")
            return None
    
    async def _read_server_documentation(self, repo_path: Path) -> Optional[str]:
        """Read server documentation files."""
        try:
            documentation = ""
            
            doc_files = ["README.md", "README.rst", "README.txt", "INSTALL.md", "SETUP.md"]
            
            for doc_file in doc_files:
                doc_path = repo_path / doc_file
                if doc_path.exists():
                    with open(doc_path, 'r', encoding='utf-8') as f:
                        documentation += f"\n\n=== {doc_file} ===\n"
                        documentation += f.read()
            
            package_files = ["package.json", "pyproject.toml", "requirements.txt", "setup.py"]
            
            for package_file in package_files:
                package_path = repo_path / package_file
                if package_path.exists():
                    with open(package_path, 'r', encoding='utf-8') as f:
                        documentation += f"\n\n=== {package_file} ===\n"
                        documentation += f.read()
            
            return documentation if documentation.strip() else None
            
        except Exception as e:
            print(f"Error reading documentation: {e}")
            return None
    
    async def _analyze_setup_instructions(self, server_name: str, documentation: str) -> Optional[Dict]:
        """Use OpenAI to analyze setup instructions from documentation."""
        try:
            prompt = f"""
            Analyze the following MCP server documentation for '{server_name}' and extract setup instructions.
            
            Please provide a JSON response with the following structure:
            {{
                "dependencies": ["list", "of", "dependencies"],
                "installation_steps": ["step 1", "step 2", "step 3"],
                "configuration": {{
                    "config_file": "path/to/config",
                    "required_settings": {{"key": "value"}},
                    "optional_settings": {{"key": "value"}}
                }},
                "startup_command": "command to start the server",
                "test_command": "command to test the server",
                "port": "default port if applicable",
                "environment_variables": {{"VAR_NAME": "description"}}
            }}
            
            Documentation:
            {documentation}
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert at reading technical documentation and extracting setup instructions. Always respond with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            content = response.choices[0].message.content
            
            try:
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                setup_instructions = json.loads(content.strip())
                return setup_instructions
                
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON response: {e}")
                print(f"Response content: {content}")
                return None
                
        except Exception as e:
            print(f"Error analyzing setup instructions: {e}")
            return None
    
    async def _execute_setup_steps(self, repo_path: Path, setup_instructions: Dict) -> Dict:
        """Execute the setup steps for the MCP server."""
        result = {
            "success": False,
            "completed_steps": [],
            "errors": []
        }
        
        try:
            original_cwd = os.getcwd()
            os.chdir(repo_path)
            
            dependencies = setup_instructions.get("dependencies", [])
            if dependencies:
                for dep in dependencies:
                    try:
                        if dep.startswith("npm"):
                            cmd = ["npm", "install"]
                        elif dep.startswith("pip"):
                            cmd = ["pip", "install", "-r", "requirements.txt"]
                        elif dep.startswith("poetry"):
                            cmd = ["poetry", "install"]
                        else:
                            cmd = dep.split()
                        
                        process = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        
                        stdout, stderr = await process.communicate()
                        
                        if process.returncode == 0:
                            result["completed_steps"].append(f"dependency_installed: {dep}")
                        else:
                            result["errors"].append(f"Failed to install {dep}: {stderr.decode()}")
                            
                    except Exception as e:
                        result["errors"].append(f"Error installing {dep}: {str(e)}")
            
            installation_steps = setup_instructions.get("installation_steps", [])
            for step in installation_steps:
                try:
                    cmd = step.split()
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode == 0:
                        result["completed_steps"].append(f"installation_step: {step}")
                    else:
                        result["errors"].append(f"Failed step '{step}': {stderr.decode()}")
                        
                except Exception as e:
                    result["errors"].append(f"Error executing step '{step}': {str(e)}")
            
            if len(result["errors"]) == 0 or len(result["completed_steps"]) > 0:
                result["success"] = True
            
        except Exception as e:
            result["errors"].append(f"Unexpected error during setup: {str(e)}")
        finally:
            os.chdir(original_cwd)
        
        return result
    
    async def _configure_mcp_client(self, server_name: str, setup_instructions: Dict) -> Dict:
        """Configure MCP client to connect to the server."""
        result = {
            "success": False,
            "configuration": {},
            "errors": []
        }
        
        try:
            config_dir = self.mcp_config_file.parent
            config_dir.mkdir(parents=True, exist_ok=True)
            
            if self.mcp_config_file.exists():
                with open(self.mcp_config_file, 'r') as f:
                    config = json.load(f)
            else:
                config = {"servers": {}}
            
            server_config = {
                "command": setup_instructions.get("startup_command", ""),
                "args": [],
                "env": setup_instructions.get("environment_variables", {})
            }
            
            port = setup_instructions.get("port")
            if port:
                server_config["port"] = port
            
            config["servers"][server_name] = server_config
            
            with open(self.mcp_config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            result["success"] = True
            result["configuration"] = server_config
            
        except Exception as e:
            result["errors"].append(f"Error configuring MCP client: {str(e)}")
        
        return result
    
    async def _test_mcp_server(self, server_name: str) -> Dict:
        """Test MCP server functionality."""
        result = {
            "success": False,
            "tests": [],
            "errors": []
        }
        
        try:
            cmd = ["mcp-cli", "server", "list"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if server_name in output:
                    test_result = {
                        "test": "server_listed",
                        "status": "passed",
                        "message": f"Server {server_name} appears in server list"
                    }
                    result["tests"].append(test_result)
                    result["success"] = True
                else:
                    test_result = {
                        "test": "server_listed",
                        "status": "failed",
                        "message": f"Server {server_name} not found in server list"
                    }
                    result["tests"].append(test_result)
            else:
                result["errors"].append(f"mcp-cli command failed: {stderr.decode()}")
            
        except Exception as e:
            result["errors"].append(f"Error testing server: {str(e)}")
        
        return result
    
    async def list_installed_servers(self) -> Dict:
        """List all installed MCP servers."""
        return {
            "installed_servers": list(self.installed_servers.keys()),
            "server_details": self.installed_servers,
            "config_file": str(self.mcp_config_file)
        }
    
    async def remove_mcp_server(self, server_name: str) -> Dict:
        """Remove an installed MCP server."""
        result = {
            "success": False,
            "message": ""
        }
        
        try:
            if server_name in self.installed_servers:
                del self.installed_servers[server_name]
            
            if self.mcp_config_file.exists():
                with open(self.mcp_config_file, 'r') as f:
                    config = json.load(f)
                
                if server_name in config.get("servers", {}):
                    del config["servers"][server_name]
                    
                    with open(self.mcp_config_file, 'w') as f:
                        json.dump(config, f, indent=2)
            
            server_path = self.mcp_servers_dir / server_name
            if server_path.exists():
                import shutil
                shutil.rmtree(server_path)
            
            result["success"] = True
            result["message"] = f"Server {server_name} removed successfully"
            
        except Exception as e:
            result["message"] = f"Error removing server: {str(e)}"
        
        return result
