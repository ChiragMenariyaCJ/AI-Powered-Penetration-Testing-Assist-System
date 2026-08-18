from typing import Optional


class AIRecommendationEngine:
    """AI Engine for generating attack recommendations based on vulnerabilities"""

    # MITRE ATT&CK Technique Mapping
    MITRE_TECHNIQUES = {
        "Initial Access": {
            "T1190": {"name": "Exploit Public-Facing Application", "risk": "CRITICAL"},
            "T1199": {"name": "Trusted Relationship", "risk": "HIGH"},
            "T1200": {"name": "Hardware Additions", "risk": "MEDIUM"},
        },
        "Execution": {
            "T1059": {"name": "Command and Scripting Interpreter", "risk": "CRITICAL"},
            "T1059.001": {"name": "PowerShell", "risk": "HIGH"},
            "T1059.003": {"name": "Windows Command Shell", "risk": "HIGH"},
            "T1203": {"name": "Exploitation for Client Execution", "risk": "CRITICAL"},
        },
        "Persistence": {
            "T1098": {"name": "Account Manipulation", "risk": "HIGH"},
            "T1197": {"name": "Browser Extensions", "risk": "MEDIUM"},
            "T1547": {"name": "Boot or Logon Autostart Execution", "risk": "HIGH"},
        },
        "Privilege Escalation": {
            "T1548": {"name": "Abuse Elevation Control Mechanism", "risk": "CRITICAL"},
            "T1547.001": {"name": "Registry Run Keys", "risk": "HIGH"},
            "T1053": {"name": "Scheduled Task/Job", "risk": "HIGH"},
        },
        "Defense Evasion": {
            "T1548": {"name": "Abuse Elevation Control Mechanism", "risk": "HIGH"},
            "T1197": {"name": "Browser Extensions", "risk": "MEDIUM"},
            "T1140": {"name": "Deobfuscate/Decode Files", "risk": "MEDIUM"},
        },
    }

    # Service-to-Attack Mapping
    SERVICE_ATTACK_MAPPING = {
        "SSH": {
            "techniques": ["T1110", "T1021.004"],
            "attacks": [
                {
                    "name": "Brute Force Attack",
                    "complexity": "LOW",
                    "tools": ["hydra", "medusa", "ssh-audit"],
                    "steps": [
                        "Enumerate valid usernames",
                        "Dictionary or brute force attack",
                        "Gain shell access",
                    ],
                }
            ],
        },
        "SMB": {
            "techniques": ["T1570", "T1021.002"],
            "attacks": [
                {
                    "name": "EternalBlue Exploitation",
                    "complexity": "LOW",
                    "tools": ["metasploit", "EternalBlue POC"],
                    "steps": [
                        "Identify SMB version",
                        "Check vulnerability",
                        "Exploit using EternalBlue",
                        "Gain system access",
                    ],
                },
                {
                    "name": "Credential Relay Attack",
                    "complexity": "MEDIUM",
                    "tools": ["responder", "ntlm_relay"],
                    "steps": [
                        "Set up LLMNR/NBNS listener",
                        "Intercept credentials",
                        "Relay credentials to target",
                    ],
                },
            ],
        },
        "RDP": {
            "techniques": ["T1110", "T1021.001"],
            "attacks": [
                {
                    "name": "RDP Brute Force",
                    "complexity": "LOW",
                    "tools": ["crowbar", "hydra"],
                    "steps": [
                        "Scan for RDP service",
                        "Brute force credentials",
                        "Gain remote access",
                    ],
                },
                {
                    "name": "CVE-2019-0708 BlueKeep",
                    "complexity": "MEDIUM",
                    "tools": ["metasploit", "bluekeep POC"],
                    "steps": [
                        "Identify vulnerable RDP version",
                        "Exploit BlueKeep",
                        "Execute arbitrary code",
                    ],
                },
            ],
        },
        "MYSQL": {
            "techniques": ["T1110", "T1021.003"],
            "attacks": [
                {
                    "name": "SQL Injection",
                    "complexity": "MEDIUM",
                    "tools": ["sqlmap", "burp"],
                    "steps": [
                        "Identify SQL injection point",
                        "Extract database",
                        "Dump credentials",
                        "Privilege escalation",
                    ],
                },
                {
                    "name": "Default Credentials",
                    "complexity": "LOW",
                    "tools": ["mysql-client"],
                    "steps": [
                        "Try default credentials",
                        "Gain database access",
                        "Extract sensitive data",
                    ],
                },
            ],
        },
        "HTTP": {
            "techniques": ["T1190", "T1203"],
            "attacks": [
                {
                    "name": "Web Application Exploit",
                    "complexity": "HIGH",
                    "tools": ["burp", "zaproxy", "metasploit"],
                    "steps": [
                        "Enumerate web application",
                        "Identify vulnerabilities",
                        "Exploit vulnerability",
                        "Gain shell access",
                    ],
                }
            ],
        },
        "DNS": {
            "techniques": ["T1071.004"],
            "attacks": [
                {
                    "name": "DNS Cache Poisoning",
                    "complexity": "HIGH",
                    "tools": ["scapy", "dnsmasq"],
                    "steps": [
                        "Intercept DNS query",
                        "Inject malicious response",
                        "Redirect to attacker site",
                    ],
                }
            ],
        },
    }

    CRITICAL_SERVICES = {
        "SMB": "CRITICAL",
        "RDP": "CRITICAL",
        "MySQL": "CRITICAL",
        "PostgreSQL": "CRITICAL",
        "MongoDB": "CRITICAL",
        "Redis": "CRITICAL",
        "SSH": "HIGH",
        "HTTP": "HIGH",
        "HTTPS": "MEDIUM",
    }

    def __init__(self):
        pass

    def generate_recommendations(self, vulnerability: dict) -> list[dict]:
        """
        Generate attack recommendations for a vulnerability
        
        Args:
            vulnerability: Dict with host, port, service, severity, etc.
            
        Returns:
            List of recommendation dicts
        """
        recommendations = []

        service = vulnerability.get("service", "").upper()
        severity = vulnerability.get("severity", "MEDIUM").upper()
        port = vulnerability.get("port", 0)

        # Get base recommendations for service
        if service in self.SERVICE_ATTACK_MAPPING:
            service_attacks = self.SERVICE_ATTACK_MAPPING[service]

            for attack in service_attacks.get("attacks", []):
                recommendation = {
                    "attack_technique": attack["name"],
                    "mitre_technique_id": service_attacks.get("techniques", [None])[0],
                    "exploitation_method": self._format_exploitation_method(attack),
                    "risk_level": self._calculate_risk_level(
                        severity, attack.get("complexity")
                    ),
                    "priority": self._calculate_priority(severity, port),
                    "likelihood": self._calculate_likelihood(
                        severity, attack.get("complexity")
                    ),
                    "impact": self._calculate_impact(severity),
                    "prerequisites": self._get_prerequisites(service, attack),
                    "tools_required": ", ".join(attack.get("tools", [])),
                    "execution_steps": self._format_execution_steps(
                        attack.get("steps", [])
                    ),
                    "post_exploitation": self._get_post_exploitation(service),
                    "confidence_score": self._calculate_confidence(severity),
                }
                recommendations.append(recommendation)

        else:
            # Generic recommendations for unknown services
            recommendation = {
                "attack_technique": f"Generic Service Enumeration ({service})",
                "mitre_technique_id": "T1046",
                "exploitation_method": f"Enumerate the {service} service on port {port} to identify version, configuration, and potential weaknesses.",
                "risk_level": "MEDIUM",
                "priority": 5,
                "likelihood": 60,
                "impact": 40,
                "prerequisites": "Network access to target",
                "tools_required": "nmap, service-specific tools",
                "execution_steps": "1. Connect to service\n2. Banner grabbing\n3. Identify version\n4. Search for CVEs",
                "post_exploitation": "Research and exploit identified vulnerabilities",
                "confidence_score": 60,
            }
            recommendations.append(recommendation)

        return recommendations

    def _format_exploitation_method(self, attack: dict) -> str:
        """Format exploitation method from attack data"""
        steps = attack.get("steps", [])
        if steps:
            return ". ".join(steps)
        return "Execute the attack following the documented techniques"

    def _calculate_risk_level(self, severity: str, complexity: str) -> str:
        """Calculate risk level based on severity and complexity"""
        risk_mapping = {
            ("CRITICAL", "LOW"): "CRITICAL",
            ("CRITICAL", "MEDIUM"): "CRITICAL",
            ("CRITICAL", "HIGH"): "HIGH",
            ("HIGH", "LOW"): "CRITICAL",
            ("HIGH", "MEDIUM"): "HIGH",
            ("HIGH", "HIGH"): "HIGH",
            ("MEDIUM", "LOW"): "HIGH",
            ("MEDIUM", "MEDIUM"): "MEDIUM",
            ("MEDIUM", "HIGH"): "MEDIUM",
            ("LOW", "LOW"): "MEDIUM",
            ("LOW", "MEDIUM"): "LOW",
            ("LOW", "HIGH"): "LOW",
        }
        complexity = complexity or "MEDIUM"
        return risk_mapping.get((severity, complexity), "MEDIUM")

    def _calculate_priority(self, severity: str, port: int) -> int:
        """Calculate priority (1-10) based on severity and port"""
        severity_priority = {
            "CRITICAL": 9,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
        }
        priority = severity_priority.get(severity, 5)

        # Adjust for common risky ports
        if port in [22, 135, 139, 445, 3306, 5432, 27017, 6379]:
            priority = min(10, priority + 1)

        return priority

    def _calculate_likelihood(self, severity: str, complexity: str) -> int:
        """Calculate attack success likelihood (0-100)"""
        base_likelihood = {
            "CRITICAL": 85,
            "HIGH": 70,
            "MEDIUM": 50,
            "LOW": 30,
        }
        likelihood = base_likelihood.get(severity, 50)

        complexity_factor = {
            "LOW": 10,
            "MEDIUM": -5,
            "HIGH": -20,
        }
        likelihood += complexity_factor.get(complexity, 0)

        return max(10, min(100, likelihood))

    def _calculate_impact(self, severity: str) -> int:
        """Calculate potential impact (0-100)"""
        impact_mapping = {
            "CRITICAL": 95,
            "HIGH": 80,
            "MEDIUM": 60,
            "LOW": 40,
            "INFO": 20,
        }
        return impact_mapping.get(severity, 50)

    def _calculate_confidence(self, severity: str) -> int:
        """Calculate recommendation confidence score (0-100)"""
        confidence_mapping = {
            "CRITICAL": 95,
            "HIGH": 85,
            "MEDIUM": 75,
            "LOW": 65,
            "INFO": 50,
        }
        return confidence_mapping.get(severity, 70)

    def _get_prerequisites(self, service: str, attack: dict) -> str:
        """Get prerequisites for attack"""
        base_prereqs = "Network access to target service"

        additional = {
            "SSH": "Valid username enumeration",
            "SMB": "NetBIOS name resolution",
            "RDP": "Network connectivity to RDP port",
            "MYSQL": "Network access to MySQL port",
            "HTTP": "Web browser or HTTP client",
        }

        return f"{base_prereqs}. {additional.get(service, '')}"

    def _format_execution_steps(self, steps: list) -> str:
        """Format execution steps"""
        if not steps:
            return "Follow standard exploitation procedures"
        return "\n".join([f"{i+1}. {step}" for i, step in enumerate(steps)])

    def _get_post_exploitation(self, service: str) -> str:
        """Get post-exploitation steps"""
        post_exploit = {
            "SSH": "Maintain persistence, escalate privileges, pivot to other systems",
            "SMB": "Extract credentials, dump SAM database, establish remote access",
            "RDP": "Establish persistence, extract credentials, explore network",
            "MYSQL": "Extract sensitive data, create backdoor user, maintain persistence",
            "HTTP": "Establish shell access, escalate privileges, pivot network",
        }
        return post_exploit.get(
            service,
            "Establish persistent access, extract sensitive data, pivot to other systems",
        )

    def calculate_attack_score(self, vulnerability: dict) -> dict:
        """Calculate risk score for an attack"""
        severity = vulnerability.get("severity", "MEDIUM").upper()
        port = vulnerability.get("port", 0)
        service = vulnerability.get("service", "UNKNOWN").upper()

        base_scores = {
            "CRITICAL": 85,
            "HIGH": 70,
            "MEDIUM": 50,
            "LOW": 30,
        }

        risk_score = base_scores.get(severity, 50)

        # Adjust for critical services
        if service in self.CRITICAL_SERVICES:
            risk_score = min(100, risk_score + 15)

        complexity = "MEDIUM"
        if service in ["SSH", "RDP"]:
            complexity = "LOW"
        elif service in ["HTTP"]:
            complexity = "HIGH"

        return {
            "risk_score": risk_score,
            "attack_complexity": complexity,
            "required_privileges": "NONE"
            if service in ["HTTP", "DNS"]
            else "LOW",
            "success_probability": self._calculate_likelihood(severity, complexity),
        }
