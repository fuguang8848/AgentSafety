"""
Guardrails Module - Dual-layer filtering for input and output safety.

- InputGuardrail: Checks user input (emails, API keys, injection attacks)
- OutputGuardrail: Checks model output (sensitive info, password patterns)
- GuardrailManager: Unified management of input/output guardrails
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class GuardrailType(Enum):
    """Types of guardrail checks."""
    EMAIL = "email"
    API_KEY = "api_key"
    INJECTION = "injection"
    PII = "pii"
    PASSWORD = "password"
    SENSITIVE_DATA = "sensitive_data"


@dataclass
class GuardrailResult:
    """Result of a guardrail check."""
    passed: bool
    guardrail_type: GuardrailType
    message: str
    matched_content: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical


class InputGuardrail:
    """
    Input guardrail - validates and sanitizes user input.
    
    Checks:
    - Email addresses (potential information leakage)
    - API keys / secrets (exposure detection)
    - Injection attacks (SQL, command, prompt injection)
    """
    
    # Patterns for detection
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    )
    
    API_KEY_PATTERNS = [
        re.compile(r'(?:api[_-]?key|apikey|api_secret|secret[_-]?key)["\']?\s*[:=]\s*["\']?[\w-]{20,}', re.IGNORECASE),
        re.compile(r'Bearer\s+[A-Za-z0-9\-_~+/]+=*', re.IGNORECASE),
        re.compile(r'ghp_[A-Za-z0-9]{36}'),  # GitHub PAT
        re.compile(r'AKIA[A-Z0-9]{16}'),     # AWS Access Key
        re.compile(r'xox[baprs]-[A-Za-z0-9]{10,}'),  # Slack tokens
    ]
    
    INJECTION_PATTERNS = [
        # SQL Injection
        re.compile(r'(?:union\s+select|exec\s*\(|;\s*drop\s+table|--\s*$)', re.IGNORECASE),
        # Command Injection
        re.compile(r'[;&|`$]\s*(?:whoami|ls|cat|rm|wget|curl|nc\s)', re.IGNORECASE),
        # Prompt Injection
        re.compile(r'(?:ignore\s+(?:previous|all)|system\s*:|你现在是|你是)', re.IGNORECASE),
        re.compile(r'(?:忘记了|忘记之前的|disregard)', re.IGNORECASE),
    ]
    
    def __init__(self, strict: bool = False):
        """
        Initialize InputGuardrail.
        
        Args:
            strict: If True, use stricter matching rules
        """
        self.strict = strict
    
    def check(self, text: str) -> List[GuardrailResult]:
        """
        Check input text against all guardrail rules.
        
        Args:
            text: User input text to check
            
        Returns:
            List of GuardrailResult for each detected issue
        """
        results = []
        
        # Check for emails
        results.extend(self._check_emails(text))
        
        # Check for API keys
        results.extend(self._check_api_keys(text))
        
        # Check for injection attempts
        results.extend(self._check_injection(text))
        
        return results
    
    def _check_emails(self, text: str) -> List[GuardrailResult]:
        """Detect email addresses in text."""
        results = []
        matches = self.EMAIL_PATTERN.findall(text)
        if matches:
            # In strict mode, flag all emails; otherwise only multiple
            if self.strict or len(matches) > 1:
                results.append(GuardrailResult(
                    passed=False,
                    guardrail_type=GuardrailType.EMAIL,
                    message=f"Detected {len(matches)} email address(es) in input",
                    matched_content=", ".join(set(matches)),
                    severity="low" if len(matches) == 1 else "medium"
                ))
        return results
    
    def _check_api_keys(self, text: str) -> List[GuardrailResult]:
        """Detect API keys and secrets in text."""
        results = []
        for pattern in self.API_KEY_PATTERNS:
            match = pattern.search(text)
            if match:
                results.append(GuardrailResult(
                    passed=False,
                    guardrail_type=GuardrailType.API_KEY,
                    message="Potential API key or secret detected in input",
                    matched_content=match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
                    severity="critical"
                ))
                break  # One finding is enough
        return results
    
    def _check_injection(self, text: str) -> List[GuardrailResult]:
        """Detect injection attack patterns in text."""
        results = []
        for pattern in self.INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                injection_type = "sql" if "union" in match.group().lower() or "drop" in match.group().lower() else \
                                 "command" if any(x in match.group().lower() for x in ["whoami", "ls", "cat"]) else \
                                 "prompt"
                results.append(GuardrailResult(
                    passed=False,
                    guardrail_type=GuardrailType.INJECTION,
                    message=f"Potential {injection_type} injection pattern detected",
                    matched_content=match.group(),
                    severity="critical"
                ))
                break  # One finding is enough
        return results
    
    def sanitize(self, text: str) -> str:
        """
        Attempt to sanitize input by masking sensitive patterns.
        
        Args:
            text: Input text to sanitize
            
        Returns:
            Sanitized text (use check() first for full analysis)
        """
        # Mask emails (partially)
        sanitized = self.EMAIL_PATTERN.sub(lambda m: f"{m.group()[:2]}***@***", text)
        
        # Mask API keys
        for pattern in self.API_KEY_PATTERNS:
            sanitized = pattern.sub("[REDACTED_API_KEY]", sanitized)
        
        return sanitized


class OutputGuardrail:
    """
    Output guardrail - validates model output before delivery.
    
    Checks:
    - PII (names, phone numbers, addresses)
    - Password patterns
    - Sensitive data leakage
    """
    
    PHONE_PATTERN = re.compile(
        r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    )
    
    SSN_PATTERN = re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')
    
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\d{4}[-\s]?){2}\d{6}[-\s]?\d{5}?\b'
    )
    
    PASSWORD_PATTERN = re.compile(
        r'(?:password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']?[^\s"\'<>]{6,}',
        re.IGNORECASE
    )
    
    IP_PATTERN = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{2,39}\b'
    )
    
    def __init__(self, strict: bool = False):
        """
        Initialize OutputGuardrail.
        
        Args:
            strict: If True, use stricter matching rules
        """
        self.strict = strict
    
    def check(self, text: str) -> List[GuardrailResult]:
        """
        Check output text against all guardrail rules.
        
        Args:
            text: Model output text to check
            
        Returns:
            List of GuardrailResult for each detected issue
        """
        results = []
        
        # Check for PII
        results.extend(self._check_pii(text))
        
        # Check for password patterns
        results.extend(self._check_passwords(text))
        
        # Check for sensitive data
        results.extend(self._check_sensitive_data(text))
        
        return results
    
    def _check_pii(self, text: str) -> List[GuardrailResult]:
        """Detect PII in output."""
        results = []
        
        # Phone numbers
        phones = self.PHONE_PATTERN.findall(text)
        if len(phones) >= 3:  # Multiple phone numbers = likely real PII
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.PII,
                message=f"Multiple phone numbers detected ({len(phones)})",
                severity="high"
            ))
        
        # SSN
        if self.SSN_PATTERN.search(text):
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.PII,
                message="Potential SSN detected",
                severity="critical"
            ))
        
        # Credit cards
        if self.CREDIT_CARD_PATTERN.search(text):
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.PII,
                message="Potential credit card number detected",
                severity="critical"
            ))
        
        # IP addresses
        ips = self.IP_PATTERN.findall(text)
        if len(ips) >= 2:
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.PII,
                message=f"Multiple IP addresses detected ({len(ips)})",
                severity="medium"
            ))
        
        return results
    
    def _check_passwords(self, text: str) -> List[GuardrailResult]:
        """Detect password patterns in output."""
        results = []
        match = self.PASSWORD_PATTERN.search(text)
        if match:
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.PASSWORD,
                message="Potential password or secret detected in output",
                matched_content=match.group()[:30] + "..." if len(match.group()) > 30 else match.group(),
                severity="critical"
            ))
        return results
    
    def _check_sensitive_data(self, text: str) -> List[GuardrailResult]:
        """Detect other sensitive data patterns."""
        results = []
        
        # AWS keys
        if re.search(r'AKIA[A-Z0-9]{16}', text):
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.SENSITIVE_DATA,
                message="Potential AWS access key detected",
                severity="critical"
            ))
        
        # GitHub tokens
        if re.search(r'ghp_[A-Za-z0-9]{36}', text):
            results.append(GuardrailResult(
                passed=False,
                guardrail_type=GuardrailType.SENSITIVE_DATA,
                message="Potential GitHub token detected",
                severity="critical"
            ))
        
        return results
    
    def sanitize(self, text: str) -> str:
        """
        Attempt to sanitize output by masking sensitive patterns.
        
        Args:
            text: Output text to sanitize
            
        Returns:
            Sanitized text
        """
        sanitized = text
        
        # Redact SSN
        sanitized = self.SSN_PATTERN.sub("[REDACTED_SSN]", sanitized)
        
        # Redact credit cards
        sanitized = self.CREDIT_CARD_PATTERN.sub("[REDACTED_CC]", sanitized)
        
        # Redact passwords
        sanitized = self.PASSWORD_PATTERN.sub("[REDACTED_PASSWORD]", sanitized)
        
        # Redact AWS keys
        sanitized = re.sub(r'AKIA[A-Z0-9]{16}', '[REDACTED_AWS_KEY]', sanitized)
        
        # Redact GitHub tokens
        sanitized = re.sub(r'ghp_[A-Za-z0-9]{36}', '[REDACTED_GH_TOKEN]', sanitized)
        
        return sanitized


class GuardrailManager:
    """
    Unified manager for input and output guardrails.
    
    Provides coordinated filtering and policy enforcement.
    """
    
    def __init__(self, strict: bool = False, auto_sanitize: bool = True):
        """
        Initialize GuardrailManager.
        
        Args:
            strict: Use strict mode for all guardrails
            auto_sanitize: Automatically sanitize flagged content
        """
        self.input_guardrail = InputGuardrail(strict=strict)
        self.output_guardrail = OutputGuardrail(strict=strict)
        self.auto_sanitize = auto_sanitize
        self.strict = strict
        
        # Statistics
        self._stats = {
            "input_checks": 0,
            "input_failures": 0,
            "output_checks": 0,
            "output_failures": 0,
        }
    
    def check_input(self, text: str) -> Tuple[bool, List[GuardrailResult]]:
        """
        Check input text through input guardrail.
        
        Args:
            text: User input to check
            
        Returns:
            Tuple of (passed, results)
        """
        self._stats["input_checks"] += 1
        results = self.input_guardrail.check(text)
        
        passed = len(results) == 0
        if not passed:
            self._stats["input_failures"] += 1
        
        return passed, results
    
    def check_output(self, text: str) -> Tuple[bool, List[GuardrailResult]]:
        """
        Check output text through output guardrail.
        
        Args:
            text: Model output to check
            
        Returns:
            Tuple of (passed, results)
        """
        self._stats["output_checks"] += 1
        results = self.output_guardrail.check(text)
        
        passed = len(results) == 0
        if not passed:
            self._stats["output_failures"] += 1
        
        return passed, results
    
    def process(self, input_text: str, output_text: Optional[str] = None) -> Dict[str, Any]:
        """
        Process input and optionally output through guardrails.
        
        Args:
            input_text: User input to check
            output_text: Optional model output to check
            
        Returns:
            Dict with check results and any sanitized content
        """
        result = {
            "input_passed": True,
            "input_results": [],
            "output_passed": True,
            "output_results": [],
            "sanitized_input": None,
            "sanitized_output": None,
        }
        
        # Check input
        input_passed, input_results = self.check_input(input_text)
        result["input_passed"] = input_passed
        result["input_results"] = [
            {"type": r.guardrail_type.value, "message": r.message, "severity": r.severity}
            for r in input_results
        ]
        
        if self.auto_sanitize and not input_passed:
            result["sanitized_input"] = self.input_guardrail.sanitize(input_text)
        
        # Check output if provided
        if output_text is not None:
            output_passed, output_results = self.check_output(output_text)
            result["output_passed"] = output_passed
            result["output_results"] = [
                {"type": r.guardrail_type.value, "message": r.message, "severity": r.severity}
                for r in output_results
            ]
            
            if self.auto_sanitize and not output_passed:
                result["sanitized_output"] = self.output_guardrail.sanitize(output_text)
        
        return result
    
    def get_stats(self) -> Dict[str, int]:
        """Get guardrail statistics."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self._stats = {
            "input_checks": 0,
            "input_failures": 0,
            "output_checks": 0,
            "output_failures": 0,
        }
