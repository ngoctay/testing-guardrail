from typing import Optional
from app.rules.base import BaseRule, RuleResult, Category

# Import built-in rules
from app.rules.security.secrets import HardcodedSecretsRule
from app.rules.security.sql_injection import SQLInjectionRule
from app.rules.security.command_injection import CommandInjectionRule
from app.rules.security.path_traversal import PathTraversalRule
from app.rules.security.insecure_deserialization import InsecureDeserializationRule
from app.rules.enterprise.naming import NamingConventionRule
from app.rules.enterprise.logging import LoggingRequirementsRule
from app.rules.enterprise.error_handling import ErrorHandlingRule

# Import industry-specific rules
from app.rules.industry.healthcare import (
    PHILoggingRule,
    EncryptionRequiredRule,
    HIPAAAuditTrailRule,
)
from app.rules.industry.telecom import (
    DataRetentionRule,
    SubscriberPrivacyRule,
)
from app.rules.industry.government import (
    AccessControlRule,
    FedRAMPAuditLoggingRule,
    EncryptionStandardsRule,
)


class RuleEngine:
    """Pluggable rule engine for running security and standards checks."""

    def __init__(self):
        self._rules: dict[str, BaseRule] = {}
        self._packs: dict[str, list[str]] = {}
        self._register_builtin_rules()
        self._register_builtin_packs()

    def _register_builtin_rules(self):
        """Register all built-in rules."""
        builtin_rules = [
            # Security rules
            HardcodedSecretsRule(),
            SQLInjectionRule(),
            CommandInjectionRule(),
            PathTraversalRule(),
            InsecureDeserializationRule(),
            # Enterprise standards rules
            NamingConventionRule(),
            LoggingRequirementsRule(),
            ErrorHandlingRule(),
            # Healthcare (HIPAA) rules
            PHILoggingRule(),
            EncryptionRequiredRule(),
            HIPAAAuditTrailRule(),
            # Telecom rules
            DataRetentionRule(),
            SubscriberPrivacyRule(),
            # Government (FedRAMP) rules
            AccessControlRule(),
            FedRAMPAuditLoggingRule(),
            EncryptionStandardsRule(),
        ]
        for rule in builtin_rules:
            self.register_rule(rule)

    def _register_builtin_packs(self):
        """Register built-in rule packs."""
        self._packs = {
            "default-security": [
                "SEC-001",  # Hardcoded secrets
                "SEC-002",  # SQL injection
                "SEC-003",  # Command injection
                "SEC-004",  # Path traversal
                "SEC-005",  # Insecure deserialization
            ],
            "enterprise-standards": [
                "STD-001",  # Naming conventions
                "STD-002",  # Logging requirements
                "STD-003",  # Error handling
            ],
            "healthcare": [
                "HIPAA-001",  # PHI logging prevention
                "HIPAA-002",  # PHI encryption required
                "HIPAA-003",  # PHI audit trail
            ],
            "telecom": [
                "TEL-001",  # Data retention compliance
                "TEL-002",  # Subscriber privacy protection
            ],
            "government": [
                "FED-001",  # Access control
                "FED-002",  # Audit logging
                "FED-003",  # Encryption standards
            ],
        }

    def register_rule(self, rule: BaseRule):
        """Register a new rule."""
        self._rules[rule.rule_id] = rule

    def unregister_rule(self, rule_id: str):
        """Unregister a rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]

    def register_pack(self, name: str, rule_ids: list[str]):
        """Register a rule pack."""
        self._packs[name] = rule_ids

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseRule]:
        """List all registered rules."""
        return list(self._rules.values())

    def list_packs(self) -> dict[str, list[str]]:
        """List all rule packs."""
        return self._packs.copy()

    def get_pack_rules(self, pack_name: str) -> list[BaseRule]:
        """Get all rules in a pack."""
        if pack_name not in self._packs:
            return []
        return [
            self._rules[rule_id]
            for rule_id in self._packs[pack_name]
            if rule_id in self._rules
        ]

    def run_rules(
        self,
        code: str,
        file_path: str,
        language: str,
        enabled_rules: Optional[list[str]] = None,
        enabled_packs: Optional[list[str]] = None,
        category_filter: Optional[Category] = None,
    ) -> list[RuleResult]:
        """
        Run rules against code.

        Args:
            code: Source code to check
            file_path: Path to the file
            language: Programming language
            enabled_rules: Specific rule IDs to run (if None, uses packs)
            enabled_packs: Rule pack names to use (if None, uses all rules)
            category_filter: Only run rules of this category

        Returns:
            List of all violations found
        """
        rules_to_run: list[BaseRule] = []

        if enabled_rules:
            # Run specific rules
            for rule_id in enabled_rules:
                if rule_id in self._rules:
                    rules_to_run.append(self._rules[rule_id])
        elif enabled_packs:
            # Run rules from specified packs
            for pack_name in enabled_packs:
                rules_to_run.extend(self.get_pack_rules(pack_name))
        else:
            # Run all rules
            rules_to_run = list(self._rules.values())

        # Apply category filter if specified
        if category_filter:
            rules_to_run = [r for r in rules_to_run if r.category == category_filter]

        # Run all applicable rules
        all_results: list[RuleResult] = []
        for rule in rules_to_run:
            if rule.supports_language(language):
                try:
                    results = rule.check(code, file_path, language)
                    all_results.extend(results)
                except Exception as e:
                    # Log error but continue with other rules
                    print(f"Error running rule {rule.rule_id}: {e}")

        # Deduplicate results based on rule_id, file_path, and line location
        return self._deduplicate_results(all_results)

    def _deduplicate_results(self, results: list[RuleResult]) -> list[RuleResult]:
        """Remove duplicate violations at the same location."""
        seen: set[tuple[str, str, int, int]] = set()
        unique_results: list[RuleResult] = []

        for result in results:
            key = (result.rule_id, result.file_path, result.line_start, result.line_end)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)

        return unique_results

    def run_security_rules(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> list[RuleResult]:
        """Convenience method to run only security rules."""
        return self.run_rules(
            code=code,
            file_path=file_path,
            language=language,
            category_filter=Category.SECURITY,
        )

    def run_standards_rules(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> list[RuleResult]:
        """Convenience method to run only standards rules."""
        return self.run_rules(
            code=code,
            file_path=file_path,
            language=language,
            category_filter=Category.STANDARDS,
        )
