
# This file handles scope validation usecase.
import ipaddress
import re
from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.scope_validation_repository import (
    ScopeValidationRepository,
)


# Handle the scope validation use case.
@trace_usecase
class ScopeValidationUseCase:

    # Set up this object.
    def __init__(
        self,
        scope_validation_repository: ScopeValidationRepository,
        project_repository: ProjectRepository,
    ):
        self.scope_validation_repository = scope_validation_repository
        self.project_repository = project_repository

    # Create scope validation.
    def create_scope_validation(self, request):
        project = self.project_repository.get_project_by_id(request.project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        return self.scope_validation_repository.create_scope_validation(
            project_id=request.project_id,
            scope_rule_name=request.scope_rule_name,
            scope_type=request.scope_type,
            scope_value=request.scope_value,
            description=request.description,
            is_inclusive=request.is_inclusive,
            status=request.status,
        )

    # Get all scope validations.
    def get_all_scope_validations(self, project_id: int | None = None):
        if project_id is not None:
            project = self.project_repository.get_project_by_id(project_id)

            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found",
                )

            scope_validations = (
                self.scope_validation_repository.get_scope_validations_by_project_id(
                    project_id
                )
            )
        else:
            scope_validations = (
                self.scope_validation_repository.get_all_scope_validations()
            )

        return {
            "count": len(scope_validations),
            "scope_validations": scope_validations,
        }

    # Get scope validation by ID.
    def get_scope_validation_by_id(self, scope_validation_id: int):
        scope_validation = (
            self.scope_validation_repository.get_scope_validation_by_id(
                scope_validation_id
            )
        )

        if not scope_validation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scope validation rule not found",
            )

        return scope_validation

    # Update scope validation.
    def update_scope_validation(self, scope_validation_id: int, request):
        scope_validation = (
            self.scope_validation_repository.get_scope_validation_by_id(
                scope_validation_id
            )
        )

        if not scope_validation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scope validation rule not found",
            )

        update_data = request.model_dump(exclude_unset=True)

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update",
            )

        return self.scope_validation_repository.update_scope_validation(
            scope_validation,
            update_data,
        )

    # Delete scope validation.
    def delete_scope_validation(self, scope_validation_id: int):
        scope_validation = (
            self.scope_validation_repository.get_scope_validation_by_id(
                scope_validation_id
            )
        )

        if not scope_validation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scope validation rule not found",
            )

        deleted_rule = {
            "id": scope_validation.id,
            "project_id": scope_validation.project_id,
            "scope_rule_name": scope_validation.scope_rule_name,
        }

        self.scope_validation_repository.delete_scope_validation(scope_validation)

        return {
            "message": "Scope validation rule deleted successfully",
            "rule": deleted_rule,
        }

    # Check target in scope.
    def check_target_in_scope(self, project_id: int, target_value: str):
        project = self.project_repository.get_project_by_id(project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        scope_rules = (
            self.scope_validation_repository.get_scope_validations_by_project_id(
                project_id
            )
        )

        if not scope_rules:
            return {
                "is_in_scope": False,
                "matching_rules": [],
                "blocked_by_rules": ["No active scope rules configured"],
            }

        # Keep matching allow and deny rules separate so the response explains its decision.
        matching_inclusive_rules = []
        blocking_exclusive_rules = []

        for rule in scope_rules:
            if self._matches_scope_rule(target_value, rule):
                if rule.is_inclusive:
                    matching_inclusive_rules.append(rule.scope_rule_name)
                else:
                    blocking_exclusive_rules.append(rule.scope_rule_name)

        has_inclusive_rules = any(r.is_inclusive for r in scope_rules)
        has_exclusive_rules = any(not r.is_inclusive for r in scope_rules)

        # A matching exclusion always blocks; otherwise at least one inclusion must match.
        if has_exclusive_rules and blocking_exclusive_rules:
            is_in_scope = False
        elif has_inclusive_rules:
            is_in_scope = len(matching_inclusive_rules) > 0
        else:
            is_in_scope = True

        return {
            "is_in_scope": is_in_scope,
            "matching_rules": matching_inclusive_rules,
            "blocked_by_rules": blocking_exclusive_rules,
        }

    # Work with matches scope rule.
    def _matches_scope_rule(self, target_value: str, rule) -> bool:
        try:
            if rule.scope_type == "CIDR":
                return self._check_cidr(target_value, rule.scope_value)
            elif rule.scope_type == "IP_RANGE":
                return self._check_ip_range(target_value, rule.scope_value)
            elif rule.scope_type == "DOMAIN":
                return self._check_domain(target_value, rule.scope_value)
            elif rule.scope_type == "HOSTNAME":
                return self._check_hostname(target_value, rule.scope_value)
            elif rule.scope_type == "WILDCARD":
                return self._check_wildcard(target_value, rule.scope_value)
        # Invalid stored values are treated as non-matches instead of widening the scope.
        except Exception:
            return False

        return False

    # Check cidr.
    def _check_cidr(self, target: str, cidr: str) -> bool:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ip = ipaddress.ip_address(target)
            return ip in network
        except Exception:
            return False

    # Check ip range.
    def _check_ip_range(self, target: str, ip_range: str) -> bool:
        try:
            parts = ip_range.split("-")
            if len(parts) != 2:
                return False
            start_ip = ipaddress.ip_address(parts[0].strip())
            end_ip = ipaddress.ip_address(parts[1].strip())
            target_ip = ipaddress.ip_address(target)
            return start_ip <= target_ip <= end_ip
        except Exception:
            return False

    # Check domain.
    def _check_domain(self, target: str, domain: str) -> bool:
        domain = domain.lower()
        target = target.lower()
        return target == domain or target.endswith("." + domain)

    # Check hostname.
    def _check_hostname(self, target: str, hostname: str) -> bool:
        return target.lower() == hostname.lower()

    # Check wildcard.
    def _check_wildcard(self, target: str, pattern: str) -> bool:
        pattern = pattern.replace(".", r"\.")
        pattern = pattern.replace("*", ".*")
        regex = f"^{pattern}$"
        try:
            return re.match(regex, target, re.IGNORECASE) is not None
        except Exception:
            return False
