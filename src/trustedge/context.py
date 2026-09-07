"""The context object handed to each provider-specific grading rubric."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .conditions import ConditionSet
from .models import IamExport, Role, TrustPrincipal, TrustStatement


@dataclass
class GradingContext:
    """Everything a rubric needs to grade one principal on one statement.

    A rubric is deliberately given the whole export: deciding whether a
    cross-account principal is "external" needs the account id, and deciding
    whether an OIDC issuer is even registered needs the provider list.
    """

    export: IamExport
    role: Role
    statement: TrustStatement
    principal: TrustPrincipal
    conditions: ConditionSet

    @property
    def account_id(self) -> Optional[str]:
        return self.role.account_id or self.export.account_id

    @property
    def issuer(self) -> str:
        """Normalised OIDC issuer or provider id for the principal, if any."""
        return self.principal.provider_id or ""

    def condition_key(self, claim: str) -> str:
        """Build the ``<provider>:<claim>`` condition key for this principal.

        AWS defines OIDC federation condition keys as "the name of the OIDC
        provider (token.actions.githubusercontent.com) followed by a claim
        (:aud)".
        """
        return "%s:%s" % (self.issuer, claim)
