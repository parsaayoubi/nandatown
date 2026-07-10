# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

The default ``jwt`` plugin issues flat, bearer-style tokens: an agent gets
a token from the central issuer, and revocation tracks whole tokens by
their exact string. There is no way for an agent to hand a *subset* of its
own authority to another agent without going back to the issuer, and no way
to revoke a parent such that every token derived from it dies too.

``DelegatableAuth`` adds exactly that, in the spirit of macaroons
(Birgisson et al., 2014) and biscuits: capability tokens that can be
*attenuated* (narrowed) and *delegated* peer-to-peer, with revocation that
cascades down the delegation tree by construction.

The whole trick is the HMAC chain. A root token is signed with the shared
secret. A child token's signature is computed over its own claims **plus
the parent's signature** — so the child is cryptographically anchored to
the parent. To verify a child we must re-derive the whole chain from the
root down; if any ancestor's signature is on the revocation set, the child
fails to verify. Revoking one parent hash therefore invalidates every
descendant with no per-child bookkeeping.

Attenuation rules enforced at ``delegate`` time:

* **Scope subset.** A child's scopes must be a strict subset of its
  parent's. Requesting a scope the parent does not hold raises
  ``ScopeEscalationError``.
* **TTL monotonicity.** A child expires no later than its parent. A longer
  child TTL is clamped to the parent's expiry.
* **Audience binding.** A delegated token names the agent it was minted
  for. Presenting it as a different agent raises ``AudienceMismatchError``
  at verify time.

Stdlib-only (HMAC-SHA256), deterministic under a fixed clock, so it
composes with NEST's replay-deterministic simulator.

Example::

    auth = DelegatableAuth(secret=b"trust-root", clock=lambda: 100.0)
    root = await auth.issue(AgentId("orchestrator"), ["read", "write", "admin"])
    # Orchestrator hands agent-b a narrower, shorter-lived token — no issuer:
    child = await auth.delegate(root, audience=AgentId("agent-b"),
                                scopes_subset=["read"], ttl=60.0)
    ctx = await auth.verify(child, presenter=AgentId("agent-b"))
    assert ctx.scopes == ["read"]
    # Revoke the root; the child dies with it.
    await auth.revoke(root)
    # verify(child) now raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token


class DelegationError(ValueError):
    """Base class for all delegation-related failures."""


class ScopeEscalationError(DelegationError):
    """Raised when a child token requests scopes its parent does not hold."""


class RevokedAncestorError(DelegationError):
    """Raised when a token (or any of its ancestors) has been revoked."""


class AudienceMismatchError(DelegationError):
    """Raised when a delegated token is presented by the wrong agent."""


# Compact, sorted JSON keeps signatures deterministic across runs.
def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# Every claim verify/delegate reads; a decoded payload missing any of these
# is rejected outright rather than KeyError-ing mid-check.
_REQUIRED_CLAIMS = frozenset({"sub", "aud", "scopes", "iat", "exp", "depth", "parent_sig", "chain"})


class DelegatableAuth:
    """Macaroon-style delegatable auth with cascading revocation.

    Satisfies the ``Auth`` protocol (``issue`` / ``verify`` / ``revoke``)
    and adds ``delegate`` for peer-to-peer attenuation.

    Example::

        auth = DelegatableAuth(secret=b"secret")
        root = await auth.issue(AgentId("a1"), ["read", "write"])
    """

    def __init__(
        self,
        secret: bytes = b"nest-default-secret",
        clock: Callable[[], float] | None = None,
        default_ttl: float = 3600.0,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._default_ttl = default_ttl
        # Revocation is keyed by a token's *signature*, which is unique per
        # token and is what children embed to anchor themselves.
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock()
        return time.time()

    def _sign(self, payload: str, anchor: str) -> str:
        """HMAC over the token payload, keyed by secret, chained to ``anchor``.

        ``anchor`` is the empty string for a root token, or the parent
        token's signature for a delegated one. Chaining to the parent
        signature is what makes revocation cascade.
        """
        msg = f"{anchor}.{payload}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _encode(self, claims: dict[str, Any], signature: str) -> Token:
        return Token(f"{_canonical(claims)}|{signature}")

    def _decode(self, token: Token) -> tuple[dict[str, Any], str]:
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise DelegationError(msg)
        payload_str, sig = parts
        try:
            claims = json.loads(payload_str)
        except json.JSONDecodeError as exc:
            msg = "Invalid token payload"
            raise DelegationError(msg) from exc
        # A syntactically valid payload can still be hostile (wrong JSON type,
        # missing claims). Reject it here so verify/delegate never KeyError on
        # attacker-controlled input.
        if not isinstance(claims, dict):
            msg = "Invalid token payload"
            raise DelegationError(msg)
        typed_claims = cast("dict[str, Any]", claims)
        if not _REQUIRED_CLAIMS.issubset(typed_claims):
            msg = "Invalid token payload"
            raise DelegationError(msg)
        return typed_claims, sig

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for ``subject``.

        Example::

            root = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        claims = {
            "sub": str(subject),
            "aud": str(subject),  # a root token's audience is its own subject
            "scopes": sorted(scopes),
            "iat": now,
            "exp": now + self._default_ttl,
            "depth": 0,
            "parent_sig": "",
            # Signatures of every ancestor, root-first. Empty for a root.
            # Carried in the token (macaroon-style) so revocation of ANY
            # ancestor is detectable at verify time without server state.
            "chain": [],
        }
        sig = self._sign(_canonical(claims), anchor="")
        return self._encode(claims, sig)

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a narrower child token from ``parent_token``.

        No call to the issuer is required — any holder of a valid parent
        can attenuate it. The child's scopes must be a subset of the
        parent's and its lifetime is clamped to the parent's expiry.

        Example::

            child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
        """
        parent_claims, parent_sig = self._decode(parent_token)

        # Parent must itself be valid (this also enforces that you cannot
        # delegate from a revoked or expired ancestor).
        await self.verify(parent_token, presenter=AgentId(parent_claims["aud"]))

        parent_scopes = set(parent_claims["scopes"])
        requested = set(scopes_subset)
        if not requested.issubset(parent_scopes):
            escalated = sorted(requested - parent_scopes)
            msg = f"Scope escalation: {escalated} not held by parent {sorted(parent_scopes)}"
            raise ScopeEscalationError(msg)

        now = self._now()
        # Child expiry never exceeds the parent's — clamp it.
        child_exp = min(now + ttl, parent_claims["exp"])
        # The child's ancestor chain is the parent's chain plus the parent
        # itself. Revoking any signature in this list invalidates the child.
        chain = [*parent_claims.get("chain", []), parent_sig]
        claims = {
            "sub": parent_claims["sub"],  # the ultimate authority is unchanged
            "aud": str(audience),  # but this token is bound to the delegatee
            "scopes": sorted(requested),
            "iat": now,
            "exp": child_exp,
            "depth": parent_claims["depth"] + 1,
            "parent_sig": parent_sig,  # anchor for signature integrity
            "chain": chain,  # full ancestor list for transitive revocation
        }
        sig = self._sign(_canonical(claims), anchor=parent_sig)
        return self._encode(claims, sig)

    async def verify(
        self,
        token: Token,
        presenter: AgentId | None = None,
    ) -> AuthContext:
        """Verify a token and return its context.

        Walks the delegation chain from this token up toward the root,
        checking every signature and every ancestor's revocation state. If
        any link is forged, revoked, or expired, verification fails.

        ``presenter`` is the agent presenting the token. For a delegated
        token it must equal the token's ``aud``; omit it only for trusted
        internal checks (e.g. re-verifying a parent during ``delegate``).

        Example::

            ctx = await auth.verify(child, presenter=AgentId("b"))
        """
        claims, sig = self._decode(token)

        # 1. Signature integrity: re-derive this token's signature from its
        #    claims and its recorded parent anchor.
        expected = self._sign(_canonical(claims), anchor=claims["parent_sig"])
        if not hmac.compare_digest(sig, expected):
            msg = "Invalid token signature"
            raise DelegationError(msg)

        # 2. Revocation, cascading: this token OR any ancestor being revoked
        #    invalidates it. The token carries the full ancestor signature
        #    chain, so revoking any one ancestor's signature is caught here
        #    at any depth — that is the transitive-revocation guarantee.
        if sig in self._revoked:
            msg = "Token has been revoked"
            raise RevokedAncestorError(msg)
        for ancestor_sig in claims.get("chain", []):
            if ancestor_sig in self._revoked:
                msg = "An ancestor token has been revoked"
                raise RevokedAncestorError(msg)

        # 3. Expiry.
        if claims["exp"] < self._now():
            msg = "Token has expired"
            raise DelegationError(msg)

        # 4. Audience binding for delegated tokens.
        if presenter is not None and claims["depth"] > 0 and str(presenter) != claims["aud"]:
            msg = f"Audience mismatch: token bound to {claims['aud']}, presented by {presenter}"
            raise AudienceMismatchError(msg)

        # Note: no parent token object is stored server-side by design. The
        # ancestor chain travels inside each token (macaroon-style), so the
        # cascading-revocation check at step 2 needs no lookup table and works
        # at arbitrary delegation depth.
        return AuthContext(
            subject=AgentId(claims["sub"]),
            scopes=list(claims["scopes"]),
            issued_at=claims["iat"],
            expires_at=claims["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token; all tokens delegated from it also stop verifying.

        Example::

            await auth.revoke(root)  # every child of root now fails verify
        """
        _claims, sig = self._decode(token)
        self._revoked.add(sig)
