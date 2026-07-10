# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable capability-token auth plugin."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    DelegationError,
    RevokedAncestorError,
    ScopeEscalationError,
)


def _auth(now: float = 100.0) -> DelegatableAuth:
    return DelegatableAuth(secret=b"trust-root", clock=lambda: now, default_ttl=1000.0)


@pytest.mark.asyncio
async def test_satisfies_auth_protocol():
    from nest_core.layers.auth import Auth

    assert isinstance(_auth(), Auth)


@pytest.mark.asyncio
async def test_root_issue_and_verify():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read", "write"])
    ctx = await auth.verify(root)
    assert ctx.subject == AgentId("a1")
    assert sorted(ctx.scopes) == ["read", "write"]


@pytest.mark.asyncio
async def test_delegate_narrower_child():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    ctx = await auth.verify(child, presenter=AgentId("b"))
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_child_ttl_clamped_to_parent():
    auth = _auth(now=100.0)  # root exp = 1100
    root = await auth.issue(AgentId("a1"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100_000.0)
    ctx = await auth.verify(child, presenter=AgentId("b"))
    assert ctx.expires_at == 1100.0


@pytest.mark.asyncio
async def test_scope_escalation_rejected():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("b"), ["read", "admin"], ttl=60.0)


@pytest.mark.asyncio
async def test_audience_confusion_rejected():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    with pytest.raises(AudienceMismatchError):
        await auth.verify(child, presenter=AgentId("attacker"))


@pytest.mark.asyncio
async def test_cascading_revocation_reaches_grandchild():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read", "write"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=200.0)
    grandchild = await auth.delegate(child, AgentId("d"), ["read"], ttl=100.0)

    await auth.revoke(root)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(child, presenter=AgentId("b"))
    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild, presenter=AgentId("d"))


@pytest.mark.asyncio
async def test_middle_revocation_is_scoped():
    """Revoking a middle token kills its descendants but spares siblings/ancestors."""
    auth = _auth()
    root = await auth.issue(AgentId("A"), ["read", "write"])
    b = await auth.delegate(root, AgentId("B"), ["read", "write"], ttl=500.0)
    c = await auth.delegate(root, AgentId("C"), ["read"], ttl=500.0)  # sibling of B
    d = await auth.delegate(b, AgentId("D"), ["read"], ttl=200.0)  # child of B

    await auth.revoke(b)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(d, presenter=AgentId("D"))  # descendant dies
    assert (await auth.verify(c, presenter=AgentId("C"))).scopes == ["read"]  # sibling lives
    assert (await auth.verify(root)).subject == AgentId("A")  # ancestor lives


@pytest.mark.asyncio
async def test_forged_scope_rejected():
    auth = _auth()
    root = await auth.issue(AgentId("a1"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    payload, sig = str(child).rsplit("|", 1)
    forged = Token(payload.replace('"read"', '"admin"') + "|" + sig)
    with pytest.raises(DelegationError):
        await auth.verify(forged, presenter=AgentId("b"))


@pytest.mark.asyncio
async def test_malformed_token_rejected_cleanly():
    """Hostile-but-parseable payloads raise DelegationError, never KeyError."""
    auth = _auth()
    for junk in ["", "no-separator", "{}|", "[1,2]|", '{"sub":"a"}|sig', "not-json|deadbeef"]:
        with pytest.raises(DelegationError):
            await auth.verify(Token(junk))


@pytest.mark.asyncio
async def test_expired_token_rejected():
    now = {"t": 100.0}
    auth = DelegatableAuth(secret=b"s", clock=lambda: now["t"], default_ttl=10.0)
    root = await auth.issue(AgentId("a1"), ["read"])
    now["t"] = 200.0  # advance the clock past expiry
    with pytest.raises(DelegationError):
        await auth.verify(root)


@pytest.mark.asyncio
async def test_deterministic_under_fixed_clock():
    a1 = _auth()
    a2 = _auth()
    t1 = await a1.issue(AgentId("a1"), ["read", "write"])
    t2 = await a2.issue(AgentId("a1"), ["read", "write"])
    assert str(t1) == str(t2)


@pytest.mark.asyncio
async def test_one_shot_pay_analogue_still_works():
    """The base Auth surface (issue/verify/revoke) works without delegation."""
    auth = _auth()
    tok = await auth.issue(AgentId("solo"), ["read"])
    assert (await auth.verify(tok)).subject == AgentId("solo")
    await auth.revoke(tok)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(tok)
