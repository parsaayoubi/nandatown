# SPDX-License-Identifier: Apache-2.0
"""Delegated-auth scenario -- drive a delegation tree through revocation.

A coordinator issues itself a root capability token and delegates a narrower
token to each intermediary; every intermediary further delegates a read-only
token to its leaf agents -- three levels, all without going back to the
issuer. Leaves then present their token every round and broadcast whether
verification succeeded. Halfway through, the coordinator revokes the FIRST
intermediary's token: with a cascading-revocation plugin the whole first
subtree flips from ``work:ok`` to ``work:denied`` while every other subtree
(and the coordinator's root) keeps working.

All agents share ONE auth plugin instance (injected via the
``_agent_plugins`` override channel), because delegation semantics live in
the shared secret and revocation set -- separate instances could never
verify each other's tokens.

Example::

    agents = delegated_auth_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Token

_WORK = b"work"
_REVOKE = b"revoke"
_CAP_PREFIX = "cap:"


async def _verify(auth: Any, token: Token, presenter: AgentId) -> None:
    """Verify ``token`` as ``presenter``, tolerating presenter-less plugins."""
    try:
        await auth.verify(token, presenter=presenter)
    except TypeError:
        await auth.verify(token)


class CoordinatorAgent(StateMachineAgent):
    """Holds the root token, delegates to intermediaries, revokes one mid-run.

    Example::

        agent = CoordinatorAgent(AgentId("coordinator-0"), [AgentId("intermediary-0")], 5.0)
    """

    def __init__(
        self,
        agent_id: AgentId,
        intermediaries: list[AgentId],
        revoke_at: float,
    ) -> None:
        self._id = agent_id
        self._intermediaries = intermediaries
        self._revoke_at = revoke_at
        self._granted: dict[AgentId, Token] = {}

    async def on_start(self, ctx: AgentContext) -> None:
        """Issue the root, delegate to every intermediary, schedule the revocation.

        Example::

            await agent.on_start(ctx)
        """
        auth = ctx.plugins["auth"]
        root = await auth.issue(self._id, ["read", "write", "admin"])
        delegate = getattr(auth, "delegate", None)
        if delegate is None:
            await ctx.broadcast(b"delegation:unavailable")
            return
        for peer in self._intermediaries:
            token = await delegate(root, peer, ["read", "write"], 600.0)
            self._granted[peer] = token
            await ctx.send(peer, _CAP_PREFIX.encode() + str(token).encode())
        await ctx.schedule(self._revoke_at, _REVOKE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Revoke the first intermediary's token when the revoke tick fires.

        Example::

            await agent.on_message(ctx, agent_id, b"revoke")
        """
        if payload != _REVOKE or not self._granted:
            return
        auth = ctx.plugins["auth"]
        victim = self._intermediaries[0]
        await auth.revoke(self._granted[victim])
        await ctx.broadcast(f"revoked:{victim}".encode())


class IntermediaryAgent(StateMachineAgent):
    """Receives a delegated token and re-delegates read-only tokens to leaves.

    Example::

        agent = IntermediaryAgent(AgentId("intermediary-0"), [AgentId("leaf-0-0")])
    """

    def __init__(self, agent_id: AgentId, leaves: list[AgentId]) -> None:
        self._id = agent_id
        self._leaves = leaves

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On receiving a capability, attenuate it further for each leaf.

        Example::

            await agent.on_message(ctx, coordinator, b"cap:<token>")
        """
        text = payload.decode("utf-8", errors="replace")
        if not text.startswith(_CAP_PREFIX):
            return
        token = Token(text[len(_CAP_PREFIX) :])
        auth = ctx.plugins["auth"]
        for leaf in self._leaves:
            child = await auth.delegate(token, leaf, ["read"], 300.0)
            await ctx.send(leaf, _CAP_PREFIX.encode() + str(child).encode())


class LeafAgent(StateMachineAgent):
    """Presents its delegated token every round and reports the outcome.

    Example::

        agent = LeafAgent(AgentId("leaf-0-0"), rounds=10)
    """

    def __init__(self, agent_id: AgentId, rounds: int) -> None:
        self._id = agent_id
        self._rounds = rounds
        self._token: Token | None = None

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Store the received capability, then verify it on every work tick.

        All work ticks are scheduled upfront (like the memory scenario's
        gossip rounds) so a dropped tick cannot halt the reporting loop.

        Example::

            await agent.on_message(ctx, intermediary, b"cap:<token>")
        """
        text = payload.decode("utf-8", errors="replace")
        if text.startswith(_CAP_PREFIX):
            self._token = Token(text[len(_CAP_PREFIX) :])
            for round_idx in range(self._rounds):
                await ctx.schedule(float(round_idx + 1), _WORK)
            return
        if payload != _WORK or self._token is None:
            return
        auth = ctx.plugins["auth"]
        try:
            await _verify(auth, self._token, self._id)
        except Exception as exc:  # noqa: BLE001 - denial reason goes in the trace
            await ctx.broadcast(f"work:denied:{self._id}:{type(exc).__name__}".encode())
            return
        await ctx.broadcast(f"work:ok:{self._id}".encode())


def delegated_auth_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the coordinator / intermediary / leaf delegation tree.

    One shared auth plugin instance is injected into every agent via the
    ``_agent_plugins`` override channel; role counts come from the scenario's
    ``agents.roles`` block and leaves are split evenly across intermediaries.

    Example::

        agents = delegated_auth_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = int(task_config.get("rounds", 10))
    roles = {role.name: role.count for role in (config.agents.roles or [])}
    intermediary_count = max(1, roles.get("intermediary", 3))
    leaf_count = max(intermediary_count, roles.get("leaf", 12))
    leaves_per = leaf_count // intermediary_count

    # A fixed clock keeps token bytes (iat/exp, hence signatures) identical
    # across runs, so the trace replays byte-for-byte. Plugins without a
    # callable-clock kwarg (or without delegate at all) just use their default.
    auth_cls = plugins["auth"]
    shared_auth = None
    if hasattr(auth_cls, "delegate"):
        try:
            shared_auth = auth_cls(clock=lambda: 0.0)
        except TypeError:
            shared_auth = None
    if shared_auth is None:
        shared_auth = auth_cls()

    coordinator_id = AgentId("coordinator-0")
    intermediary_ids = [AgentId(f"intermediary-{i}") for i in range(intermediary_count)]

    agents: dict[AgentId, StateMachineAgent] = {}
    # Revoke halfway through the leaves' work rounds so the trace shows the
    # first subtree flipping ok -> denied while the others keep working.
    agents[coordinator_id] = CoordinatorAgent(
        coordinator_id, intermediary_ids, revoke_at=rounds / 2
    )
    for i, intermediary_id in enumerate(intermediary_ids):
        leaf_ids = [AgentId(f"leaf-{i}-{j}") for j in range(leaves_per)]
        agents[intermediary_id] = IntermediaryAgent(intermediary_id, leaf_ids)
        for leaf_id in leaf_ids:
            agents[leaf_id] = LeafAgent(leaf_id, rounds=rounds)

    plugins["_agent_plugins"] = {aid: {"auth": shared_auth} for aid in agents}
    return agents
