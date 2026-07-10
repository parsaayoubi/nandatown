# Delegatable Capability Tokens (auth layer)

## What this is

An `auth`-layer plugin for Nanda Town that lets an agent hand a **subset** of
its own authority to another agent — without going back to the central
issuer — and revoke it such that the revocation **cascades** to every token
derived from it. Modelled on macaroons (Birgisson et al., 2014).

Registered name: `("auth", "delegatable")`.
Implementation: `nest_plugins_reference.auth.delegatable:DelegatableAuth`.
Dependencies: none (stdlib `hmac` / `hashlib` / `json` only). Deterministic
under a fixed clock, so it replays inside Tier-1 simulations.

## When to use it

Use `delegatable` instead of the default `jwt` plugin whenever an agent needs
to sub-delegate a narrowed, time-bounded capability to another agent and be
able to withdraw it cleanly — e.g. an orchestrator renting a tool to a
worker agent for ten minutes, then revoking access.

## API

It satisfies the standard `Auth` protocol (`issue` / `verify` / `revoke`) and
adds `delegate`.

### `await auth.issue(subject, scopes) -> Token`
Mint a root token for `subject` holding `scopes` (a list of strings).

### `await auth.delegate(parent_token, audience, scopes_subset, ttl) -> Token`
Mint a child token from `parent_token`, bound to `audience` (an `AgentId`),
holding `scopes_subset`, expiring after `ttl` seconds.
- `scopes_subset` **must** be a subset of the parent's scopes, else
  `ScopeEscalationError`.
- The child's expiry is clamped to never exceed the parent's.
- Any holder of a valid parent can call this — no issuer round-trip.

### `await auth.verify(token, presenter=None) -> AuthContext`
Verify signature, expiry, cascading revocation, and audience.
- Pass `presenter` (the `AgentId` presenting the token). For a delegated
  token it must equal the token's audience, else `AudienceMismatchError`.
- If the token or **any ancestor** was revoked, raises `RevokedAncestorError`.

### `await auth.revoke(token) -> None`
Revoke a token. Every token delegated from it (at any depth) stops
verifying on the next `verify` call.

## Example

```python
from nest_plugins_reference.auth.delegatable import DelegatableAuth
from nest_core.types import AgentId

auth = DelegatableAuth(secret=b"trust-root", clock=lambda: 100.0)

root = await auth.issue(AgentId("orchestrator"), ["read", "write", "admin"])

# Hand agent-b a read-only, 60-second token — no issuer involved:
child = await auth.delegate(root, AgentId("agent-b"), ["read"], ttl=60.0)
ctx = await auth.verify(child, presenter=AgentId("agent-b"))
assert ctx.scopes == ["read"]

# Revoke the root; the child dies with it:
await auth.revoke(root)
# await auth.verify(child, presenter=AgentId("agent-b"))  -> RevokedAncestorError
```

## Try it in a scenario

```bash
nest run delegated_auth        # if you copied the scenario into scenarios/
# or point any scenario at it by editing its layers block:
#   auth: delegatable
```

## Guarantees and limits

- **Scope monotonicity:** a child never holds a scope its parent lacked.
- **TTL monotonicity:** a child never outlives its parent.
- **Cascading revocation:** revoking any token invalidates its whole subtree,
  at arbitrary depth, with no per-child bookkeeping (the ancestor chain
  travels inside each token).
- **Audience binding:** a delegated token presented by the wrong agent is
  rejected.
- Delegation is a strict tree (single parent per token), not a DAG.
- In-process only; no network token introspection.
