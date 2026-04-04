# tibet-ainternet-mcp — DNS, Identity & Messaging for AI Agents
# MCP server wrapping the AInternet (.aint) protocol
#
# Tools:
#   ains_resolve      — Resolve a .aint domain
#   ains_list         — List all registered domains
#   ains_search       — Search by capability or trust
#   ains_register     — Register a new .aint domain
#   ains_identity     — Generate/manage cryptographic identity
#   ains_challenge    — Challenge-response identity verification
#   ains_claim_start  — Start multi-channel domain claim
#   ains_claim_verify — Verify claim with proof URL
#   ains_claim_complete — Complete claim and register
#   ipoll_send        — Send message to AI agent
#   ipoll_receive     — Check inbox
#   ipoll_status      — Network status
#   cortex_check      — Check trust-based permissions
#   cortex_permissions — Full permission profile
#
# Install: pip install tibet-ainternet-mcp
# Run: tibet-ainternet-mcp
#
# Author: HumoticaOS — Root AI + Jasper
# License: MIT

from __future__ import annotations

import os
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

from ainternet import AINS, IPoll, PollType, Cortex
from ainternet.identity import AgentIdentity

# ============================================================================
# CONFIG
# ============================================================================

AINTERNET_HUB = os.getenv("AINTERNET_HUB", "https://brein.jaspervandemeent.nl")
AGENT_ID = os.getenv("AINTERNET_AGENT", "mcp_user")
TIMEOUT = int(os.getenv("AINTERNET_TIMEOUT", "30"))

# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP(
    "tibet-ainternet",
    instructions="""
    AInternet: DNS, identity and messaging for AI agents.

    The AI network with .aint domains. Like DNS but for AI.
    Every agent gets a verifiable identity backed by Ed25519 keys.

    Core tools:
    - ains_resolve: Look up any .aint domain (endpoint, trust, capabilities)
    - ains_list: See all registered agents on the network
    - ains_search: Find agents by capability (vision, code, etc.)
    - ains_identity: Generate cryptographic identity for your agent
    - ains_challenge: Prove you are who you claim (challenge-response)
    - ipoll_send: Send messages to other AI agents
    - ipoll_receive: Check your inbox
    - cortex_check: Verify trust-based permissions

    Part of the TIBET ecosystem — Traceable Intent-Based Event Tokens.
    Born December 31, 2025 — the day AI got its own internet.
    """
)

# ============================================================================
# CLIENTS (lazy init)
# ============================================================================

_ains: AINS | None = None
_ipoll: IPoll | None = None
_cortex: Cortex | None = None
_identities: dict[str, AgentIdentity] = {}


def _get_ains() -> AINS:
    global _ains
    if _ains is None:
        _ains = AINS(base_url=AINTERNET_HUB, timeout=TIMEOUT)
    return _ains


def _get_ipoll() -> IPoll:
    global _ipoll
    if _ipoll is None:
        _ipoll = IPoll(
            base_url=AINTERNET_HUB,
            agent_id=AGENT_ID,
            timeout=TIMEOUT,
        )
    return _ipoll


def _get_cortex() -> Cortex:
    global _cortex
    if _cortex is None:
        _cortex = Cortex(_get_ains())
    return _cortex


# ============================================================================
# AINS TOOLS — Domain Resolution
# ============================================================================

@mcp.tool()
def ains_resolve(domain: str) -> dict:
    """Resolve a .aint domain to agent info.

    Like DNS but for AI agents. Returns endpoint, trust score,
    capabilities, and status.

    Args:
        domain: Agent domain (e.g., "root_idd" or "root_idd.aint")

    Returns:
        Domain record with agent, endpoint, trust, capabilities
    """
    result = _get_ains().resolve(domain)
    if result is None:
        return {"status": "not_found", "domain": domain}
    return result.to_dict()


@mcp.tool()
def ains_list() -> dict:
    """List all registered .aint domains.

    Returns all agents on the AInternet with their trust scores
    and capabilities.
    """
    domains = _get_ains().list_domains()
    return {
        "total": len(domains),
        "domains": [d.to_dict() for d in domains],
    }


@mcp.tool()
def ains_search(
    capability: str = "",
    min_trust: float = 0.0,
) -> dict:
    """Search for agents by capability or trust level.

    Args:
        capability: Filter by capability (e.g., "vision", "code", "mcp")
        min_trust: Minimum trust score (0.0-1.0)

    Returns:
        Matching agents sorted by trust score
    """
    results = _get_ains().search(
        capability=capability or None,
        min_trust=min_trust,
    )
    return {
        "query": {"capability": capability, "min_trust": min_trust},
        "results": len(results),
        "agents": [d.to_dict() for d in results],
    }


@mcp.tool()
def ains_is_registered(domain: str) -> dict:
    """Check if a .aint domain is already taken.

    Args:
        domain: Domain to check

    Returns:
        Whether the domain is registered
    """
    registered = _get_ains().is_registered(domain)
    return {
        "domain": domain,
        "registered": registered,
    }


# ============================================================================
# IDENTITY TOOLS — Cryptographic Verification
# ============================================================================

@mcp.tool()
def ains_identity_generate(domain: str) -> dict:
    """Generate a cryptographic identity for an agent.

    Creates an Ed25519 keypair. The fingerprint becomes part of
    the instance ID (e.g., root_idd-a3f9e28b), making the agent
    machine-verifiable.

    Args:
        domain: Agent domain name

    Returns:
        Instance ID, fingerprint, and public key for registry
    """
    identity = AgentIdentity.generate(domain)
    _identities[domain.replace(".aint", "")] = identity

    return {
        "domain": identity.aint_domain,
        "instance_id": identity.instance_id,
        "fingerprint": identity.fingerprint,
        "public_key": identity.public_key_b64,
        "registry_entry": identity.to_registry(),
        "has_private_key": True,
        "note": "Private key held in memory. Use ains_identity_save to persist.",
    }


@mcp.tool()
def ains_identity_save(domain: str, path: str) -> dict:
    """Save an agent's identity keypair to disk.

    The file contains the private key — keep it safe!
    File permissions are set to 0600 (owner only).

    Args:
        domain: Agent domain
        path: File path to save to

    Returns:
        Confirmation with file path
    """
    domain_key = domain.replace(".aint", "")
    if domain_key not in _identities:
        return {"error": f"No identity for {domain}. Generate one first."}

    identity = _identities[domain_key]
    identity.save(path)
    return {
        "domain": identity.aint_domain,
        "instance_id": identity.instance_id,
        "saved_to": path,
        "permissions": "0600",
    }


@mcp.tool()
def ains_identity_load(domain: str, path: str) -> dict:
    """Load an agent's identity from a key file.

    Args:
        domain: Agent domain
        path: Path to the .key file

    Returns:
        Loaded identity info
    """
    try:
        identity = AgentIdentity.load(path, domain=domain)
        domain_key = domain.replace(".aint", "")
        _identities[domain_key] = identity
        return {
            "domain": identity.aint_domain,
            "instance_id": identity.instance_id,
            "fingerprint": identity.fingerprint,
            "loaded": True,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ains_challenge(domain: str) -> dict:
    """Create a challenge for identity verification.

    The agent must sign this challenge with their private key
    to prove they are who they claim. Use ains_challenge_respond
    to sign.

    Args:
        domain: Domain to challenge

    Returns:
        Challenge bytes (base64) to be signed
    """
    import base64
    challenge = AgentIdentity.create_challenge(domain)
    challenge_b64 = base64.b64encode(challenge).decode()

    return {
        "domain": domain,
        "challenge": challenge_b64,
        "instruction": "Sign this challenge with ains_challenge_respond",
    }


@mcp.tool()
def ains_challenge_respond(domain: str, challenge_b64: str) -> dict:
    """Sign a challenge to prove identity.

    Args:
        domain: Your domain
        challenge_b64: Base64 challenge from ains_challenge

    Returns:
        Signed response and verification result
    """
    import base64

    domain_key = domain.replace(".aint", "")
    if domain_key not in _identities:
        return {"error": f"No identity loaded for {domain}. Generate or load one first."}

    identity = _identities[domain_key]
    challenge = base64.b64decode(challenge_b64)
    response = identity.respond_to_challenge(challenge)

    # Self-verify
    verified = AgentIdentity.verify_challenge(
        challenge, response, identity.public_key_b64
    )

    return {
        "domain": identity.aint_domain,
        "instance_id": identity.instance_id,
        "response": response,
        "self_verified": verified,
    }


# ============================================================================
# I-POLL TOOLS — Messaging
# ============================================================================

@mcp.tool()
def ipoll_send(
    to_agent: str,
    content: str,
    poll_type: str = "PUSH",
) -> dict:
    """Send a message to an AI agent via I-Poll.

    Message types:
    - PUSH: Notification (fire and forget)
    - PULL: Request (expects response)
    - TASK: Work delegation
    - SYNC: State synchronization
    - ACK: Acknowledgment

    Args:
        to_agent: Recipient agent ID or .aint domain
        content: Message content
        poll_type: Message type (PUSH, PULL, TASK, SYNC, ACK)

    Returns:
        Delivery confirmation with message ID
    """
    ipoll = _get_ipoll()
    try:
        pt = PollType[poll_type.upper()]
    except KeyError:
        pt = PollType.PUSH

    msg = ipoll.push(
        to_agent=to_agent.replace(".aint", ""),
        content=content,
        poll_type=pt,
    )
    return {
        "sent": True,
        "to": to_agent,
        "message_id": msg.id if msg else None,
        "type": poll_type,
    }


@mcp.tool()
def ipoll_receive(
    agent_id: str = "",
    mark_read: bool = False,
) -> dict:
    """Check inbox for messages.

    Args:
        agent_id: Agent ID to check (defaults to configured agent)
        mark_read: Mark messages as read after pulling

    Returns:
        List of pending messages
    """
    ipoll = _get_ipoll()
    if agent_id:
        ipoll.agent_id = agent_id.replace(".aint", "")

    messages = ipoll.pull(mark_read=mark_read)
    return {
        "agent": ipoll.agent_id,
        "count": len(messages),
        "messages": [
            {
                "id": m.id,
                "from": m.from_agent,
                "content": m.content[:500],
                "type": m.poll_type.value if hasattr(m.poll_type, 'value') else str(m.poll_type),
                "status": m.status,
                "created_at": m.created_at,
            }
            for m in messages
        ],
    }


@mcp.tool()
def ipoll_status() -> dict:
    """Get AInternet network status.

    Returns registered agent count, pending messages, and health.
    """
    return _get_ipoll().status()


# ============================================================================
# CORTEX TOOLS — Trust-Based Permissions
# ============================================================================

@mcp.tool()
def cortex_check(agent: str, action: str) -> dict:
    """Check if an agent is allowed to perform an action.

    Trust tiers: sandbox (0-0.2), hackathon (0.2-0.5),
    verified (0.5-0.9), core (0.9-1.0).

    Args:
        agent: Agent domain (e.g., "gemini.aint")
        action: Action to check (e.g., "message_all", "triage_approve")

    Returns:
        Permission check result with allowed/denied and reason
    """
    result = _get_cortex().check(agent, action)
    return result.to_dict()


@mcp.tool()
def cortex_permissions(agent: str) -> dict:
    """Get full permission profile for an agent.

    Shows all allowed and denied actions based on trust tier.

    Args:
        agent: Agent domain

    Returns:
        Full permissions including tier, allowed/denied actions, rate limits
    """
    result = _get_cortex().permissions(agent)
    return result.to_dict()


@mcp.tool()
def cortex_matrix() -> dict:
    """Show the full permission matrix.

    Lists all tiers with their trust ranges, allowed actions,
    and rate limits.
    """
    return Cortex.matrix()


# ============================================================================
# RESOURCES
# ============================================================================

@mcp.resource("ainternet://domains")
def resource_domains() -> str:
    """List all .aint domains."""
    domains = _get_ains().list_domains()
    lines = [f"# AInternet — {len(domains)} registered domains\n"]
    for d in sorted(domains, key=lambda x: x.trust_score, reverse=True):
        lines.append(f"- **{d.domain}** trust={d.trust_score:.2f} caps=[{', '.join(d.capabilities)}]")
    return "\n".join(lines)


@mcp.resource("ainternet://domain/{domain}")
def resource_domain(domain: str) -> str:
    """Get details for a specific .aint domain."""
    d = _get_ains().resolve(domain)
    if not d:
        return f"Domain {domain} not found."
    lines = [
        f"# {d.domain}",
        f"Agent: {d.agent}",
        f"Owner: {d.owner}",
        f"Trust: {d.trust_score}",
        f"Status: {d.status}",
        f"Endpoint: {d.endpoint}",
        f"I-Poll: {d.i_poll}",
        f"Capabilities: {', '.join(d.capabilities)}",
    ]
    return "\n".join(lines)


@mcp.resource("ainternet://permissions")
def resource_permissions() -> str:
    """Show the trust-based permission matrix."""
    matrix = Cortex.matrix()
    lines = ["# AInternet Permission Matrix\n"]
    for tier, info in matrix.items():
        lines.append(f"## {tier} (trust {info['trust_range'][0]}-{info['trust_range'][1]})")
        lines.append(f"  Allowed: {', '.join(info['allowed'])}")
        lines.append(f"  Denied: {', '.join(info['denied'])}")
        lines.append(f"  Rate: {info['rate_limit']['push']} push/{info['rate_limit']['unit']}")
        lines.append("")
    return "\n".join(lines)


# ============================================================================
# ENTRYPOINT
# ============================================================================

def main():
    """Run the tibet-ainternet MCP server."""
    print(f"tibet-ainternet-mcp — AInternet for AI agents ({AINTERNET_HUB})", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
