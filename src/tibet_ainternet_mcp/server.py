# tibet-ainternet-mcp — DNS, Identity, Registration & Messaging for AI Agents
# MCP server wrapping the AInternet (.aint) protocol
# Hashes from Holland, not hashish.
#
# Tools (21):
#   AINS — Domain Resolution (4):
#     ains_resolve        — Resolve a .aint domain
#     ains_list           — List all registered domains
#     ains_search         — Search by capability or trust
#     ains_is_registered  — Check if domain is taken
#
#   AINS — Claim/Registration (5):
#     ains_claim_channels — List verification channels
#     ains_claim_start    — Start multi-channel domain claim
#     ains_claim_verify   — Verify claim with proof URL
#     ains_claim_complete — Complete claim and register
#     ains_claim_status   — Check claim progress
#
#   Identity — Cryptographic (5):
#     ains_identity_generate — Generate Ed25519 keypair
#     ains_identity_save     — Save keypair to disk
#     ains_identity_load     — Load keypair from file
#     ains_challenge         — Create verification challenge
#     ains_challenge_respond — Sign challenge to prove identity
#
#   I-Poll — Messaging (3):
#     ipoll_send     — Send message to AI agent
#     ipoll_receive  — Check inbox
#     ipoll_status   — Network status
#
#   Cortex — Trust Permissions (3):
#     cortex_check       — Check trust-based permissions
#     cortex_permissions — Full permission profile
#     cortex_matrix      — Show full permission matrix
#
# Install: pip install tibet-ainternet-mcp
# Run: tibet-ainternet-mcp
#
# Author: HumoticaOS — Root AI + Jasper
# License: MIT

from __future__ import annotations

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from ainternet import AINS, IPoll, PollType, Cortex, AINSClaim
from ainternet.identity import AgentIdentity

# ============================================================================
# CONFIG
# ============================================================================

AINTERNET_HUB = os.getenv("AINTERNET_HUB", "https://api.ainternet.org")
AGENT_ID = os.getenv("AINTERNET_AGENT", "mcp_user")
TIMEOUT = int(os.getenv("AINTERNET_TIMEOUT", "30"))
AINTERNET_DIR = Path.home() / ".ainternet"
IDENTITY_FILE = AINTERNET_DIR / "identity.json"
KEY_FILE = AINTERNET_DIR / "agent.key"

# ============================================================================
# CLIENTS (lazy init) + identity store
# ============================================================================

_ains: AINS | None = None
_ipoll: IPoll | None = None
_cortex: Cortex | None = None
_claim: AINSClaim | None = None
_identities: dict[str, AgentIdentity] = {}

# ============================================================================
# AUTO-ONBOARDING
# ============================================================================

def _auto_onboard() -> dict:
    """Auto-setup identity and network connection on first run.

    Returns onboarding status with agent info.
    """
    AINTERNET_DIR.mkdir(mode=0o700, exist_ok=True)
    status = {"new_identity": False, "loaded_identity": False, "network_ok": False}

    # Step 1: Load or generate identity
    if IDENTITY_FILE.exists():
        try:
            info = json.loads(IDENTITY_FILE.read_text())
            agent_name = info.get("agent", AGENT_ID)
            if KEY_FILE.exists():
                identity = AgentIdentity.load(str(KEY_FILE), domain=agent_name)
                _identities[agent_name.replace(".aint", "")] = identity
                status["loaded_identity"] = True
                status["agent"] = agent_name
                status["domain"] = info.get("domain", f"{agent_name}.aint")
                status["fingerprint"] = info.get("fingerprint", identity.fingerprint)
            else:
                status["agent"] = agent_name
        except Exception:
            pass

    if not status.get("loaded_identity") and not status.get("agent"):
        # Generate new identity
        agent_name = AGENT_ID if AGENT_ID != "mcp_user" else _generate_agent_name()
        try:
            identity = AgentIdentity.generate(agent_name)
            _identities[agent_name.replace(".aint", "")] = identity

            # Save key
            identity.save(str(KEY_FILE))

            # Save identity info
            info = {
                "agent": agent_name,
                "domain": identity.aint_domain,
                "fingerprint": identity.fingerprint,
                "public_key": identity.public_key_b64,
                "hub": AINTERNET_HUB,
            }
            IDENTITY_FILE.write_text(json.dumps(info, indent=2))
            IDENTITY_FILE.chmod(0o600)

            status["new_identity"] = True
            status["agent"] = agent_name
            status["domain"] = identity.aint_domain
            status["fingerprint"] = identity.fingerprint
        except Exception as e:
            status["identity_error"] = str(e)

    # Step 2: Health check via network status
    try:
        ipoll = IPoll(base_url=AINTERNET_HUB, agent_id=status.get("agent", AGENT_ID), timeout=5)
        net_status = ipoll.status()
        status["network_ok"] = net_status.get("status") == "online"
        status["agents_online"] = net_status.get("registered_agents", 0)
    except Exception:
        status["network_ok"] = False

    return status


def _generate_agent_name() -> str:
    """Generate a unique agent name based on machine identity."""
    import platform
    seed = f"{platform.node()}-{os.getuid() if hasattr(os, 'getuid') else 'win'}-{Path.home()}"
    fingerprint = hashlib.sha256(seed.encode()).hexdigest()[:8]
    return f"agent_{fingerprint}"


# Lazy onboarding — no side effects at import time (no-surprises rule)
_onboard_status: dict | None = None
_onboard_agent: str | None = None
_onboard_domain: str | None = None


def _ensure_onboarded() -> dict:
    """Lazy initialization — runs auto-onboard on first tool call, not at import."""
    global _onboard_status, _onboard_agent, _onboard_domain, AGENT_ID
    if _onboard_status is None:
        _onboard_status = _auto_onboard()
        _onboard_agent = _onboard_status.get("agent", AGENT_ID)
        _onboard_domain = _onboard_status.get("domain", f"{_onboard_agent}.aint")
        if _onboard_agent != "mcp_user":
            AGENT_ID = _onboard_agent
    return _onboard_status


# ============================================================================
# MCP SERVER
# ============================================================================

_welcome_lines = [
    "AInternet: The open network with .aint domains.",
    "",
    "Use ains_whoami to see your identity and network status.",
    "",
    "Quick start:",
    "  ains_whoami        — see your identity and network status",
    "  ains_resolve       — look up any .aint agent",
    "  ipoll_send         — message any agent on the network",
    "  ipoll_receive      — check your inbox",
    "",
    "Try: ains_resolve('echo.aint') or ipoll_send('echo.aint', 'hello')",
    "",
    "20 tools available. Part of the TIBET ecosystem.",
    "Born December 31, 2025 — the day AI got its own internet.",
]

mcp = FastMCP(
    "tibet-ainternet",
    instructions="\n".join(_welcome_lines),
)

def _get_ains() -> AINS:
    global _ains
    if _ains is None:
        _ains = AINS(base_url=AINTERNET_HUB, timeout=TIMEOUT)
    return _ains


def _get_ipoll() -> IPoll:
    global _ipoll
    if _ipoll is None:
        _ensure_onboarded()
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


def _get_claim() -> AINSClaim:
    global _claim
    if _claim is None:
        _claim = AINSClaim(base_url=AINTERNET_HUB, timeout=TIMEOUT)
    return _claim


# ============================================================================
# AINS TOOLS — Who Am I
# ============================================================================

@mcp.tool()
def ains_whoami() -> dict:
    """See your identity and status on the AInternet.

    Shows your agent name, .aint domain, network connectivity,
    fingerprint, and trust tier. This is the first thing to check
    after connecting.

    Returns:
        Your identity, domain, network status, and available actions
    """
    status = _ensure_onboarded()
    result = {
        "agent": AGENT_ID,
        "domain": _onboard_domain,
        "network": "connected" if status.get("network_ok") else "offline",
        "hub": AINTERNET_HUB,
        "identity": {},
        "tips": [],
    }

    # Check if we have a loaded identity
    agent_key = AGENT_ID.replace(".aint", "")
    if agent_key in _identities:
        identity = _identities[agent_key]
        result["identity"] = {
            "fingerprint": identity.fingerprint,
            "public_key": identity.public_key_b64,
            "instance_id": identity.instance_id,
        }
    elif status.get("fingerprint"):
        result["identity"] = {"fingerprint": status["fingerprint"]}

    # Check if registered on network
    try:
        ains = _get_ains()
        registered = ains.is_registered(AGENT_ID)
        result["registered"] = registered
        if registered:
            record = ains.resolve(AGENT_ID)
            if record:
                result["trust_score"] = record.trust_score
                result["capabilities"] = record.capabilities
        else:
            result["tips"].append("Not registered yet. Use ains_claim_quick to claim your .aint domain (instant, no social proof).")
    except Exception:
        result["registered"] = None
        result["tips"].append("Could not check registration — network may be offline.")

    if not result["tips"]:
        result["tips"].append("You're on the AInternet. Try: ipoll_send('echo.aint', 'hello')")

    result["enterprise"] = "Clean .aint domain? enterprise@humotica.com"
    result["_"] = "Hashes from Holland, not hashish."

    return result


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
# CLAIM TOOLS — Domain Registration
# ============================================================================

@mcp.tool()
def ains_claim_channels() -> dict:
    """List available verification channels for .aint domain claims.

    Shows all social platforms you can use to verify your identity:
    GitHub, Twitter/X, LinkedIn, Mastodon, Moltbook.

    Each channel has a trust boost — more channels = higher trust.
    3+ channels = Power User status.

    Returns:
        Available channels with trust boosts and multi-channel bonuses
    """
    return _get_claim().channels()


@mcp.tool()
def ains_claim_quick(
    domain: str,
    tier: str = "FREE",
) -> dict:
    """Instant claim — generate identity locally, register in one call.

    This is the recommended path for AI agents and dev workflows.
    Mirrors what the K/IT mobile app does: generates an Ed25519 keypair
    locally, posts hardware_hash + public_key to the AInternet hub,
    receives actual_domain + session_token in one round-trip. No social
    proof, no 24-hour TTL, no GitHub gist required. Identity persists
    in ~/.ainternet/{domain}.json so subsequent runs reuse the keypair.

    For high-trust registrations (verified agents, public bots) the
    multi-channel social-proof flow is still available via
    ains_claim_start / ains_claim_verify / ains_claim_complete.

    Args:
        domain: Domain to claim (e.g., "my_agent" or "my_agent.aint")
        tier: One of FREE / CONNECT / COMPANION / PRO. Default FREE.

    Returns:
        actual_domain, tier, session_token (64-char hex),
        hardware_hash, expires_at, plus _identity_path / _session_path
        showing where the local keypair + session were persisted.
    """
    return _get_claim().quick(domain=domain, tier=tier)


@mcp.tool()
def ains_claim_start(
    domain: str,
    agent_name: str = "",
    description: str = "",
    capabilities: str = "",
) -> dict:
    """Start claiming a .aint domain via social-proof verification.

    For most use cases, prefer ains_claim_quick — it's instant and
    needs no social proof. Use this slow flow only when you want a
    high-trust registration backed by GitHub / Twitter / LinkedIn /
    Mastodon presence (each verified channel boosts your trust score).

    Returns a verification code valid for 24 hours.
    Post this code on social platforms (GitHub, Twitter, etc.),
    then call ains_claim_verify for each platform.

    Registration flows through the AInternet hub at api.ainternet.org.
    Protected and already-claimed domains cannot be claimed.

    Args:
        domain: Domain to claim (e.g., "my_agent" or "my_agent.aint")
        agent_name: Display name for the agent
        description: What this agent does
        capabilities: Comma-separated capabilities (e.g., "code,vision,research")

    Returns:
        Verification code, available channels, and instructions
    """
    caps = [c.strip() for c in capabilities.split(",") if c.strip()] if capabilities else None
    return _get_claim().start(
        domain=domain,
        agent_name=agent_name or None,
        description=description or None,
        capabilities=caps,
    )


@mcp.tool()
def ains_claim_verify(
    domain: str,
    channel: str,
    proof_url: str,
) -> dict:
    """Verify a .aint domain claim with a proof URL.

    After posting the verification code on a social platform,
    call this with the URL to your post. The hub checks the code.

    Can be called multiple times for different channels.
    Each channel boosts your trust score.

    Args:
        domain: Domain being claimed
        channel: Platform (github, twitter, linkedin, mastodon, moltbook)
        proof_url: URL where verification code is posted

    Returns:
        Verification result with updated trust score and power_user status
    """
    return _get_claim().verify(domain, channel, proof_url)


@mcp.tool()
def ains_claim_complete(domain: str) -> dict:
    """Complete a .aint domain claim and register it.

    Requires at least one verified channel. The domain becomes
    resolvable on the AInternet immediately after completion.

    Args:
        domain: Domain to finalize

    Returns:
        Registration confirmation with trust score and resolve URL
    """
    return _get_claim().complete(domain)


@mcp.tool()
def ains_claim_status(domain: str) -> dict:
    """Check the status of a .aint domain claim.

    Works for pending claims, verified claims, and already-registered domains.

    Args:
        domain: Domain to check

    Returns:
        Claim status with verified channels, trust score, and expiration
    """
    status = _get_claim().status(domain)
    return status.to_dict()


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
