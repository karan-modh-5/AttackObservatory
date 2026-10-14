"""Actor intelligence: pure classification of per-IP aggregates (contract section 4)."""

from __future__ import annotations

from dataclasses import dataclass

# Crypto markers are matched in SQL (see routers/ssh.py ACTOR_*_SQL): xmrig,
# miner, crypto, pool., stratum — case-insensitive substring on command payloads.

# A single actor row as aggregated by the /ssh/actors endpoint. All credential
# and command features are derived from the same SQL window as the counts.
@dataclass(frozen=True, slots=True)
class ActorFeatures:
    events: int
    probes: int
    distinct_usernames: int
    distinct_passwords: int
    commands: int
    has_success: bool
    has_crypto: bool
    events_per_hour: float
    span_hours: float


def classify_actor(features: ActorFeatures) -> tuple[str, str]:
    """Return (playbook, intent) for one actor's aggregated features.

    Playbook is the first matching rule; intent summarises the actor's goal.
    "Credentials attempted" means credentials that got in (has_success):
    failed guesses alone never escalate an actor past handshake_scan.
    Pure function: no I/O, no globals mutated, deterministic output.
    """
    attempted_credentials = features.has_success

    if features.has_success and features.commands >= 3:
        playbook = "opportunistic"
    elif features.has_crypto:
        playbook = "crypto_target"
    elif features.distinct_usernames >= 8:
        playbook = "service_account_enum"
    elif features.distinct_usernames >= 3 and features.distinct_passwords >= 3:
        playbook = "default_credential_spray"
    elif features.events_per_hour >= 20:
        playbook = "fast_dictionary"
    elif features.events <= 3 and features.probes >= 1 and not attempted_credentials:
        playbook = "handshake_scan"
    else:
        playbook = "scanner_tool"

    if features.has_success or features.commands >= 5:
        intent = "deploy"
    elif features.events > 0 and (features.probes >= 1 or attempted_credentials):
        intent = "probe"
    else:
        intent = "unknown"

    return playbook, intent
