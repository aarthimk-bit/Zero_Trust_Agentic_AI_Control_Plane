"""
identity.py  --  Agent identity for the Zero Trust prototype (Milestone M1).

Purpose (Chapter 3, section 3.5 and requirement R1):
every request in the framework must be bound to a unique, cryptographically
verifiable agent identity. This module provides that identity:

  1. Each agent gets an Ed25519 key pair: a private signing key it keeps
     secret, and a public key anyone may see.
  2. The agent's identifier is derived from its public key, so an identity
     cannot be claimed without holding the matching key.
  3. Every message an agent sends is signed with its private key.
  4. The control plane verifies the signature against the public key held
     in its registry. If one byte of the message changes, or the sender
     does not hold the right private key, verification fails.

Why Ed25519: a modern, widely used digital signature scheme with small
keys and fast verification, provided by the standard 'cryptography'
package. Signing proves WHO sent a message and that it was NOT ALTERED;
it does not hide the content (that would be encryption, which M1 does
not need).
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def derive_agent_id(public_key: Ed25519PublicKey) -> str:
    """
    Agent ID = first 16 hex characters of the SHA-256 hash of the raw
    public key (SHA-256 is a FIPS 180-4 hash function, the same family
    used later for task evidence). Deriving the ID from the key binds
    identity to key: the ID cannot be used without holding the matching
    private key.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class Agent:
    """A minimal agent: a name, a role, and its own key pair."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        # The private key never leaves the agent. Anyone holding it could
        # impersonate the agent, which is why it is kept private here and
        # never printed or written to disk.
        self._private_key = Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.agent_id = derive_agent_id(self.public_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the agent's private key."""
        return self._private_key.sign(message)


class AgentRegistry:
    """
    The control plane's memory of who exists (the seed of the policy
    database in Chapter 3). Maps agent_id to public key, name, and role.
    Registration is the trusted provisioning step in the threat model:
    keys recorded here are the ground-truth identities.
    """

    def __init__(self):
        self._entries = {}

    def register(self, agent: Agent) -> None:
        """Record an agent's identity at provisioning time."""
        self._entries[agent.agent_id] = {
            "public_key": agent.public_key,
            "name": agent.name,
            "role": agent.role,
        }

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._entries

    def public_key_of(self, agent_id: str) -> Ed25519PublicKey:
        return self._entries[agent_id]["public_key"]


def verify_signature(
    registry: AgentRegistry, agent_id: str, message: bytes, signature: bytes
) -> bool:
    """
    The control plane's identity check (step 1 of the decision function
    in Chapter 3, section 3.6). Returns True only when:
      - the claimed agent_id is registered, AND
      - the signature verifies against the REGISTERED public key.
    An imposter with its own keys fails because its signature does not
    match the key registered under the claimed ID. A tampered message
    fails because the signature no longer matches the bytes.
    """
    if not registry.is_registered(agent_id):
        return False
    public_key = registry.public_key_of(agent_id)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
