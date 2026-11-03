"""Small, explicit signature envelope for fictional continuity records."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value):
    """Bounded JSON profile: no floats, duplicate keys or ambiguous serialization."""

    def check(item, depth=0):
        if depth > 20:
            raise ValueError("JSON nesting limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int and -(2**53 - 1) <= item <= 2**53 - 1:
            return
        if type(item) is str:
            item.encode("utf-8")
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for key, child in item.items():
                check(key, depth + 1)
                check(child, depth + 1)
            return
        raise ValueError("Unsupported value")

    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(encoded) > 65536:
        raise ValueError("Record too large")
    return encoded


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class SigningKey:
    """Issuer/audit keys belong to the trusted continuity authority, never an agent."""

    def __init__(self, key_id, private_key=None):
        self.key_id = key_id
        self._private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self):
        return self._private_key.public_key().public_bytes_raw().hex()

    def sign(self, purpose, payload):
        protected = {
            "schema": "affixio.resilience.signature.v1",
            "algorithm": "Ed25519",
            "purpose": purpose,
            "key_id": self.key_id,
            "payload": payload,
        }
        return {
            **protected,
            "signature": base64.b64encode(self._private_key.sign(canonical(protected))).decode(),
        }


def verify(envelope, pins, purpose):
    try:
        if set(envelope) != {"schema", "algorithm", "purpose", "key_id", "payload", "signature"}:
            raise ValueError("Envelope schema mismatch")
        if (envelope["schema"], envelope["algorithm"], envelope["purpose"]) != (
            "affixio.resilience.signature.v1",
            "Ed25519",
            purpose,
        ):
            raise ValueError("Signature context mismatch")
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pins[envelope["key_id"]]))
        protected = {key: value for key, value in envelope.items() if key != "signature"}
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(protected))
        return json.loads(canonical(envelope["payload"]))
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid or untrusted signature") from exc
