"""TS3/TS6 client UIDs derived from a client's public key."""

from __future__ import annotations

import base64
import hashlib


def ts3_uid_from_public_key(public_key_raw: str) -> str:
    """TS3 (SHA-1) UID for a TS6 ``client_public_key_raw`` value."""
    return base64.b64encode(hashlib.sha1(public_key_raw.encode("ascii")).digest()).decode()


def ts6_uid_from_public_key(public_key_raw: str) -> str:
    """TS6 (SHA-256) UID for a ``client_public_key_raw`` value."""
    return base64.b64encode(hashlib.sha256(public_key_raw.encode("ascii")).digest()).decode()
