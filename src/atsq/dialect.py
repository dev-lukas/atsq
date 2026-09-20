"""Server dialect handling.

All TS3-vs-TS6 divergence must live in this module. Values below are taken
from the recorded dialect probe (``scripts/probe_dialect.py``; transcripts in
``tests/unit/fixtures/probe_ts3.log`` / ``probe_ts6.log``, findings in
``docs/dialects.md``), run against teamspeak:3.13 (3.13.7) and
teamspeaksystems/teamspeak6-server (6.0.0-beta11, re-audited on beta13).

Probe verdict: the wire dialects are almost identical. Both greet with a
literal ``TS3`` first line, frame lines as ``\\n\\r``, use the same escape
table, the same error codes, and emit the same events. TS6 adds fields, the
``bans`` event source and selective ``servernotifyunregister``. The reliable
distinguishing marks are the second greeting line and the ``version``
command.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = ["QUIRKS", "Dialect", "DialectQuirks", "sniff_dialect"]

#: Welcome-line prefix of a TS3 server; TS6 says "TeamSpeak ServerQuery" without the 3.
_TS3_WELCOME_PREFIX = b"Welcome to the TeamSpeak 3 "

_TS3_EVENT_SOURCES = frozenset({"server", "channel", "textserver", "textchannel", "textprivate"})


class Dialect(enum.Enum):
    TS3 = "ts3"
    TS6 = "ts6"
    #: Detect from the greeting at connect time.
    AUTO = "auto"


@dataclass(frozen=True, slots=True)
class DialectQuirks:
    """Per-generation wire deviations (all probe-verified)."""

    #: Greeting lines to consume before commands may be sent (first one is ``TS3`` on both).
    greeting_lines: int
    #: ``servernotifyregister event=`` values the server accepts.
    event_sources: frozenset[str]
    #: Whether ``servernotifyunregister event=X`` drops only X (TS3 silently drops all).
    selective_unregister: bool


QUIRKS: dict[Dialect, DialectQuirks] = {
    Dialect.TS3: DialectQuirks(
        greeting_lines=2,
        event_sources=_TS3_EVENT_SOURCES,
        selective_unregister=False,
    ),
    Dialect.TS6: DialectQuirks(
        greeting_lines=2,
        event_sources=_TS3_EVENT_SOURCES | {"bans"},
        selective_unregister=True,
    ),
}


def sniff_dialect(greeting: list[bytes]) -> Dialect:
    """Determine the dialect from the full greeting.

    The first line is ``TS3`` on both generations, so only the welcome line
    distinguishes them. Unknown shapes default to TS6 (the growing side).
    """
    for line in greeting:
        if line.startswith(_TS3_WELCOME_PREFIX):
            return Dialect.TS3
    return Dialect.TS6
