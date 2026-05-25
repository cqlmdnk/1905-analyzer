# SPDX-License-Identifier: GPL-2.0-or-later
"""CMDU fragmentation and reassembly.

IEEE 1905.1-2013 §7.4: CMDUs whose serialized form exceeds the maximum
Ethernet frame size are split into multiple frames. Each fragment
carries the same ``message_id`` and an incrementing ``fragment_id``.
The fragment with ``last_fragment=True`` terminates the group.

The reassembler accumulates fragments, returns a complete CMDU as soon
as a sequence is whole, and drops stale state after a configurable
timeout to bound memory usage in the presence of loss or replay.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from ieee1905.core.cmdu import CMDU, CMDUHeader, CMDUParseError
from ieee1905.core.tlv import RawTLV, TLVParseError

logger = logging.getLogger(__name__)

#: Default time after which incomplete fragment groups are discarded.
DEFAULT_REASSEMBLY_TIMEOUT_S = 5.0


@dataclass(slots=True)
class _PendingGroup:
    header: CMDUHeader
    fragments: dict[int, bytes] = field(default_factory=dict)
    last_fragment_id: int | None = None
    first_seen: float = field(default_factory=time.monotonic)

    def complete(self) -> bool:
        if self.last_fragment_id is None:
            return False
        expected = set(range(self.last_fragment_id + 1))
        return expected == set(self.fragments)


@dataclass(slots=True)
class FragmentReassembler:
    """Stateful CMDU fragment reassembler keyed by ``(source, MID)``."""

    timeout_s: float = DEFAULT_REASSEMBLY_TIMEOUT_S
    _groups: dict[tuple[bytes, int], _PendingGroup] = field(default_factory=dict)

    def push(self, source_mac: bytes, frame_body: bytes) -> CMDU | None:
        """Feed a fragment in; return the reassembled CMDU when complete.

        ``frame_body`` is the post-Ethernet payload (i.e. the CMDU bytes
        starting with the 8-byte CMDU header). When ``last_fragment`` is
        already true on a single-fragment CMDU, the CMDU is returned
        immediately and no state is retained.
        """
        header = CMDUHeader.from_bytes(frame_body)
        payload = frame_body[8:]  # CMDU_HEADER_SIZE

        # Fast path: single-fragment, complete CMDU.
        if header.fragment_id == 0 and header.last_fragment:
            return CMDU.from_bytes(frame_body)

        key = (source_mac, header.message_id)
        self._evict_stale()

        group = self._groups.get(key)
        if group is None:
            group = _PendingGroup(header=header)
            self._groups[key] = group

        if header.fragment_id in group.fragments:
            logger.warning(
                "duplicate fragment %d for MID=0x%04x src=%s",
                header.fragment_id,
                header.message_id,
                source_mac.hex(),
            )
        group.fragments[header.fragment_id] = payload
        if header.last_fragment:
            group.last_fragment_id = header.fragment_id

        if not group.complete():
            return None

        assembled_payload = b"".join(
            group.fragments[i] for i in sorted(group.fragments)
        )
        del self._groups[key]

        # Re-encode with first fragment's header but cleared fragmentation
        # bookkeeping; the consumer should treat reassembled CMDUs as
        # single-fragment.
        reassembled_header = CMDUHeader(
            message_type=group.header.message_type,
            message_id=group.header.message_id,
            fragment_id=0,
            last_fragment=True,
            relay_indicator=group.header.relay_indicator,
        )
        tlvs = self._parse_tlvs(assembled_payload)
        return CMDU(header=reassembled_header, tlvs=tlvs)

    def _parse_tlvs(self, payload: bytes) -> list[RawTLV]:
        out: list[RawTLV] = []
        offset = 0
        while offset < len(payload):
            try:
                tlv, consumed = RawTLV.parse_one(payload, offset)
            except TLVParseError as exc:
                raise CMDUParseError(
                    f"reassembled CMDU has malformed TLV at offset {offset}: {exc}"
                ) from exc
            out.append(tlv)
            offset += consumed
            if tlv.tlv_type == CMDU.END_OF_MESSAGE_TYPE:
                break
        return out

    def _evict_stale(self) -> None:
        now = time.monotonic()
        stale = [
            key
            for key, group in self._groups.items()
            if now - group.first_seen > self.timeout_s
        ]
        for key in stale:
            logger.info(
                "dropping stale fragment group src=%s mid=0x%04x",
                key[0].hex(),
                key[1],
            )
            del self._groups[key]

    @property
    def pending_groups(self) -> int:
        return len(self._groups)
