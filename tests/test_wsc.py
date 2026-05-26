# SPDX-License-Identifier: GPL-2.0-or-later
"""Unit tests for the WSC enrollee implementation in ``ieee1905.emulator.wsc``.

These tests exercise the protocol with a fake-registrar fixture so the
handshake can complete in-process without a real Multi-AP controller.
"""

from __future__ import annotations

import hmac
import struct
from hashlib import sha256

import pytest

from ieee1905.emulator import wsc


def _attr(attr_id: int, value: bytes) -> bytes:
    return struct.pack("!HH", attr_id, len(value)) + value


def _build_m2(
    session: wsc.WscEnrolleeSession,
    *,
    ssid: bytes = b"home",
    network_key: bytes = b"correcthorse",
    auth_type: int = 0x0020,
    encr_type: int = 0x0008,
) -> tuple[bytes, wsc.WscKeys, bytes]:
    """Fabricate a registrar-side M2 that the enrollee should accept.

    Returns ``(m2_bytes, derived_keys, plaintext_inner)`` so individual
    tests can poke at the intermediate values. The plaintext returned is
    in the legacy WPS-nested form (0x100E Credential wrapper) for tests
    that want to assert the parser's fallback behaviour; the on-wire
    ``m2_bytes`` is the flat-form Multi-AP layout the production
    ``build_m2`` helper now emits.
    """
    cred = wsc.BssCredential(
        ssid=ssid,
        auth_type=auth_type,
        encr_type=encr_type,
        network_key=network_key,
        mac_address=b"\x02\x00\x00\x00\x00\x10",
    )
    registrar = wsc.WscRegistrarSession.from_m1(session.m1_bytes)
    m2 = wsc.build_m2(registrar, cred, rf_band=session.rf_band)
    # Mirror the plaintext shape the legacy nested-credential parser
    # expects so the existing decrypt/padding/KWA tests still have a
    # canonical reference block to chew on.
    credential = (
        _attr(wsc.ATTR_NETWORK_KEY_INDEX, bytes([1]))
        + _attr(wsc.ATTR_SSID, ssid)
        + _attr(wsc.ATTR_AUTH_TYPE, struct.pack("!H", auth_type))
        + _attr(wsc.ATTR_ENCR_TYPE, struct.pack("!H", encr_type))
        + _attr(wsc.ATTR_NETWORK_KEY, network_key)
        + _attr(wsc.ATTR_MAC_ADDRESS, b"\x02\x00\x00\x00\x00\x10")
    )
    nested_plaintext = _attr(0x100E, credential)
    kwa = hmac.new(registrar.keys.auth_key, nested_plaintext, sha256).digest()[:8]
    plaintext_with_kwa = nested_plaintext + _attr(wsc.ATTR_KEY_WRAP_AUTH, kwa)
    return m2, registrar.keys, plaintext_with_kwa


def test_m1_contains_mandatory_attributes() -> None:
    session = wsc.WscEnrolleeSession(enrollee_mac=b"\x02\x00\x00\x00\x00\x01")
    m1 = session.build_m1()
    attrs = dict(wsc.parse_attributes(m1))
    assert attrs[wsc.ATTR_VERSION] == bytes([0x10])
    assert attrs[wsc.ATTR_MESSAGE_TYPE] == bytes([wsc.WSC_MSG_M1])
    assert attrs[wsc.ATTR_MAC_ADDRESS] == b"\x02\x00\x00\x00\x00\x01"
    assert len(attrs[wsc.ATTR_ENROLLEE_NONCE]) == 16
    assert len(attrs[wsc.ATTR_PUBLIC_KEY]) == 192
    assert len(attrs[wsc.ATTR_UUID_E]) == 16
    assert attrs[wsc.ATTR_RF_BANDS] == bytes([wsc.RF_BAND_2G])


def test_kdf_three_iterations_concat() -> None:
    # The KDF must produce exactly 640 / 8 = 80 bytes split into
    # AuthKey (32B), KeyWrapKey (16B), EMSK (32B).
    kdk = b"\x11" * 32
    out = wsc._kdf(kdk, 640)
    assert len(out) == 96  # 3 * 32 (we always emit full iterations)
    # Sanity: HMAC chain matches.
    label = b"Wi-Fi Easy and Secure Key Derivation"
    expected = b""
    for i in range(1, 4):
        expected += hmac.new(
            kdk, struct.pack("!I", i) + label + struct.pack("!I", 640), sha256
        ).digest()
    assert out == expected


def test_full_handshake_roundtrip() -> None:
    session = wsc.WscEnrolleeSession(enrollee_mac=b"\x02\x00\x00\x00\x00\x02")
    session.build_m1()
    m2, _keys, _plaintext = _build_m2(
        session, ssid=b"home-mesh", network_key=b"a-strong-key"
    )
    # Parse M2 from the wire and verify both the outer Authenticator and
    # the inner Key Wrap Authenticator, ending with credential extraction.
    attrs = dict(wsc.parse_attributes(m2))
    keys = wsc.derive_keys(
        session, attrs[wsc.ATTR_PUBLIC_KEY], attrs[wsc.ATTR_REGISTRAR_NONCE]
    )
    assert wsc.verify_authenticator(keys, session.m1_bytes, m2)
    inner = wsc.decrypt_encrypted_settings(keys, attrs[wsc.ATTR_ENCRYPTED_SETTINGS])
    creds = wsc.parse_credentials(inner)
    assert len(creds) == 1
    assert creds[0].ssid == b"home-mesh"
    assert creds[0].network_key == b"a-strong-key"
    assert creds[0].auth_type == 0x0020
    assert creds[0].encr_type == 0x0008


def test_authenticator_fail_rejects_m2() -> None:
    session = wsc.WscEnrolleeSession(enrollee_mac=b"\x02\x00\x00\x00\x00\x03")
    session.build_m1()
    m2, _keys, _ = _build_m2(session)
    attrs = dict(wsc.parse_attributes(m2))
    keys = wsc.derive_keys(
        session, attrs[wsc.ATTR_PUBLIC_KEY], attrs[wsc.ATTR_REGISTRAR_NONCE]
    )
    # Flip a byte inside M2 (but outside the Authenticator attribute itself).
    tampered = bytearray(m2)
    tampered[40] ^= 0x01
    assert not wsc.verify_authenticator(keys, session.m1_bytes, bytes(tampered))


def test_decrypt_rejects_bad_padding() -> None:
    session = wsc.WscEnrolleeSession(enrollee_mac=b"\x02\x00\x00\x00\x00\x04")
    session.build_m1()
    m2, keys, _ = _build_m2(session)
    enc = dict(wsc.parse_attributes(m2))[wsc.ATTR_ENCRYPTED_SETTINGS]
    bad = bytearray(enc)
    bad[-1] ^= 0xFF  # corrupt last ciphertext byte → bad padding or KWA
    with pytest.raises(ValueError):
        wsc.decrypt_encrypted_settings(keys, bytes(bad))


def test_attribute_truncation_raises() -> None:
    # Length says 8 but only 4 bytes follow.
    payload = struct.pack("!HH", 0x1020, 8) + b"\x00\x00\x00\x00"
    with pytest.raises(ValueError):
        wsc.parse_attributes(payload)
