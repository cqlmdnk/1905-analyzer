# SPDX-License-Identifier: GPL-2.0-or-later
"""Unit tests for the WSC enrollee implementation in ``ieee1905.emulator.wsc``.

These tests exercise the protocol with a fake-registrar fixture so the
handshake can complete in-process without a real Multi-AP controller.
"""

from __future__ import annotations

import hmac
import os
import struct
from hashlib import sha256

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    tests can poke at the intermediate values.
    """
    # Registrar's own DH key pair.
    r_private = int.from_bytes(os.urandom(192), "big") % (wsc._DH_P - 1) or 2
    r_public = pow(wsc._DH_G, r_private, wsc._DH_P)
    r_public_bytes = r_public.to_bytes(192, "big")
    r_nonce = os.urandom(16)

    # Mirror the enrollee's key derivation from the registrar's side.
    shared = pow(session._dh_public, r_private, wsc._DH_P)
    dh_key = sha256(shared.to_bytes(192, "big")).digest()
    kdk = hmac.new(
        dh_key,
        session.enrollee_nonce + session.enrollee_mac + r_nonce,
        sha256,
    ).digest()
    block = wsc._kdf(kdk, 640)
    keys = wsc.WscKeys(
        auth_key=block[0:32], key_wrap_key=block[32:48], emsk=block[48:80]
    )

    # Build the inner credential attribute stream.
    credential = (
        _attr(wsc.ATTR_NETWORK_KEY_INDEX, bytes([1]))
        + _attr(wsc.ATTR_SSID, ssid)
        + _attr(wsc.ATTR_AUTH_TYPE, struct.pack("!H", auth_type))
        + _attr(wsc.ATTR_ENCR_TYPE, struct.pack("!H", encr_type))
        + _attr(wsc.ATTR_NETWORK_KEY, network_key)
        + _attr(wsc.ATTR_MAC_ADDRESS, b"\x02\x00\x00\x00\x00\x10")
    )
    inner = _attr(0x100E, credential)  # Attribute 0x100E = Credential
    kwa = hmac.new(keys.auth_key, inner, sha256).digest()[:8]
    plaintext = inner + _attr(wsc.ATTR_KEY_WRAP_AUTH, kwa)

    # PKCS#7 pad + AES-128-CBC encrypt with KeyWrapKey.
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len]) * pad_len
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(keys.key_wrap_key), modes.CBC(iv), backend=default_backend()
    )
    enc = iv + cipher.encryptor().update(plaintext_padded)

    # M2 attribute stream (sans Authenticator).
    m2_core = (
        _attr(wsc.ATTR_VERSION, bytes([0x10]))
        + _attr(wsc.ATTR_MESSAGE_TYPE, bytes([wsc.WSC_MSG_M2]))
        + _attr(wsc.ATTR_ENROLLEE_NONCE, session.enrollee_nonce)
        + _attr(wsc.ATTR_REGISTRAR_NONCE, r_nonce)
        + _attr(0x1048, os.urandom(16))  # UUID-R
        + _attr(wsc.ATTR_PUBLIC_KEY, r_public_bytes)
        + _attr(wsc.ATTR_AUTH_TYPE_FLAGS, struct.pack("!H", 0x0122))
        + _attr(wsc.ATTR_ENCR_TYPE_FLAGS, struct.pack("!H", 0x0009))
        + _attr(wsc.ATTR_CONN_TYPE_FLAGS, bytes([0x01]))
        + _attr(wsc.ATTR_CONFIG_METHODS, struct.pack("!H", 0x2008))
        + _attr(wsc.ATTR_MANUFACTURER, b"test")
        + _attr(wsc.ATTR_MODEL_NAME, b"test")
        + _attr(wsc.ATTR_MODEL_NUMBER, b"1")
        + _attr(wsc.ATTR_SERIAL_NUMBER, b"1")
        + _attr(wsc.ATTR_PRIMARY_DEVICE_TYPE, b"\x00\x06\x00\x50\xf2\x04\x00\x01")
        + _attr(wsc.ATTR_DEVICE_NAME, b"test")
        + _attr(wsc.ATTR_RF_BANDS, bytes([session.rf_band]))
        + _attr(wsc.ATTR_ASSOCIATION_STATE, struct.pack("!H", 0))
        + _attr(wsc.ATTR_CONFIG_ERROR, struct.pack("!H", 0))
        + _attr(wsc.ATTR_DEVICE_PASSWORD_ID, struct.pack("!H", 4))
        + _attr(wsc.ATTR_OS_VERSION, struct.pack("!I", 0x80000001))
        + _attr(wsc.ATTR_ENCRYPTED_SETTINGS, enc)
    )
    auth = hmac.new(keys.auth_key, session.m1_bytes + m2_core, sha256).digest()[:8]
    m2 = m2_core + _attr(wsc.ATTR_AUTHENTICATOR, auth)
    return m2, keys, plaintext


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
