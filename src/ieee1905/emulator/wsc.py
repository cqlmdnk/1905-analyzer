# SPDX-License-Identifier: GPL-2.0-or-later
"""WSC (Wi-Fi Simple Config) M1/M2 enrollee for EasyMesh onboarding.

Implements the protocol bits a Multi-AP agent needs during AP
autoconfiguration:

- Generate a 1536-bit MODP DH key pair (RFC 3526 Group 5; WPS v2.0 §7.2).
- Build an M1 enrollee message with the mandatory WPS v2.0 §8.3.1 set.
- Derive AuthKey / KeyWrapKey / EMSK per WPS v2.0 §6.3.
- Decrypt M2's Encrypted Settings (AES-128-CBC) and verify both the
  message Authenticator and the inner Key Wrap Authenticator.

PIN / PBC / registrar flows are out of scope.
"""

from __future__ import annotations

import hmac
import os
import struct
import uuid
from dataclasses import dataclass, field
from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RFC 3526 §3 — 1536-bit MODP (Oakley Group 5). WPS v2.0 §7.2 mandates this group.
_DH_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)
_DH_P = int(_DH_P_HEX, 16)
_DH_G = 2
_PK_BYTES = 192  # 1536 bits

# WPS v2.0 §8.2.1 — attribute type identifiers.
ATTR_VERSION = 0x104A
ATTR_MESSAGE_TYPE = 0x1022
ATTR_UUID_E = 0x1047
ATTR_MAC_ADDRESS = 0x1020
ATTR_ENROLLEE_NONCE = 0x101A
ATTR_PUBLIC_KEY = 0x1032
ATTR_AUTH_TYPE_FLAGS = 0x1004
ATTR_ENCR_TYPE_FLAGS = 0x1010
ATTR_CONN_TYPE_FLAGS = 0x100D
ATTR_CONFIG_METHODS = 0x1008
ATTR_WPS_STATE = 0x1044
ATTR_MANUFACTURER = 0x1021
ATTR_MODEL_NAME = 0x1023
ATTR_MODEL_NUMBER = 0x1024
ATTR_SERIAL_NUMBER = 0x1042
ATTR_PRIMARY_DEVICE_TYPE = 0x1054
ATTR_DEVICE_NAME = 0x1011
ATTR_RF_BANDS = 0x103C
ATTR_ASSOCIATION_STATE = 0x1002
ATTR_DEVICE_PASSWORD_ID = 0x1012
ATTR_CONFIG_ERROR = 0x1009
ATTR_OS_VERSION = 0x1029
ATTR_AUTHENTICATOR = 0x1005
ATTR_REGISTRAR_NONCE = 0x1039
ATTR_ENCRYPTED_SETTINGS = 0x1018
ATTR_KEY_WRAP_AUTH = 0x101E
ATTR_SSID = 0x1045
ATTR_NETWORK_KEY = 0x1027
ATTR_NETWORK_KEY_INDEX = 0x1028
ATTR_AUTH_TYPE = 0x1003
ATTR_ENCR_TYPE = 0x100F

WSC_MSG_M1 = 0x04
WSC_MSG_M2 = 0x05

# RF band bitmap (WPS v2.0 §12).
RF_BAND_2G = 0x01
RF_BAND_5G = 0x02
RF_BAND_60G = 0x04


def _attr(attr_id: int, value: bytes) -> bytes:
    """Encode a single WSC attribute as type(2) || length(2) || value."""
    return struct.pack("!HH", attr_id, len(value)) + value


def parse_attributes(payload: bytes) -> list[tuple[int, bytes]]:
    """Decode a WSC attribute stream into ``(type, value)`` pairs."""
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(payload):
        attr_id, length = struct.unpack_from("!HH", payload, offset)
        offset += 4
        if offset + length > len(payload):
            raise ValueError(f"WSC attribute 0x{attr_id:04x} truncated")
        out.append((attr_id, payload[offset : offset + length]))
        offset += length
    return out


def _int_to_pk(n: int) -> bytes:
    """Encode a DH public value as a fixed-width 192-byte big-endian field."""
    return n.to_bytes(_PK_BYTES, "big")


def _pk_to_int(buf: bytes) -> int:
    return int.from_bytes(buf, "big")


@dataclass(slots=True)
class WscEnrolleeSession:
    """State a WSC enrollee must keep between sending M1 and processing M2.

    One session per radio per BSS-configuration round-trip — Multi-AP
    creates a fresh M1 (and so a fresh session) on every Autoconfig Renew.
    """

    enrollee_mac: bytes
    rf_band: int = RF_BAND_2G
    manufacturer: bytes = b"ieee1905-suite"
    model_name: bytes = b"emulator"
    model_number: bytes = b"1"
    serial_number: bytes = b"0"
    device_name: bytes = b"agent-emulator"

    enrollee_nonce: bytes = field(default_factory=lambda: os.urandom(16))
    uuid_e: bytes = field(default_factory=lambda: uuid.uuid4().bytes)

    _dh_private: int = 0
    _dh_public: int = 0

    m1_bytes: bytes = b""

    def __post_init__(self) -> None:
        # Random 1536-bit private exponent, public = g^private mod p.
        self._dh_private = int.from_bytes(os.urandom(_PK_BYTES), "big") % (_DH_P - 1)
        if self._dh_private < 2:
            self._dh_private = 2
        self._dh_public = pow(_DH_G, self._dh_private, _DH_P)

    @property
    def public_key(self) -> bytes:
        return _int_to_pk(self._dh_public)

    def build_m1(self) -> bytes:
        """Return the WSC M1 attribute stream the agent should send."""
        # Primary Device Type (WPS v2.0 §12): 2B category | 4B OUI | 2B subcategory.
        # 0x0006 = "Network Infrastructure", 0x00 50 F2 04 = Wi-Fi Alliance OUI,
        # subcategory 0x0001 = Access Point.
        pdt = bytes.fromhex("0006") + bytes.fromhex("0050f204") + bytes.fromhex("0001")

        attrs = (
            _attr(ATTR_VERSION, bytes([0x10]))
            + _attr(ATTR_MESSAGE_TYPE, bytes([WSC_MSG_M1]))
            + _attr(ATTR_UUID_E, self.uuid_e)
            + _attr(ATTR_MAC_ADDRESS, self.enrollee_mac)
            + _attr(ATTR_ENROLLEE_NONCE, self.enrollee_nonce)
            + _attr(ATTR_PUBLIC_KEY, self.public_key)
            # WPA-PSK (0x0002) | WPA2-PSK (0x0020) | SAE (0x0100).
            + _attr(ATTR_AUTH_TYPE_FLAGS, struct.pack("!H", 0x0122))
            # NONE (0x0001) | AES (0x0008).
            + _attr(ATTR_ENCR_TYPE_FLAGS, struct.pack("!H", 0x0009))
            + _attr(ATTR_CONN_TYPE_FLAGS, bytes([0x01]))  # ESS
            + _attr(ATTR_CONFIG_METHODS, struct.pack("!H", 0x2008))  # PBC + virtual PBC
            + _attr(ATTR_WPS_STATE, bytes([0x01]))  # Not configured
            + _attr(ATTR_MANUFACTURER, self.manufacturer)
            + _attr(ATTR_MODEL_NAME, self.model_name)
            + _attr(ATTR_MODEL_NUMBER, self.model_number)
            + _attr(ATTR_SERIAL_NUMBER, self.serial_number)
            + _attr(ATTR_PRIMARY_DEVICE_TYPE, pdt)
            + _attr(ATTR_DEVICE_NAME, self.device_name)
            + _attr(ATTR_RF_BANDS, bytes([self.rf_band]))
            + _attr(ATTR_ASSOCIATION_STATE, struct.pack("!H", 0x0000))
            + _attr(ATTR_DEVICE_PASSWORD_ID, struct.pack("!H", 0x0004))  # PushButton
            + _attr(ATTR_CONFIG_ERROR, struct.pack("!H", 0x0000))
            + _attr(ATTR_OS_VERSION, struct.pack("!I", 0x80000001))
        )
        self.m1_bytes = attrs
        return attrs


def _kdf(kdk: bytes, total_bits: int = 640) -> bytes:
    """WPS v2.0 §6.3 KDF — HMAC-SHA256 in iterative counter mode."""
    label = b"Wi-Fi Easy and Secure Key Derivation"
    out = bytearray()
    iterations = (total_bits + 255) // 256
    for i in range(1, iterations + 1):
        prf_input = struct.pack("!I", i) + label + struct.pack("!I", total_bits)
        out.extend(hmac.new(kdk, prf_input, sha256).digest())
    return bytes(out)


@dataclass(slots=True)
class WscKeys:
    auth_key: bytes
    key_wrap_key: bytes
    emsk: bytes


def derive_keys(
    session: WscEnrolleeSession, registrar_public_key: bytes, registrar_nonce: bytes
) -> WscKeys:
    """Derive WSC session keys from the completed DH exchange."""
    r_pub_int = _pk_to_int(registrar_public_key)
    shared = pow(r_pub_int, session._dh_private, _DH_P)
    dh_key = sha256(_int_to_pk(shared)).digest()
    kdk = hmac.new(
        dh_key,
        session.enrollee_nonce + session.enrollee_mac + registrar_nonce,
        sha256,
    ).digest()
    block = _kdf(kdk, 640)
    return WscKeys(
        auth_key=block[0:32],
        key_wrap_key=block[32:48],
        emsk=block[48:80],
    )


def verify_authenticator(keys: WscKeys, m1: bytes, m2: bytes) -> bool:
    """Validate M2's outer Authenticator attribute against ``M1 || M2-without-auth``.

    Per WPS v2.0 §8.3.2 the Authenticator attribute is always the last
    attribute in the message, so the strip / compare is purely positional.
    """
    if len(m2) < 12:
        return False
    aid, length = struct.unpack_from("!HH", m2, len(m2) - 12)
    if aid != ATTR_AUTHENTICATOR or length != 8:
        return False
    expected = m2[-8:]
    m2_stripped = m2[:-12]
    mac = hmac.new(keys.auth_key, m1 + m2_stripped, sha256).digest()[:8]
    return hmac.compare_digest(mac, expected)


def decrypt_encrypted_settings(keys: WscKeys, encrypted: bytes) -> bytes:
    """AES-128-CBC decrypt and validate Encrypted Settings (WPS v2.0 §6.5).

    Returns the inner attribute stream with the Key Wrap Authenticator stripped.
    Raises ``ValueError`` if padding, framing, or KWA verification fails.
    """
    if len(encrypted) < 16 or (len(encrypted) - 16) % 16 != 0:
        raise ValueError("Encrypted Settings payload not aligned to AES block size")
    iv, ciphertext = encrypted[:16], encrypted[16:]
    cipher = Cipher(
        algorithms.AES(keys.key_wrap_key), modes.CBC(iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # PKCS#7 padding removal.
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("invalid Encrypted Settings PKCS#7 padding")
    plaintext = padded[:-pad_len]
    # KWA is the final 12-byte attribute (0x101E, length 8).
    if len(plaintext) < 12:
        raise ValueError("Encrypted Settings plaintext too short for Key Wrap Authenticator")
    kwa_aid, kwa_len = struct.unpack_from("!HH", plaintext, len(plaintext) - 12)
    if kwa_aid != ATTR_KEY_WRAP_AUTH or kwa_len != 8:
        raise ValueError("Key Wrap Authenticator attribute missing or malformed")
    inner = plaintext[:-12]
    expected_kwa = plaintext[-8:]
    actual_kwa = hmac.new(keys.auth_key, inner, sha256).digest()[:8]
    if not hmac.compare_digest(actual_kwa, expected_kwa):
        raise ValueError("Key Wrap Authenticator mismatch")
    return inner


@dataclass(slots=True)
class BssCredential:
    """A single AP credential extracted from M2's Encrypted Settings."""

    ssid: bytes
    auth_type: int
    encr_type: int
    network_key: bytes
    mac_address: bytes


def parse_credentials(inner: bytes) -> list[BssCredential]:
    """Extract AP credentials from the decrypted Encrypted Settings."""
    creds: list[BssCredential] = []
    for attr_id, val in parse_attributes(inner):
        # M2 wraps each Credential in attribute 0x100E whose value is itself
        # an attribute stream (WPS v2.0 §11).
        if attr_id != 0x100E:
            continue
        ssid = b""
        auth = encr = 0
        key = mac = b""
        for sub_id, sub_val in parse_attributes(val):
            if sub_id == ATTR_SSID:
                ssid = sub_val
            elif sub_id == ATTR_AUTH_TYPE:
                auth = int.from_bytes(sub_val, "big")
            elif sub_id == ATTR_ENCR_TYPE:
                encr = int.from_bytes(sub_val, "big")
            elif sub_id == ATTR_NETWORK_KEY:
                key = sub_val
            elif sub_id == ATTR_MAC_ADDRESS:
                mac = sub_val
        creds.append(
            BssCredential(
                ssid=ssid,
                auth_type=auth,
                encr_type=encr,
                network_key=key,
                mac_address=mac,
            )
        )
    return creds
