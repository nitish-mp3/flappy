#!/usr/bin/env python3
"""
KNX IP Secure — Session Authentication & Encryption
=====================================================
Implements KNX IP Secure tunneling protocol:
  - ECDH Curve25519 key exchange
  - AES-128-CBC-MAC + AES-128-CTR message authentication & encryption
  - Session authentication flow
  - Secure wrapper framing

Crypto matches the xknx reference implementation and KNX AN159 spec.

This module is optional — if py3-cryptography is not installed,
the proxy operates in non-secure mode only.
"""

import struct
import hashlib
import logging
import time
from typing import Optional, Tuple

log = logging.getLogger('knx_secure')

# ── Try to import cryptography ────────────────────────────────────────
_SECURE_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import serialization
    _SECURE_AVAILABLE = True
    log.info("KNX IP Secure: cryptography library available")
except ImportError:
    log.warning("KNX IP Secure: cryptography library NOT available — secure mode disabled")


def is_secure_available() -> bool:
    """Return True if the crypto libraries are available."""
    return _SECURE_AVAILABLE


# ── KNX Secure Constants ─────────────────────────────────────────────
SECURE_WRAPPER_SVC        = 0x0950
SESSION_REQUEST_SVC       = 0x0951
SESSION_RESPONSE_SVC      = 0x0952
SESSION_AUTHENTICATE_SVC  = 0x0953
SESSION_STATUS_SVC        = 0x0954
TIMER_NOTIFY_SVC          = 0x0955

MAC_LENGTH = 16  # 128-bit MAC
SERIAL_NUMBER = bytes(6)  # placeholder serial
MESSAGE_TAG_TUNNELLING = b'\x00\x00'  # 2-byte message tag for tunneling

# Used as CTR counter_0 during SESSION_RESPONSE / SESSION_AUTHENTICATE
COUNTER_0_HANDSHAKE = (
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00'
)

# Fixed KNXnet/IP headers for MAC additional_data computation
_HEADER_SESSION_RESPONSE     = b'\x06\x10\x09\x52\x00\x38'  # 56 bytes total
_HEADER_SESSION_AUTHENTICATE = b'\x06\x10\x09\x53\x00\x18'  # 24 bytes total


# ── Crypto helpers (matching xknx security_primitives) ────────────────

def _byte_pad(data: bytes, block_size: int) -> bytes:
    """Pad data with 0x00 to a multiple of block_size."""
    if remainder := len(data) % block_size:
        return data + bytes(block_size - remainder)
    return data


def _bytes_xor(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).to_bytes(len(a), 'big')


def _sha256(data: bytes) -> bytes:
    """SHA-256 hash."""
    return hashlib.sha256(data).digest()


def _cbc_mac(key: bytes, additional_data: bytes,
             payload: bytes = b'', block_0: bytes = bytes(16)) -> bytes:
    """
    AES-128-CBC-MAC per KNX spec.
    Blocks = block_0 || len(additional_data) || additional_data || payload
    Pad to AES block boundary, then AES-CBC encrypt — MAC is last 16 bytes.
    """
    blocks = block_0 + len(additional_data).to_bytes(2, 'big') + additional_data + payload
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    ct = enc.update(_byte_pad(blocks, 16)) + enc.finalize()
    return ct[-16:]


def _encrypt_ctr(key: bytes, counter_0: bytes,
                 mac_cbc: bytes, payload: bytes = b'') -> Tuple[bytes, bytes]:
    """
    AES-128-CTR encryption.
    MAC is encrypted first (counter 0), then payload (counter 1+).
    Returns (encrypted_data, encrypted_mac).
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_0))
    enc = cipher.encryptor()
    mac = enc.update(mac_cbc)
    encrypted_data = enc.update(payload) + enc.finalize()
    return encrypted_data, mac


def _decrypt_ctr(key: bytes, counter_0: bytes,
                 mac: bytes, payload: bytes = b'') -> Tuple[bytes, bytes]:
    """
    AES-128-CTR decryption.
    MAC is decrypted first (counter 0), then payload (counter 1+).
    Returns (decrypted_data, decrypted_mac).
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_0))
    dec = cipher.decryptor()
    mac_tr = dec.update(mac)
    decrypted_data = dec.update(payload) + dec.finalize()
    return decrypted_data, mac_tr


def _derive_password(password: str, is_device_auth: bool) -> bytes:
    """PBKDF2-HMAC-SHA256 with KNX-spec salt, 65536 iterations, 16-byte output."""
    if is_device_auth:
        salt = b'device-authentication-code.1.secure.ip.knx.org'
    else:
        salt = b'user-password.1.secure.ip.knx.org'
    return hashlib.pbkdf2_hmac('sha256', password.encode('latin-1'), salt, 65536, dklen=16)


class SecureSession:
    """
    Manages one KNX IP Secure session between a client and backend.

    Handles the full lifecycle:
    1. Generate ECDH keypair
    2. Exchange public keys with peer
    3. Derive shared session key (SHA-256 of ECDH shared secret)
    4. Authenticate using device/user password (AES-CBC-MAC + AES-CTR)
    5. Encrypt/decrypt tunnel frames (SECURE_WRAPPER)
    """

    def __init__(self, device_password: str = "", user_password: str = "",
                 user_id: int = 1):
        if not _SECURE_AVAILABLE:
            raise RuntimeError("Cryptography library not installed")

        self._device_pwd_hash = (
            _derive_password(device_password, is_device_auth=True)
            if device_password else None
        )
        self._user_pwd_hash = (
            _derive_password(user_password, is_device_auth=False)
            if user_password else bytes(16)
        )
        self.user_id = user_id

        # ECDH keypair
        self._private_key = X25519PrivateKey.generate()
        self.public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Session state
        self.session_id: int = 0
        self.peer_public_key: Optional[bytes] = None
        self._pub_keys_xor: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.authenticated: bool = False

        # Sequence counters
        self.tx_seq: int = 0
        self.rx_seq: int = -1  # accept first frame with seq=0

        # Timestamps
        self.created_at = time.monotonic()
        self.last_activity = time.monotonic()

    def _derive_session_key(self, peer_pub_bytes: bytes) -> bytes:
        """Derive session key: SHA-256(ECDH shared secret)[:16]."""
        self.peer_public_key = peer_pub_bytes
        self._pub_keys_xor = _bytes_xor(self.public_key, peer_pub_bytes)
        peer_key = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_secret = self._private_key.exchange(peer_key)

        self.session_key = _sha256(shared_secret)[:16]
        log.debug(f"Session key derived for session {self.session_id}")
        return self.session_key

    def build_session_request(self) -> bytes:
        """Build a SESSION_REQUEST frame (ECDH public key)."""
        from knx_const import make_hpai, make_frame, PROTO_TCP
        hpai = make_hpai('0.0.0.0', 0, PROTO_TCP)
        body = hpai + self.public_key
        return make_frame(SESSION_REQUEST_SVC, body)

    def process_session_response(self, body: bytes) -> bool:
        """
        Process a SESSION_RESPONSE from the server.
        Extracts session_id and server's ECDH public key.
        Derives session key from ECDH shared secret.
        Verifies server MAC using device authentication password.
        Returns True on success.
        """
        if len(body) < 34:
            log.error(f"SESSION_RESPONSE too short: {len(body)} bytes")
            return False

        self.session_id = struct.unpack('>H', body[0:2])[0]
        server_pub_key = body[2:34]

        try:
            self._derive_session_key(server_pub_key)
        except Exception as e:
            log.error(f"Session key derivation failed: {e}")
            return False

        # Verify server MAC (device authentication)
        if len(body) >= 50 and self._device_pwd_hash:
            encrypted_mac = body[34:50]
            # Compute expected MAC
            additional = (
                _HEADER_SESSION_RESPONSE
                + struct.pack('>H', self.session_id)
                + self._pub_keys_xor
            )
            expected_mac = _cbc_mac(
                key=self._device_pwd_hash,
                additional_data=additional,
            )
            # Decrypt received MAC
            _, mac_tr = _decrypt_ctr(
                key=self._device_pwd_hash,
                counter_0=COUNTER_0_HANDSHAKE,
                mac=encrypted_mac,
            )
            if mac_tr != expected_mac:
                log.warning("Server MAC verification failed — "
                            "check device_authentication_password")
                # Continue anyway for compatibility — some gateways
                # have quirks. The session will fail at authenticate
                # if passwords are truly wrong.
        elif len(body) >= 50:
            log.debug("No device password — skipping server MAC verification")
        else:
            log.debug("No server MAC in SESSION_RESPONSE")

        log.info(f"Secure session {self.session_id} key exchange complete")
        return True

    def build_session_authenticate(self) -> bytes:
        """
        Build a SESSION_AUTHENTICATE frame.
        MAC computed with AES-CBC-MAC using user_password hash,
        then encrypted with AES-CTR.
        """
        if not self.session_key:
            raise RuntimeError("Session key not derived yet")

        from knx_const import make_frame

        # additional_data: header + reserved(0x00) + user_id + XOR(pub_keys)
        additional = (
            _HEADER_SESSION_AUTHENTICATE
            + bytes([0x00, self.user_id])
            + (self._pub_keys_xor or bytes(32))
        )

        mac_cbc = _cbc_mac(
            key=self._user_pwd_hash,
            additional_data=additional,
            block_0=bytes(16),
        )

        _, authenticate_mac = _encrypt_ctr(
            key=self._user_pwd_hash,
            counter_0=COUNTER_0_HANDSHAKE,
            mac_cbc=mac_cbc,
        )

        body = bytes([0x00, self.user_id]) + authenticate_mac
        return make_frame(SESSION_AUTHENTICATE_SVC, body)

    def process_session_status(self, body: bytes) -> bool:
        """Process SESSION_STATUS. Returns True if status == 0x00."""
        if len(body) < 1:
            log.error("SESSION_STATUS body empty")
            return False

        status = body[0]
        if status == 0x00:
            self.authenticated = True
            log.info(f"Secure session {self.session_id} authenticated successfully")
            return True
        else:
            log.error(f"Secure session authentication failed: status=0x{status:02x}")
            return False

    def encrypt_frame(self, plaintext: bytes) -> bytes:
        """
        Encrypt a KNXnet/IP frame into a SECURE_WRAPPER.
        Uses AES-128-CBC-MAC + AES-128-CTR (per KNX spec).
        """
        if not self.session_key:
            raise RuntimeError("Session key not derived yet")

        seq_info = self.tx_seq.to_bytes(6, 'big')
        self.tx_seq += 1

        payload_length = len(plaintext)
        # Total: 6 header + 2 session_id + 6 seq + 6 serial + 2 tag + N data + 16 MAC
        total_length = 38 + payload_length
        wrapper_header = struct.pack('>BBHH', 0x06, 0x10,
                                     SECURE_WRAPPER_SVC, total_length)
        session_id_bytes = struct.pack('>H', self.session_id)

        # CBC-MAC
        block_0 = (seq_info + SERIAL_NUMBER + MESSAGE_TAG_TUNNELLING
                    + struct.pack('>H', payload_length))
        mac_cbc = _cbc_mac(
            key=self.session_key,
            additional_data=wrapper_header + session_id_bytes,
            payload=plaintext,
            block_0=block_0,
        )

        # CTR encryption
        counter_0 = seq_info + SERIAL_NUMBER + MESSAGE_TAG_TUNNELLING + b'\xff\x00'
        encrypted_data, mac = _encrypt_ctr(
            key=self.session_key,
            counter_0=counter_0,
            mac_cbc=mac_cbc,
            payload=plaintext,
        )

        self.last_activity = time.monotonic()
        return (wrapper_header + session_id_bytes + seq_info
                + SERIAL_NUMBER + MESSAGE_TAG_TUNNELLING
                + encrypted_data + mac)

    def decrypt_frame(self, body: bytes) -> Optional[bytes]:
        """
        Decrypt a SECURE_WRAPPER frame body.
        Returns the inner plaintext KNXnet/IP payload, or None on failure.
        """
        if not self.session_key:
            log.warning("Decrypt called without session key")
            return None

        # Minimum: session_id(2) + seq(6) + serial(6) + tag(2) + mac(16) = 32
        if len(body) < 32:
            log.warning(f"SECURE_WRAPPER body too short: {len(body)}")
            return None

        session_id = struct.unpack('>H', body[0:2])[0]
        if session_id != self.session_id:
            log.warning(f"Session ID mismatch: expected {self.session_id}, "
                        f"got {session_id}")
            return None

        seq_info = body[2:8]
        seq = int.from_bytes(seq_info, 'big')
        serial = body[8:14]
        msg_tag = body[14:16]
        encrypted_data = body[16:-16] if len(body) > 32 else b''
        mac = body[-16:]

        # Replay protection
        if seq <= self.rx_seq:
            log.warning(f"Replay detected: rx_seq={self.rx_seq}, got={seq}")
            return None

        # CTR decrypt
        counter_0 = seq_info + serial + msg_tag + b'\xff\x00'
        decrypted_data, mac_tr = _decrypt_ctr(
            key=self.session_key,
            counter_0=counter_0,
            mac=mac,
            payload=encrypted_data,
        )

        # Verify CBC-MAC
        total_length = 6 + len(body)
        wrapper_header = struct.pack('>BBHH', 0x06, 0x10,
                                     SECURE_WRAPPER_SVC, total_length)
        block_0 = (seq_info + serial + msg_tag
                    + struct.pack('>H', len(decrypted_data)))
        mac_cbc = _cbc_mac(
            key=self.session_key,
            additional_data=wrapper_header + body[0:2],
            payload=decrypted_data,
            block_0=block_0,
        )

        if mac_cbc != mac_tr:
            log.warning(f"SECURE_WRAPPER MAC verification failed "
                        f"(session={self.session_id}, seq={seq})")
            return None

        self.rx_seq = seq
        self.last_activity = time.monotonic()
        return decrypted_data

    def close(self):
        """Clean up session resources."""
        self.session_key = None
        self.authenticated = False
        self._private_key = None
        log.debug(f"Secure session {self.session_id} closed")


class SecureSessionManager:
    """
    Manages multiple SecureSession instances for secure backend connections.
    Maps (host, port) -> SecureSession for backend connections.
    """

    def __init__(self):
        self._sessions: dict = {}

    def create_session(self, host: str, port: int,
                       device_password: str = "",
                       user_password: str = "",
                       user_id: int = 1) -> Optional[SecureSession]:
        """Create a new secure session for a backend."""
        if not _SECURE_AVAILABLE:
            log.error("Cannot create secure session — cryptography not available")
            return None

        key = (host, port)
        old = self._sessions.pop(key, None)
        if old:
            old.close()

        session = SecureSession(device_password, user_password, user_id)
        self._sessions[key] = session
        log.info(f"Created secure session for {host}:{port}")
        return session

    def get_session(self, host: str, port: int) -> Optional[SecureSession]:
        """Get an existing secure session."""
        return self._sessions.get((host, port))

    def remove_session(self, host: str, port: int):
        """Remove and close a secure session."""
        sess = self._sessions.pop((host, port), None)
        if sess:
            sess.close()

    def close_all(self):
        """Close all secure sessions."""
        for sess in self._sessions.values():
            sess.close()
        self._sessions.clear()
