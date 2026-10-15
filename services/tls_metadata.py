"""
Passive TLS handshake metadata (no decryption)
===============================================
Reads the *cleartext* TLS handshake header fields that every client and server send
before encryption starts:

  ClientHello → offered version, SNI (when the client sends it), ALPN, cipher-suite /
                extension counts, supported_versions, and the JA3 fingerprint.
  ServerHello → negotiated version and cipher suite.

What this module does NOT do:
  • decrypt anything, or read application data records (content type 23 is ignored);
  • reassemble TCP segments — a ClientHello split across segments (common with large
    post-quantum key shares) yields only the fields present in the first segment and
    is marked `"complete": False`; JA3 is then omitted rather than guessed;
  • compute JA4 — not implemented, reported as unsupported in /health.

JA3 follows the published definition (SSLVersion,Ciphers,Extensions,EllipticCurves,
EllipticCurvePointFormats; GREASE values removed; MD5). It is validated in
tests/test_tls_metadata.py against the reference vector from the JA3 specification.
Only the extracted fields are returned — the payload bytes are never stored.
"""
import hashlib
import struct
from typing import Any, Dict, List, Optional

CONTENT_HANDSHAKE = 22
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

JA4_SUPPORTED = False


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0A0A, 0x1A1A, … 0xFAFA."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def looks_like_tls_handshake(data: bytes) -> bool:
    return len(data) >= 6 and data[0] == CONTENT_HANDSHAKE and data[1] == 0x03 and data[2] <= 0x04


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise IndexError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]


def _u16_list(raw: bytes) -> List[int]:
    return [struct.unpack("!H", raw[i:i + 2])[0] for i in range(0, len(raw) - 1, 2)]


def _parse_extensions(r: _Reader, is_client: bool, out: Dict[str, Any]) -> bool:
    """Parse the extension block into `out`. Returns True when the block was complete."""
    if r.remaining() < 2:
        return r.remaining() == 0  # extensions are optional (pre-TLS1.2 hellos)
    ext_len = r.u16()
    complete = ext_len <= r.remaining()
    block = _Reader(r.take(min(ext_len, r.remaining())))
    ext_types: List[int] = []
    while block.remaining() >= 4:
        etype = block.u16()
        elen = block.u16()
        if elen > block.remaining():
            complete = False
            ext_types.append(etype)
            break
        body = block.take(elen)
        ext_types.append(etype)
        try:
            if etype == EXT_SERVER_NAME and is_client and len(body) >= 5:
                # server_name_list: list_len(2) name_type(1) name_len(2) name
                name_len = struct.unpack("!H", body[3:5])[0]
                if body[2] == 0 and 5 + name_len <= len(body):
                    out["sni"] = body[5:5 + name_len].decode("idna", errors="strict").lower()
            elif etype == EXT_SUPPORTED_GROUPS and is_client and len(body) >= 2:
                glen = struct.unpack("!H", body[:2])[0]
                out["_groups"] = _u16_list(body[2:2 + glen])
            elif etype == EXT_EC_POINT_FORMATS and is_client and len(body) >= 1:
                out["_point_formats"] = list(body[1:1 + body[0]])
            elif etype == EXT_ALPN and len(body) >= 2:
                protos, i, end = [], 2, 2 + struct.unpack("!H", body[:2])[0]
                while i < min(end, len(body)):
                    plen = body[i]
                    protos.append(body[i + 1:i + 1 + plen].decode("ascii", errors="replace"))
                    i += 1 + plen
                out["alpn"] = protos
            elif etype == EXT_SUPPORTED_VERSIONS:
                if is_client and len(body) >= 1:
                    out["_supported_versions"] = _u16_list(body[1:1 + body[0]])
                elif not is_client and len(body) >= 2:
                    out["_selected_version"] = struct.unpack("!H", body[:2])[0]
        except (UnicodeError, IndexError, struct.error):
            pass  # one malformed extension never invalidates the rest of the handshake
    out["_extensions"] = ext_types
    return complete and block.remaining() == 0


def parse_tls_handshake(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse the first handshake message of a TCP segment's TLS record.
    Returns a metadata dict or None when the bytes are not a ClientHello/ServerHello.
    """
    if not looks_like_tls_handshake(data):
        return None
    try:
        r = _Reader(data)
        r.u8()                      # content type
        record_version = r.u16()
        record_len = r.u16()
        hs_type = r.u8()
        if hs_type not in (HS_CLIENT_HELLO, HS_SERVER_HELLO):
            return None
        hs_len = r.u24()
        complete = record_len <= len(data) - 5 and hs_len + 4 <= record_len
        is_client = hs_type == HS_CLIENT_HELLO

        out: Dict[str, Any] = {"handshake": "client_hello" if is_client else "server_hello",
                               "record_version": VERSION_NAMES.get(record_version, hex(record_version))}
        legacy_version = r.u16()
        r.take(32)                  # random
        r.take(r.u8())              # session id
        if is_client:
            ciphers = _u16_list(r.take(r.u16()))
            r.take(r.u8())          # compression methods
        else:
            ciphers = [r.u16()]
            r.u8()                  # compression method
        complete = _parse_extensions(r, is_client, out) and complete
    except IndexError:
        # Header fields themselves are cut off — nothing reliable to report.
        return None

    supported = [v for v in out.pop("_supported_versions", []) if not is_grease(v)]
    selected = out.pop("_selected_version", None)
    exts = out.pop("_extensions", [])
    groups = out.pop("_groups", [])
    point_formats = out.pop("_point_formats", [])

    out["legacy_version"] = VERSION_NAMES.get(legacy_version, hex(legacy_version))
    out["complete"] = bool(complete)
    if is_client:
        out["offered_versions"] = [VERSION_NAMES.get(v, hex(v)) for v in supported] or [out["legacy_version"]]
        out["cipher_suite_count"] = len([c for c in ciphers if not is_grease(c)])
        out["extension_count"] = len([e for e in exts if not is_grease(e)])
        if complete:
            ja3_string = ",".join([
                str(legacy_version),
                "-".join(str(c) for c in ciphers if not is_grease(c)),
                "-".join(str(e) for e in exts if not is_grease(e)),
                "-".join(str(g) for g in groups if not is_grease(g)),
                "-".join(str(p) for p in point_formats),
            ])
            out["ja3_string"] = ja3_string
            out["ja3"] = hashlib.md5(ja3_string.encode("ascii")).hexdigest()
    else:
        version = selected or legacy_version
        out["negotiated_version"] = VERSION_NAMES.get(version, hex(version))
        out["cipher_suite"] = f"0x{ciphers[0]:04x}"
    return out


def capabilities() -> Dict[str, Any]:
    return {
        "builtin_handshake_parser": "available",
        "sni": "available (when sent in a single-segment ClientHello)",
        "ja3": "available (built-in, validated against the JA3 reference vector)",
        "ja4": "unsupported" if not JA4_SUPPORTED else "available",
        "decryption": "never performed",
    }
