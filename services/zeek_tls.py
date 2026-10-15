"""
Optional Zeek TLS enrichment for PCAP analysis
===============================================
When a Zeek binary is available (config ZEEK_BIN, default "zeek" on PATH), uploaded
PCAPs are additionally run through `zeek -r <pcap>` and the resulting ssl.log is read
for handshake metadata Zeek observed (version, cipher, server_name, and ja3/ja3s/ja4
columns when the corresponding Zeek packages are installed). Nothing here is required:
when Zeek is missing the rest of the pipeline runs unchanged and /health says so.

Zeek runs with an argument list (no shell) inside a private temporary directory.
"""
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

_SSL_FIELDS = {
    "version": "version",
    "cipher": "cipher",
    "server_name": "sni",
    "next_protocol": "alpn",
    "established": "established",
    "ja3": "ja3",
    "ja3s": "ja3s",
    "ja4": "ja4",
}


def zeek_path(zeek_bin: str) -> Optional[str]:
    if not zeek_bin:
        return None
    if os.path.isabs(zeek_bin):
        return zeek_bin if os.path.isfile(zeek_bin) else None
    return shutil.which(zeek_bin)


def status(zeek_bin: str) -> Dict[str, Any]:
    path = zeek_path(zeek_bin)
    if not path:
        return {"available": False, "reason": f"Zeek binary '{zeek_bin}' not found; PCAP TLS enrichment uses the built-in parser only."}
    return {"available": True, "path_configured": True}


def parse_ssl_log(path: str) -> Dict[Tuple, Dict[str, Any]]:
    """
    Parse a Zeek TSV ssl.log into {(orig_h, orig_p, resp_h, resp_p): tls metadata}.
    Unknown or unset ("-") columns are omitted rather than filled in.
    """
    out: Dict[Tuple, Dict[str, Any]] = {}
    fields: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#") or not fields:
                continue
            row = dict(zip(fields, line.split("\t")))
            try:
                key = (row["id.orig_h"], int(row["id.orig_p"]), row["id.resp_h"], int(row["id.resp_p"]))
            except (KeyError, ValueError):
                continue
            meta: Dict[str, Any] = {"extraction_source": "zeek"}
            for col, name in _SSL_FIELDS.items():
                val = row.get(col)
                if val not in (None, "", "-", "(empty)"):
                    meta[name] = (val == "T") if col == "established" else val
            out[key] = meta
    return out


def run_on_pcap(pcap_path: str, zeek_bin: str, timeout_s: int = 120) -> Dict[str, Any]:
    """Run Zeek over a PCAP. Returns {"available", "records" (dict), "error"?}."""
    path = zeek_path(zeek_bin)
    if not path:
        return {"available": False, "records": {}, "error": None}
    workdir = tempfile.mkdtemp(prefix="zeek-")
    try:
        proc = subprocess.run(
            [path, "-C", "-r", os.path.abspath(pcap_path)],
            cwd=workdir, capture_output=True, timeout=timeout_s, check=False,
        )
        ssl_log = os.path.join(workdir, "ssl.log")
        if proc.returncode != 0:
            return {"available": True, "records": {}, "error": f"zeek exited with code {proc.returncode}"}
        if not os.path.isfile(ssl_log):
            return {"available": True, "records": {}, "error": None}  # no TLS in this capture
        return {"available": True, "records": parse_ssl_log(ssl_log), "error": None}
    except subprocess.TimeoutExpired:
        return {"available": True, "records": {}, "error": f"zeek timed out after {timeout_s}s"}
    except OSError as exc:
        return {"available": False, "records": {}, "error": f"zeek could not be started: {exc.strerror or exc}"}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
