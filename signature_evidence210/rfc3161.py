"""RFC 3161 request validation and response generation.

Validation is pure Python (asn1crypto). Signing is delegated to the
OpenSSL 'ts -reply' sub-process with a hard timeout, running in a
temporary directory that is always cleaned up. Serial numbers are
allocated from the SQLite store and handed to OpenSSL through its
serial file; the serial actually used is read back from the token and
persisted together with the receipt, atomically. Any failure leaves no
success record behind.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Optional

from asn1crypto import cms, core, tsp

from .config import Settings
from .store import ClockRollbackError, ReceiptStore

ALLOWED_DIGESTS = {"sha256": 32, "sha384": 48}


class TimeStampRespOut(core.Sequence):
    """TimeStampResp with optional token (asn1crypto marks it required)."""

    _fields = [
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


@dataclass
class ParsedQuery:
    der: bytes
    digest_name: str
    cert_req: bool


def _status_response(status: str, fail_info: Optional[str] = None,
                     status_string: Optional[str] = None) -> bytes:
    info = {"status": status}
    if status_string:
        info["status_string"] = [status_string]
    if fail_info:
        info["fail_info"] = {fail_info}
    return TimeStampRespOut({"status": info}).dump()


def failure_response(fail_info: str, status_string: str) -> bytes:
    return _status_response("rejection", fail_info, status_string)


def system_failure_response(status_string: str) -> bytes:
    return _status_response("rejection", "system_failure", status_string)


def parse_query(data: bytes) -> ParsedQuery:
    """Validate a TimeStampReq DER blob or raise ValueError((fail_info, msg))."""
    try:
        req = tsp.TimeStampReq.load(data)
    except (ValueError, TypeError) as exc:
        raise ValueError(("bad_data_format", f"malformed TimeStampReq: {exc}")) from exc
    if req.dump() != data:
        raise ValueError(("bad_data_format", "trailing or non-canonical bytes in request"))

    if req["version"].native != "v1":
        raise ValueError(("bad_request", "only version 1 requests are supported"))

    imprint = req["message_imprint"]
    digest_name = imprint["hash_algorithm"]["algorithm"].native
    if digest_name not in ALLOWED_DIGESTS:
        raise ValueError(("bad_alg", f"unsupported digest algorithm: {digest_name}"))
    digest = imprint["hashed_message"].native
    if len(digest) != ALLOWED_DIGESTS[digest_name]:
        raise ValueError((
            "bad_data_format",
            f"digest length {len(digest)} does not match {digest_name}",
        ))

    return ParsedQuery(der=data, digest_name=digest_name,
                       cert_req=bool(req["cert_req"].native))


def check_request_constraints(req: tsp.TimeStampReq, settings: Settings) -> Optional[bytes]:
    """Return an error TimeStampResp DER if policy/extension rules fail."""
    extensions = req["extensions"]
    if len(extensions) > 0:
        return failure_response("unaccepted_extensions", "request extensions are not accepted")
    policy = req["req_policy"]
    if policy.native is not None:
        oid = policy.dotted
        if oid not in settings.accepted_policies:
            return failure_response("unaccepted_policy", f"policy {oid} is not accepted")
    return None


def validate(data: bytes, settings: Settings):
    """Return (ParsedQuery, None) or (None, error_response_der)."""
    try:
        parsed = parse_query(data)
    except ValueError as exc:
        fail_info, message = exc.args[0]
        return None, failure_response(fail_info, message)
    req = tsp.TimeStampReq.load(data)
    error = check_request_constraints(req, settings)
    if error is not None:
        return None, error
    return parsed, None


def _run_openssl_reply(settings: Settings, query_der: bytes, serial: int) -> bytes:
    with tempfile.TemporaryDirectory(prefix="tsa-sign-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "query.der").write_bytes(query_der)
        settings.serial_file_path.write_text(format(serial, "02X") + "\n")
        cmd = [
            "openssl", "ts", "-reply",
            "-config", str(settings.openssl_cnf_path),
            "-queryfile", str(tmpdir / "query.der"),
            "-signer", str(settings.tsa_cert_path),
            "-inkey", str(settings.tsa_key_path),
            "-chain", str(settings.ca_cert_path),
            "-tspolicy", settings.default_policy_oid,
            "-out", str(tmpdir / "resp.der"),
        ]
        proc = subprocess.run(
            cmd, capture_output=True, timeout=settings.sign_timeout_seconds
        )
        out_path = tmpdir / "resp.der"
        if proc.returncode != 0 or not out_path.is_file():
            raise RuntimeError(
                "openssl ts -reply failed: " + proc.stderr.decode(errors="replace").strip()
            )
        return out_path.read_bytes()


def _token_fields(resp_der: bytes):
    resp = tsp.TimeStampResp.load(resp_der)
    token = resp["time_stamp_token"]
    tst = tsp.TSTInfo.load(token["content"]["encap_content_info"]["content"].contents)
    return resp, tst


def issue(data: bytes, settings: Settings, store: ReceiptStore) -> bytes:
    """Validate, sign and record a timestamp. Always returns DER bytes."""
    parsed, error = validate(data, settings)
    if error is not None:
        return error

    with store.lock():
        try:
            store.check_clock()
        except ClockRollbackError as exc:
            return failure_response("time_not_available", str(exc))

        serial_hint = store.next_serial()
        try:
            resp_der = _run_openssl_reply(settings, parsed.der, serial_hint)
        except subprocess.TimeoutExpired:
            return system_failure_response("signing process timed out")
        except (RuntimeError, OSError) as exc:
            return system_failure_response(f"signing failed: {exc}")

        try:
            resp, tst = _token_fields(resp_der)
        except Exception as exc:  # defensive: openssl output must parse
            return system_failure_response(f"cannot parse generated token: {exc}")

        serial = tst["serial_number"].native
        gen_time = tst["gen_time"].native
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)

        try:
            store.record(serial, gen_time, resp_der)
        except ValueError as exc:
            return system_failure_response(f"cannot persist receipt: {exc}")

    return resp_der
