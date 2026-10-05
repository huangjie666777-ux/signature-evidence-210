from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto import algos, cms, core, tsp, x509 as asn1x509
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from signature_evidence210.config import Settings
from signature_evidence210.main import create_app
from signature_evidence210.pki import PKIError, ensure_pki
from signature_evidence210.rfc3161 import TimeStampRespOut
from signature_evidence210.store import ReceiptStore

POLICY = "1.3.6.1.4.1.99999.210.1"


def make_settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture()
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture()
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


def build_query(digest_name="sha256", nonce=0x1234ABCD, cert_req=True,
                policy=None, tamper_len=None, version=1, extensions=None):
    algo = {"sha256": hashlib.sha256, "sha384": hashlib.sha384,
            "sha1": hashlib.sha1}[digest_name]
    digest = algo(b"archive-summary").digest()
    if tamper_len is not None:
        digest = digest[:tamper_len]
    req = {
        "version": version,
        "message_imprint": {
            "hash_algorithm": {"algorithm": digest_name},
            "hashed_message": digest,
        },
        "cert_req": cert_req,
    }
    if nonce is not None:
        req["nonce"] = nonce
    if policy is not None:
        req["req_policy"] = policy
    if extensions is not None:
        req["extensions"] = extensions
    return tsp.TimeStampReq(req).dump()


def post(client, data: bytes):
    return client.post(
        "/tsa", content=data,
        headers={"Content-Type": "application/timestamp-query"},
    )


def status_of(resp):
    assert resp.headers["content-type"] == "application/timestamp-reply"
    parsed = TimeStampRespOut.load(resp.content)
    return parsed, parsed["status"]


def granted_token(resp):
    parsed, status = status_of(resp)
    assert status["status"].native == "granted", status.native
    token = parsed["time_stamp_token"]
    tst = tsp.TSTInfo.load(token["content"]["encap_content_info"]["content"].contents)
    return parsed, token, tst


def test_granted_sha256_with_nonce_and_cert(client):
    resp = post(client, build_query())
    parsed, token, tst = granted_token(resp)
    assert tst["nonce"].native == 0x1234ABCD
    assert tst["policy"].dotted == POLICY
    assert tst["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert tst["message_imprint"]["hashed_message"].native == hashlib.sha256(
        b"archive-summary").digest()
    assert tst["serial_number"].native > 0
    assert len(token["content"]["certificates"]) == 2  # signer + CA
    attr_types = [a["type"].native for a in token["content"]["signer_infos"][0]["signed_attrs"]]
    assert "signing_certificate" in attr_types  # ESS cert binding


def test_granted_sha384_without_nonce_without_cert(client):
    resp = post(client, build_query(digest_name="sha384", nonce=None, cert_req=False))
    parsed, token, tst = granted_token(resp)
    assert isinstance(tst["nonce"], core.Void)
    assert tst["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha384"
    assert len(token["content"]["certificates"]) == 0


def test_reject_sha1(client):
    resp = post(client, build_query(digest_name="sha1"))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"bad_alg"}
    assert isinstance(TimeStampRespOut.load(resp.content)["time_stamp_token"], core.Void)


def test_reject_bad_digest_length(client):
    resp = post(client, build_query(tamper_len=16))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"bad_data_format"}


def test_reject_trailing_bytes(client):
    resp = post(client, build_query() + b"\x00\x00")
    _, status = status_of(resp)
    assert status["status"].native == "rejection"


def test_reject_unknown_policy(client):
    resp = post(client, build_query(policy="1.2.3.4.5"))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"unaccepted_policy"}


def test_accept_configured_policy(client):
    resp = post(client, build_query(policy=POLICY))
    _, token, tst = granted_token(resp)
    assert tst["policy"].dotted == POLICY


def test_reject_extensions(client):
    ext = [{"extn_id": "1.2.3.4", "critical": False, "extn_value": b"\x05\x00"}]
    resp = post(client, build_query(extensions=ext))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"unaccepted_extensions"}


def test_reject_version_2(client):
    resp = post(client, build_query(version=2))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"bad_request"}


def test_serials_unique_persistent_and_receipt_fetch(client, settings):
    serials = []
    for _ in range(3):
        _, _, tst = granted_token(post(client, build_query(nonce=None)))
        serials.append(tst["serial_number"].native)
    assert len(set(serials)) == 3
    assert serials == sorted(serials)

    for serial in serials:
        r = client.get(f"/tsa/receipt/{serial}")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/timestamp-reply"
        tsp.TimeStampResp.load(r.content)  # parses

    assert client.get("/tsa/receipt/999999").status_code == 404

    # restart with the same data dir keeps serials unique
    app2 = create_app(settings)
    with TestClient(app2) as client2:
        _, _, tst = granted_token(post(client2, build_query(nonce=None)))
        assert tst["serial_number"].native > max(serials)


def test_clock_rollback_refuses(client, settings):
    granted_token(post(client, build_query(nonce=None)))
    store = ReceiptStore(settings.db_path)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    store.record(10_000_000, future, b"\x30\x00")
    store.close()
    resp = post(client, build_query(nonce=None))
    _, status = status_of(resp)
    assert status["status"].native == "rejection"
    assert status["fail_info"].native == {"time_not_available"}


def test_cert_endpoints(client):
    r = client.get("/tsa/cert")
    assert r.status_code == 200
    assert b"BEGIN CERTIFICATE" in r.content
    r = client.get("/tsa/chain")
    assert r.content.count(b"BEGIN CERTIFICATE") == 2


def test_wrong_content_type(client):
    r = client.post("/tsa", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415


def test_oversize_request(client, settings):
    big = b"0" * (settings.max_request_bytes + 1)
    r = client.post("/tsa", content=big,
                    headers={"Content-Type": "application/timestamp-query"})
    assert r.status_code == 413


def test_concurrent_serials_unique(client):
    from concurrent.futures import ThreadPoolExecutor

    def one(_):
        for _ in range(20):
            resp = post(client, build_query(nonce=None))
            if resp.status_code == 200:
                _, _, tst = granted_token(resp)
                return tst["serial_number"].native
            assert resp.status_code == 503
        raise AssertionError("server stayed busy")

    with ThreadPoolExecutor(max_workers=8) as pool:
        serials = list(pool.map(one, range(16)))
    assert len(set(serials)) == 16


def test_key_mismatch_refuses_startup(settings):
    ensure_pki(settings)
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings.tsa_key_path.write_bytes(other.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    with pytest.raises(PKIError):
        ensure_pki(settings)


def test_missing_key_refuses_startup(settings):
    ensure_pki(settings)
    settings.tsa_key_path.unlink()
    with pytest.raises(PKIError):
        ensure_pki(settings)


def test_tsa_cert_eku(settings):
    ensure_pki(settings)
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(settings.tsa_cert_path.read_bytes())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert eku.critical
    assert [o.dotted_string for o in eku.value] == ["1.3.6.1.5.5.7.3.8"]


def test_openssl_verify_and_tamper_rejection(client, settings, tmp_path):
    message = b"archive-summary"
    query = build_query(nonce=None)
    resp = post(client, query)
    granted_token(resp)

    work = tmp_path / "verify"
    work.mkdir()
    (work / "msg.bin").write_bytes(message)
    (work / "resp.tsr").write_bytes(resp.content)
    ok = subprocess.run(
        ["openssl", "ts", "-verify", "-data", str(work / "msg.bin"),
         "-in", str(work / "resp.tsr"), "-CAfile", str(settings.ca_cert_path)],
        capture_output=True)
    assert ok.returncode == 0, ok.stderr.decode()

    tampered = bytearray(resp.content)
    tampered[-20] ^= 0xFF
    (work / "bad.tsr").write_bytes(bytes(tampered))
    bad = subprocess.run(
        ["openssl", "ts", "-verify", "-data", str(work / "msg.bin"),
         "-in", str(work / "bad.tsr"), "-CAfile", str(settings.ca_cert_path)],
        capture_output=True)
    assert bad.returncode != 0
