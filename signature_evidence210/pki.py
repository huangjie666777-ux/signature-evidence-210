"""Demo PKI bootstrap and startup validation.

Generates a self-signed demo root CA and an RSA TSA certificate whose
extended key usage is exactly critical timeStamping. On restart the
existing material is reused, but only after the private keys are proven
to match the certificates. Private keys never leave the data directory.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import Settings


class PKIError(RuntimeError):
    """Raised when key material is missing, inconsistent, or invalid."""


def _write_private_key(path: Path, key) -> None:
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _generate(settings: Settings) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo TSA Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo TSA Signer")])
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(tsa_name)
        .issuer_name(ca_cert.subject)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(settings.ca_key_path, ca_key)
    _write_private_key(settings.tsa_key_path, tsa_key)
    settings.ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    settings.tsa_cert_path.write_bytes(tsa_cert.public_bytes(serialization.Encoding.PEM))


def _load_key(path: Path):
    if not path.is_file():
        raise PKIError(f"private key missing: {path}")
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise PKIError(f"cannot load private key {path}: {exc}") from exc


def _load_cert(path: Path) -> x509.Certificate:
    if not path.is_file():
        raise PKIError(f"certificate missing: {path}")
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except Exception as exc:
        raise PKIError(f"cannot load certificate {path}: {exc}") from exc


def _public_bytes(key_or_cert) -> bytes:
    pub = key_or_cert.public_key()
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _validate(settings: Settings) -> None:
    ca_key = _load_key(settings.ca_key_path)
    tsa_key = _load_key(settings.tsa_key_path)
    ca_cert = _load_cert(settings.ca_cert_path)
    tsa_cert = _load_cert(settings.tsa_cert_path)

    if _public_bytes(ca_key) != _public_bytes(ca_cert):
        raise PKIError("CA private key does not match CA certificate")
    if _public_bytes(tsa_key) != _public_bytes(tsa_cert):
        raise PKIError("TSA private key does not match TSA certificate")

    try:
        eku = tsa_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as exc:
        raise PKIError("TSA certificate has no extended key usage") from exc
    if not eku.critical:
        raise PKIError("TSA EKU extension must be critical")
    if list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise PKIError("TSA EKU must contain only timeStamping")

    ca_cert.public_key().verify(
        tsa_cert.signature,
        tsa_cert.tbs_certificate_bytes,
        padding=padding.PKCS1v15(),
        algorithm=tsa_cert.signature_hash_algorithm,
    )


def _write_openssl_cnf(settings: Settings) -> None:
    settings.openssl_cnf_path.write_text(
        "[tsa]\n"
        "default_tsa = tsa_section\n"
        "[tsa_section]\n"
        f"serial = {settings.serial_file_path}\n"
        "crypto_device = builtin\n"
        "signer_digest = sha256\n"
        "digests = sha256, sha384\n"
        "tsa_name = no\n"
        "ess_cert_id_chain = no\n"
    )


def ensure_pki(settings: Settings) -> None:
    """Create demo key material in an empty dir, else validate existing."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    present = [
        p
        for p in (
            settings.ca_key_path,
            settings.ca_cert_path,
            settings.tsa_key_path,
            settings.tsa_cert_path,
        )
        if p.exists()
    ]
    if not present:
        _generate(settings)
    elif len(present) != 4:
        missing = [str(p) for p in (
            settings.ca_key_path,
            settings.ca_cert_path,
            settings.tsa_key_path,
            settings.tsa_cert_path,
        ) if not p.exists()]
        raise PKIError("incomplete PKI material, missing: " + ", ".join(missing))
    _validate(settings)
    _write_openssl_cnf(settings)
