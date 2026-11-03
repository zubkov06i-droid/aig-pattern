"""Самоподписанный TLS-сертификат для Ingress (хост aig.local) -> tls/tls.crt, tls/tls.key."""

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

out = pathlib.Path(__file__).resolve().parents[1] / "tls"
out.mkdir(exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aig.local")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("aig.local")]), critical=False
    )
    .sign(key, hashes.SHA256())
)
(out / "tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(out / "tls.key").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
print(f"сертификат: {out / 'tls.crt'}")
