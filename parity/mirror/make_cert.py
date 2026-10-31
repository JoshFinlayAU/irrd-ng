#!/usr/bin/env python3
"""A throwaway CA and a server certificate for "files", for HTTPS in the
mirroring differential (NRTMv4 clients only accept https and file URLs).

    make_cert.py <outdir>   writes ca.pem, files.pem, files.key
"""
import datetime
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "irrd-ng mirror differential CA")])
ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(hours=1))
    .not_valid_after(now + datetime.timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)
key = ec.generate_private_key(ec.SECP256R1())
cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "files")]))
    .issuer_name(ca_name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(hours=1))
    .not_valid_after(now + datetime.timedelta(days=30))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("files")]), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
    )
    .sign(ca_key, hashes.SHA256())
)
with open(f"{out}/ca.pem", "wb") as f:
    f.write(ca.public_bytes(serialization.Encoding.PEM))
with open(f"{out}/files.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open(f"{out}/files.key", "wb") as f:
    f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
