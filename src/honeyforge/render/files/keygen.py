"""Runs once during `docker build` to mint per-image key material, so the read-only
container never generates keys at runtime and never presents OpenCanary's default
(widely fingerprinted) certificate subject.

Usage: python keygen.py SSH_DIR CERT_PATH KEY_PATH ORG CN [SAN ...]
"""

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.x509.oid import NameOID


def _write(path, data, mode=0o640):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def ssh_keys(directory):
    # Same filenames/formats OpenCanary's ssh module reads from ssh.key_path.
    for name, key in (("id_rsa", rsa.generate_private_key(public_exponent=65537, key_size=3072)),
                      ("id_dsa", dsa.generate_private_key(key_size=1024))):
        pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        _write(os.path.join(directory, name), _pem(key))
        _write(os.path.join(directory, name + ".pub"), pub, 0o644)


def tls_cert(cert_path, key_path, org, cn, sans):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=30))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in [cn, *sans]]), critical=False)
            .sign(key, hashes.SHA256()))
    _write(key_path, _pem(key))
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)


if __name__ == "__main__":
    ssh_dir, cert_path, key_path, org, cn, *sans = sys.argv[1:]
    ssh_keys(ssh_dir)
    tls_cert(cert_path, key_path, org, cn, sans)
