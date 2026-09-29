"""Ephemeral TLS server and synthetic NPKI inputs for the loopback test."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_certificate import synthetic_material, encrypt_test_key
from test_pfx import synthetic_pfx

root = Path(sys.argv[1])
os.umask(0o077)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LOCAL FIXTURE ONLY")])
now = datetime.now(timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("mob.hometax.go.kr"), x509.DNSName("mob.tbht.hometax.go.kr"),
            x509.DNSName("mob.tbet.hometax.go.kr"),
            x509.DNSName("sesw.hometax.go.kr"),
            x509.DNSName("apct.hometax.go.kr")]), critical=False)
        .sign(key, hashes.SHA256()))
(root / "tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(root / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
certificate, private, _ = synthetic_material(policies=['1.2.410.200004.5.2.1.1'])
(root / "signCert.der").write_bytes(certificate)
(root / "signPri.key").write_bytes(encrypt_test_key(private, b"OFFLINE FIXTURE PASSWORD"))
(root / "certificate.pfx").write_bytes(synthetic_pfx([certificate],[private],b"OFFLINE FIXTURE PASSWORD"))
