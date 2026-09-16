from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_ca(output_dir: Path):
    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    ca_key_path = output_dir / "ca.key"
    ca_cert_path = output_dir / "ca_cert.pem"

    private_key = ec.generate_private_key(ec.SECP256R1())

    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "Warpper",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Warpper CA",
            ),
        ]
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None,
            ),
            critical=True,
        )
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
        .sign(private_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    ca_cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    ca_key_path.chmod(0o600)

    return ca_key_path, ca_cert_path
