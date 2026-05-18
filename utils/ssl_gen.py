import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def ensure_ssl_certificates(cert_file: str, key_file: str):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("⚡ 未检测到本地 SSL 证书，正在通过 Cryptography 引擎为您动态硬核签发自签名证书...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Fujian"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Fuzhou"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSO Local Dev Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "192.168.1.5"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("192.168.1.5")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("✅ 工业级本地自签名证书生成完毕！已安全写入当前工作目录。")