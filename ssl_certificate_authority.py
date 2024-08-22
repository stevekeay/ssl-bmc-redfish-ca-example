from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address


class CA:
    """A simple CA that can issue SSL ready-signed certificates

    This module requires a root SSL certificate and signing key.

    To initialise your CA, first generate a key, which must then be kept SECRET.
    If you lose the key, no new certificates can be issued, but any existing
    ones will continue to work:

    `openssl genrsa -out ca_key.pem 4096`

    Then generate your root certificate.  This file should be published.  This
    is the certificate that we "import" so it becomes trusted by the client
    systems that need to make https requests.

    `openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3652 -subj "/CN=Official Corporate CA/OU=Undercloud/O=Rackspace" -out ca_cert.pem`

    Example usage:

    from ssl_certificate_authority import CA

    ca = CA(ca_key_file_name="ca_key.pem", ca_cert_file_name="ca_cert.pem")

    key, cert = ca.generate_signed_certificate("1.2.3.4")
    """

    def __init__(self, ca_key_file_name, ca_cert_file_name):
        self.ca_key = self.load_ca_key_from_pem_file(ca_key_file_name)
        self.ca_cert = self.load_ca_cert_from_pem_file(ca_cert_file_name)

    def generate_signed_certificate(
        self,
        ip_addr: str,
        o="Rackspace",
        ou="Undercloud BMC",
        start_date=None,
        validity_days=3692,
    ):
        """Generate a new SSL key and certificate signed by this CA

        >>> ca = CA(ca_key_file_name="ca_key.pem", ca_cert_file_name="ca_cert.pem")
        >>> ca.generate_signed_certificate("1.2.3.4")
        ['-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...
        """

        if start_date is None:
            start_date = datetime.now(timezone.utc)

        key = self.generate_rsa_key()

        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, o),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, ip_addr),
            ]
        )
        alt_name = x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv4Address(ip_addr)),
                x509.DNSName(ip_addr),
            ]
        )

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(subject)
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(key.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(start_date)
        cert = cert.not_valid_after(start_date + timedelta(days=validity_days))
        cert = cert.add_extension(alt_name, critical=False)
        cert = cert.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        cert = cert.sign(self.ca_key, hashes.SHA256())

        cert = cert.public_bytes(serialization.Encoding.PEM).decode()

        key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        return [key, cert]

    def load_ca_key_from_pem_file(self, file_name):
        pem_data = self.read_pem_file(file_name)
        return serialization.load_pem_private_key(pem_data, password=None)

    def load_ca_cert_from_pem_file(self, file_name):
        pem_data = self.read_pem_file(file_name)
        return x509.load_pem_x509_certificate(pem_data)

    def read_pem_file(self, file_name):
        with open(file_name, "rb") as file:
            return file.read()

    def generate_rsa_key(self, key_size=2048, public_exponent=65537):
        return rsa.generate_private_key(
            public_exponent=public_exponent, key_size=key_size
        )
