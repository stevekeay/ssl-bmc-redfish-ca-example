from ssl_certificate_authority import CA
from datetime import datetime, timezone


def test_ca():
    ca = CA(
        ca_key_file_name="test/test_ca_key.pem",
        ca_cert_file_name="test/test_ca_cert.pem",
    )
    date = datetime(2024, 1, 1, 10, 0, 0, 0, tzinfo=timezone.utc)

    key, cert = ca.generate_signed_certificate("1.2.3.4", start_date=date)

    assert key.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert cert.startswith("-----BEGIN CERTIFICATE-----")
