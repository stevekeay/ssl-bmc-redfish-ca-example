import json
import requests
from ssl_certificate_authority import CA
import urllib3

urllib3.disable_warnings()


def install_drac_ssl_certificate(
    ip, username, password, ca_key_file_name, ca_cert_file_name
):
    """Generate a new signed SSL certificate and upload it to the DRAC

    Certificates are generated on-the-fly using our own CA certificate.  For
    more inforamtion about the one-time process for generating this, see docs
    for ssl_certificate_authority.py.

    The SSL certificate for each DRAC uses the IP address - there are no DNS
    records for our DRACs - all DRAC access is via IP like https://10.x.x.x./


    Example usage:

    from drac_ssl import install_drac_ssl_certificate

    install_drac_ssl_certificate(
        ip="10.46.96.156",
        username="root",
        password="calvin",
        ca_key_file_name="ca_key.pem",
        ca_cert_file_name="ca_cert.pem",
    )

    Raises Exception if the upload fails.

    A diagnostic message is returned.

    If successful, this operation causes some older DRAC cards to reboot which
    makes their API unavailable for a minute or so.  Once they come back up
    the https API should be using the new SSL certificate.

    You can test the SSL verification like:

    curl --cacert ./ca/cert  https://10.46.96.156/redfish/

    An equivalent upload operation can be performed using Dell racadm commands:

    # racadm -r 10.x.x.x -u username -p password sslkeyupload  -t 1 -f key.pem
    # racadm -r 10.x.x.x -u username -p password sslcertupload -t 1 -f cert.pem
    """
    ca = CA(ca_key_file_name, ca_cert_file_name)
    key, cert = ca.generate_signed_certificate(ip)

    redfish_upload_key(ip, username, password, key)
    redfish_upload_cert(ip, username, password, cert)


def redfish_upload_key(drac_ip, username, password, key):
    url = f"https://{drac_ip}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.UploadSSLKey"
    payload = {"SSLKeyString": key}
    redfish_api_post(drac_ip, username, password, url, payload, "SSL key")


def redfish_upload_cert(drac_ip, username, password, cert):
    url = f"https://{drac_ip}/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate"
    payload = {"CertificateType": "Server", "SSLCertificateFile": cert}
    redfish_api_post(drac_ip, username, password, url, payload, "SSL cert")


def redfish_api_post(drac_ip, username, password, url, payload, description):
    headers = {
        "Content-type": "application/json",
        "Accept": "application/json",
    }

    urllib3.disable_warnings() # don't nag about verify=False

    response = requests.post(
        url,
        data=json.dumps(payload),
        headers=headers,
        verify=False,
        auth=(username, password),
    )
    response_data = response.json()
    result = f"DRAC {description} POST to {url=} {response_data=}"

    if response.status_code == 200:
        print(f"Successful {result}")
    else:
        raise Exception(f"Failure HTTP {response.status_code} for {result}")
