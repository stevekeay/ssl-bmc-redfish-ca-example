## SSL On BMC/DRAC

This code was a starting point to make a workflow.

## Dependencies:

- cryptography
- requests

## sample usage:

```python
from drac_ssl import install_drac_ssl_certificate

install_drac_ssl_certificate(
    ip="10.46.96.156",
    username="root",
    password="calvin",
    ca_key_file_name="ca/key",
    ca_cert_file_name="ca/cert",
)
```
