#!/usr/bin/env python3

import json
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

known_mva_root_certificates = {
    "DigiCert": "https://cacerts.digicert.com/DigiCertVerifiedMarkRootCA.crt.pem",
    "Entrust": "https://web.entrust.com/root-certificates/VMRC1.cer",
}


def fetch_from_url(pem_url):
    """
    Fetches a PEM certificate from the given URL.

    This function sends a GET request to the specified URL to retrieve a PEM
    certificate. It performs several checks to ensure the response is valid
    and contains the expected certificate content.

    Args:
        pem_url (str): The URL to fetch the PEM certificate from.

    Returns:
        bytes: The content of the PEM certificate.

    Raises:
        ValueError: If the request fails, the response is empty, or the
                    content is not a valid PEM certificate.
    """
    pem_response = requests.get(pem_url)
    if not pem_response.ok:
        raise ValueError(
            f"Failed to fetch certificate. Status code: {pem_response.status_code}"
        )
    if not pem_response.content:
        raise ValueError("No certificate content.")
    if b"BEGIN CERTIFICATE" not in pem_response.content:
        raise ValueError("Invalid certificate content.")
    return pem_response.content


def get_last_in_chain(pem_bytes):
    """
    Get the last certificate in a chain from PEM bytes.

    Args:
        pem_bytes (bytes): PEM formatted certificate bytes.

    Returns:
        bytes: The last certificate in the chain.

    Example:
        >>> pem = b"-----BEGIN CERTIFICATE-----\\nMIIBIjANBgkqh\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIBIjANBgabc\\n-----END CERTIFICATE-----\\n"
        >>> last_cert = get_last_in_chain(pem)
        >>> b"MIIBIjANBgkqh" not in last_cert
        True
        >>> b"MIIBIjANBgabc" in last_cert
        True
    """
    begin_bytes = b"-----BEGIN CERTIFICATE-----"
    all_pems = pem_bytes.split(begin_bytes)
    last_pem = begin_bytes + all_pems[-1]
    return last_pem


def format_hex(obj):
    """
    Format a hex object to a consistent hexadecimal string.

    Args:
        obj (bytes, int, str): The object to convert.

    Returns:
        str: The hexadecimal representation of the object.

    Example:
        >>> format_hex(b"Testing!")
        '54:65:73:74:69:6E:67:21'
        >>> format_hex(255)
        'FF'
        >>> format_hex(100000)
        '01:86:A0'
        >>> format_hex("de:ad:be:ef")
        'DE:AD:BE:EF'
    """
    hex_str = None

    if type(obj) is bytes:
        hex_str = obj.hex()
    elif type(obj) is int:
        hex_str = obj.to_bytes((obj.bit_length() + 7) // 8, "big").hex()
    elif type(obj) is str:
        hex_str = obj

    # replace all non-hex characters
    hex_str = "".join(c for c in hex_str if c in "0123456789abcdefABCDEF")

    if hex_str:
        return ":".join(hex_str[i : i + 2].upper() for i in range(0, len(hex_str), 2))

    return None


def fetch_and_format_cert(obj=None, as_dict=False, as_json=False):
    """
    Fetch and format a certificate.

    Args:
        obj (str, bytes): The certificate object, either the source URL or PEM bytes.
        as_dict (bool): Whether to return the certificate as a dictionary.
        as_json (bool): Whether to return the certificate as a JSON string.

    Returns:
        dict or str: The formatted certificate.

    Raises:
        ValueError: If no or invalid certificate object is provided.
    """
    if obj is None:
        raise ValueError("No certificate object provided.")

    pem_bytes = None
    cert = None

    if type(obj) is str and obj.startswith("https://"):
        pem_bytes = fetch_from_url(obj)
    elif type(obj) is str and obj.startswith("-----BEGIN CERTIFICATE-----"):
        pem_bytes = obj.encode("utf-8")

    if type(obj) is bytes:
        pem_bytes = obj

    if pem_bytes is None:
        raise ValueError("No certificate bytes.")

    pem_bytes = get_last_in_chain(pem_bytes)
    cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    if not cert:
        raise ValueError("Invalid certificate bytes.")

    fingerprint_sha256_raw = cert.fingerprint(hashes.SHA256()).hex()
    fingerprint_sha256 = format_hex(fingerprint_sha256_raw)

    cert_obj = {
        "serial_number": cert.serial_number,
        "serial_hex": format_hex(cert.serial_number),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": fingerprint_sha256,
    }

    if as_dict:
        return cert_obj

    if as_json:
        return json.dumps(cert_obj)

    txt_string = "\n".join(
        [
            f'# Issuer: {cert_obj["issuer"]}',
            f'# Subject: {cert_obj["subject"]}',
            f'# Serial: {cert_obj["serial_hex"]}',
            f'# Not Valid Before: {cert_obj["not_valid_before"]}',
            f'# Not Valid After: {cert_obj["not_valid_after"]}',
            f'# SHA256 Fingerprint: {cert_obj["fingerprint_sha256"]}',
            pem_bytes.decode("utf-8"),
        ]
    )

    return txt_string


if __name__ == "__main__":
    for cert_name, cert_url in known_mva_root_certificates.items():
        cert_txt = fetch_and_format_cert(cert_url)
        print(cert_txt)
