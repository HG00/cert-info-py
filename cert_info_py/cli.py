import socket
import ssl
import argparse
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def fetch_certificate(host, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(), server_hostname=host)
    conn.settimeout(5)
    conn.connect((host, port))
    der_cert = conn.getpeercert(binary_form=True)
    conn.close()
    return x509.load_der_x509_certificate(der_cert, default_backend())


def parse_certificate(cert):
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    serial = format(cert.serial_number, 'x').upper()
    fingerprint = cert.fingerprint(cert.signature_hash_algorithm).hex().upper()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    days_remaining = (not_after - datetime.utcnow()).days

    return {
        "subject": subject,
        "issuer": issuer,
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_remaining": days_remaining,
        "serial": serial,
        "fingerprint": ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)),
        "subject_alt_names": san
    }


def main():
    parser = argparse.ArgumentParser(description="Fetch and inspect a server TLS certificate")
    parser.add_argument("host", help="Hostname to inspect")
    parser.add_argument("port", type=int, nargs="?", default=443, help="Port (default: 443)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    args = parser.parse_args()

    try:
        cert = fetch_certificate(args.host, args.port)
        cert_info = parse_certificate(cert)
        cert_info["host"] = args.host
        cert_info["port"] = args.port

        if args.json:
            print(json.dumps(cert_info, indent=2))
        else:
            print(f"🔐 Certificate Info for {args.host}:{args.port}")
            print("----------------------------------------")
            print(f"📄 Subject:   {cert_info['subject']}")
            print(f"🏢 Issuer:    {cert_info['issuer']}")
            print(f"📅 Validity:  {cert_info['valid_from']} → {cert_info['valid_to']}")
            print(f"⏰ Expires in: {cert_info['days_remaining']} days")
            print(f"🔢 Serial:    {cert_info['serial']}")
            print(f"🔑 Fingerprint: {cert_info['fingerprint']}")
            print("🌐 Subject Alternative Names:")
            for name in cert_info["subject_alt_names"]:
                print(f"  - {name}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()