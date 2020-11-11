from requests import get, head, post
from dacite import from_dict
from dataclasses import dataclass
from base64 import urlsafe_b64encode, urlsafe_b64decode
from json import dumps, loads
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from os import listdir
import argparse
from argparse import ArgumentError
from cryptography.hazmat.primitives import hashes
from time import sleep
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from http.server import HTTPServer, SimpleHTTPRequestHandler
from ssl import wrap_socket


@dataclass
class Challenge():
    type: str
    url: str
    token: str
    status: str


@dataclass
class Account():
    status: str
    orders: str


@dataclass
class Order():
    authorizations: list
    CHALLENGES: dict
    expires: str
    finalize: str
    identifiers: list
    order_url: str
    status: str


@dataclass
class Directory():
    keyChange: str
    newAccount: str
    newNonce: str
    newOrder: str
    revokeCert: str


class ACMEClient():
    ACCOUNT: Account
    CA_KEY: str
    CHALLENGE_TYPE: str
    DIR: Directory
    DIR_URL: str
    RECORD: str
    DOMAINS: list
    JWK: dict
    HTTP_SERVER_URL: str
    KID: str
    LEX_JWK: dict
    NONCE: str
    ORDERS: list
    ORDERS_URL: str
    PRIVATE_KEY: ECC.EccKey
    PUBLIC_KEY: ECC.EccKey
    PUB_X: str
    PUB_Y: str
    REVOKE: bool

    def __init__(self):
        self.CA_KEY = "keys/pebble.minica.pem"
        self.DOMAINS = []
        self.ORDERS = []

    """
    1. Tool functions
    """

    def set_args_parameters(self, dir_url: str, c_type: str, revoke: bool, record: str, domains: list):
        self.DIR_URL = dir_url.strip()
        self.CHALLENGE_TYPE = "dns-01" if c_type == "dns01" else "http-01"
        self.REVOKE = revoke
        self.RECORD = record.strip()
        self.HTTP_SERVER_URL = "http://" + self.RECORD + ":5002/"
        self.DOMAINS.extend([domain.strip() for domain in domains])

    def generate_ES256_signature(self, message):
        key = self.PRIVATE_KEY
        h = SHA256.new(bytes(message, "utf-8"))
        signer = DSS.new(key=key, mode='fips-186-3')
        return signer.sign(h)

    def encode_to_b64_then_cleaned_UTF8(self, string):
        return urlsafe_b64encode(bytes(string, "utf-8")).decode("utf-8").replace("=", "")

    def generate_jwk(self):
        self.JWK = {
            "kty": "EC",
            "crv": "P-256",
            "x": self.PUB_X,
            "y": self.PUB_Y,
        }
        self.LEX_JWK = {
            "crv": "P-256",
            "kty": "EC",
            "x": self.PUB_X,
            "y": self.PUB_Y,
        }

    def JWK_thumbprint(self, jwk: dict):
        json_jwk = dumps(jwk).replace(" ", "")
        bytes_jwk = json_jwk.encode("utf-8")
        return SHA256.new(bytes_jwk).digest()

    def generate_JWS_request(self, protected: dict, payload: dict):
        b64_protected = self.encode_to_b64_then_cleaned_UTF8(
            dumps(protected).replace(" ", ""))

        b64_payload = self.encode_to_b64_then_cleaned_UTF8(dumps(
            payload
        ).replace(" ", "")) if payload != None else ""

        signing_input = b64_protected + "." + b64_payload

        body = {
            "protected": b64_protected,
            "payload": b64_payload,
            "signature": urlsafe_b64encode(self.generate_ES256_signature(signing_input)).decode("utf-8").replace("=", "")
        }
        return dumps(body).replace(" ", "")

    def export_ECC_key_points(self, key_path):
        f = open(
            key_path, "r")
        k = "".join([line.rstrip() for line in f.readlines()][1:-1])
        f.close()
        hex_k = urlsafe_b64decode(bytes(k, "utf-8")).hex()
        ci = 26  # The compression byte index
        l = 32  # Because of 256-bit keys
        c = hex_k[2 * ci: 2 * (ci + 1)]
        xi = 2 * (ci + 1)
        x = hex_k[xi: xi + 2 * l]
        yi = xi + 2 * l
        y = hex_k[yi: yi + 2 * l]
        b64_x = urlsafe_b64encode(bytearray.fromhex(
            x)).decode("utf-8").replace("=", "")
        b64_y = urlsafe_b64encode(bytearray.fromhex(
            y)).decode("utf-8").replace("=", "")
        self.PUB_X = b64_x
        self.PUB_Y = b64_y

    def generate_keys_if_absent(self):
        if "privatekey.pem" not in listdir("keys"):
            # Generate private key
            private_key = ECC.generate(curve="P-256")
            self.PRIVATE_KEY = private_key
            f = open("keys/privatekey.pem", "wt")
            f.write(private_key.export_key(format="PEM"))
            f.close()
        else:
            self.PRIVATE_KEY = ECC.import_key(
                open("keys/privatekey.pem", "r").read())

        if "publickey.pem" not in listdir("keys"):
            # Generate public key
            public_key = private_key.public_key()
            self.PUBLIC_KEY = public_key
            f = open("keys/publickey.pem", "wt")
            f.write(public_key.export_key(format="PEM"))
            f.close()
        else:
            self.PUBLIC_KEY = ECC.import_key(
                open("keys/publickey.pem", "r").read())
        self.export_ECC_key_points("keys/publickey.pem")
        self.generate_jwk()

    def generate_CSR(self, domains: list):
        domain = ""
        if domains[0][:2] == "*.":
            domain = domains[0][2:]
        else:
            domain = domains[0]
        # Generate our key
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write our key to disk for safe keeping
        with open("keys/serverkey.der", "wb") as f:
            f.write(server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(private_key=server_key, algorithm=hashes.SHA256())
        # Write our CSR out to disk.
        path = "certificates/csr/CSR-" + domain + ".der"
        with open(path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.DER))
        print("Generated CSR file for", domain)
        return path

    """
    2. Workflow functions
    """

    def get_directory(self):
        r = get(url=self.DIR_URL, verify=self.CA_KEY)
        self.DIR = from_dict(data_class=Directory, data=r.json())

    def get_nonce(self):
        r = head(url=self.DIR.newNonce, verify=self.CA_KEY)
        self.NONCE = r.headers["Replay-Nonce"]

    def create_account(self):

        protected = {
            "alg": "ES256",
            "jwk": self.JWK,
            "nonce": self.NONCE,
            "url": self.DIR.newAccount
        }

        payload = {
            "termsOfServiceAgreed": True
        }
        r = post(url=self.DIR.newAccount, data=self.generate_JWS_request(protected=protected, payload=payload), verify=self.CA_KEY,
                 headers={"Content-Type": "application/jose+json"})

        if r.json()["status"] == 400:   # Meaning it has a wrong replay nonce
            self.NONCE = r.headers["Replay-Nonce"]
            self.create_account()
        else:
            self.ACCOUNT = from_dict(data_class=Account, data=r.json())
            self.KID = r.headers["Location"]
            self.NONCE = r.headers["Replay-Nonce"]
            self.ORDERS_URL = r.json()["orders"]

    def post_new_order(self):
        protected = {
            "alg": "ES256",
            "kid": self.KID,
            "nonce": self.NONCE,
            "url": self.DIR.newOrder
        }
        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in self.DOMAINS],
        }
        r = post(url=self.DIR.newOrder, data=self.generate_JWS_request(protected=protected, payload=payload), verify=self.CA_KEY,
                 headers={"Content-Type": "application/jose+json"})

        if r.json()["status"] == 400:
            if r.json()["type"] == "urn:ietf:params:acme:error:badNonce":
                self.get_nonce()
                self.post_new_order()
            else:
                exit(1)
        else:
            a = r.json()
            a["CHALLENGES"] = {}
            a["order_url"] = r.headers["Location"]
            self.ORDERS.append(from_dict(data_class=Order, data=a))
            self.NONCE = r.headers["Replay-Nonce"]

    def fetch_challenges(self, order: Order):
        order.CHALLENGES = {}
        for a in order.authorizations:
            protected = {
                "alg": "ES256",
                "kid": self.KID,
                "nonce": self.NONCE,
                "url": a
            }
            r = post(url=a, data=self.generate_JWS_request(protected=protected, payload=None), verify=self.CA_KEY,
                     headers={"Content-Type": "application/jose+json"})
            if r.json()["status"] == 400:
                self.NONCE = r.headers["Replay-Nonce"]
                self.fetch_challenges(order)
            else:
                domain = r.json()["identifier"]["value"]
                if "wildcard" in r.json():
                    domain = "*." + domain
                order.CHALLENGES[domain] = []
                print("\n\n", r.json()["challenges"], "\n\n")
                for challenge in r.json()["challenges"]:
                    print(challenge)
                    if challenge["type"] == self.CHALLENGE_TYPE:
                        order.CHALLENGES[domain].append(
                            from_dict(data_class=Challenge, data=challenge))
                print("Challenges:", order.CHALLENGES)
                self.NONCE = r.headers["Replay-Nonce"]

    def complete_order(self):
        for order in self.ORDERS:
            self.fetch_challenges(order)
            for domain, challenges in order.CHALLENGES.items():
                self.verify_challenges(
                    order=order, domain=domain, challenges=challenges)
        domains = list(order.CHALLENGES.keys())
        csr_path = self.generate_CSR(domains=domains)
        certificate_url = self.issue_certificate(
            domains, order, csr_path)
        self.download_certificate(
            url=certificate_url)

    def verify_challenges(self, order: Order, domain: str, challenges: list) -> bool:
        # If the domain is a wildcard domain (of the form *.example.org)
        if domain[:2] == "*.":
            domain = domain[2:]
        for challenge in challenges:
            KEY_AUTH = challenge.token + "." + \
                urlsafe_b64encode(
                    self.JWK_thumbprint(jwk=self.LEX_JWK)).decode("utf-8").replace("=", "")

            if challenge.type == "http-01" and challenge.type == self.CHALLENGE_TYPE:
                print("Attempting http-01 challenge ...")
                url = "?path=" + \
                    challenge.token + "&key_auth=" + KEY_AUTH
                r = get(url=self.HTTP_SERVER_URL + "/http_challenge" + url)
                sleep(2)
                success = self.validate_challenge(
                    challenge=challenge, count=0, payload={})
                return success

            elif challenge.type == "dns-01" and challenge.type == self.CHALLENGE_TYPE:
                print("DNS challenge starting...")
                value = urlsafe_b64encode(
                    SHA256.new(KEY_AUTH.encode("utf-8")).digest()).decode("utf-8").replace("=", "")

                # Add record to the DNS server zonefile
                new_line = "_acme-challenge." + domain + \
                    ". 60 IN TXT " + "\"" + value + "\"\n"
                f = open("dns_records.txt", "r")
                current_record = f.readlines()
                f.close()
                open('dns_records.txt', 'w').close()
                f = open("dns_records.txt", "w")
                f.write(new_line)
                f.close()
                print("Updated DNS records file.")
                sleep(2)
                success = self.validate_challenge(
                    challenge=challenge, count=0, payload={})

                open('dns_records.txt', 'w').close()
                with open("dns_records.txt", "w") as f:
                    f.writelines(current_record)
                print("Recovered DNS record file.")
                return success

    def validate_challenge(self, challenge: Challenge, count: int, payload) -> bool:
        protected = {
            "alg": "ES256",
            "kid": self.KID,
            "nonce": self.NONCE,
            "url": challenge.url
        }
        r = post(url=challenge.url, data=self.generate_JWS_request(
            protected=protected, payload=payload), verify=self.CA_KEY,
            headers={"Content-Type": "application/jose+json"})
        self.NONCE = r.headers["Replay-Nonce"]

        if r.json()["status"] == "pending" and count < 4:
            count += 1
            sleep(7)
            return self.validate_challenge(challenge, count, None)

        elif r.json()["status"] == 400:
            self.NONCE = r.headers["Replay-Nonce"]
            return self.validate_challenge(challenge, count, None)

        elif r.json()["status"] == "valid":
            print("Challenge succeeded !")
            return True
        else:
            print("Challenge failed.")
            exit(1)

    def issue_certificate(self, domains: list, order: Order, path: str):
        protected = {
            "alg": "ES256",
            "kid": self.KID,
            "nonce": self.NONCE,
            "url": order.finalize
        }
        payload = {
            "csr": urlsafe_b64encode(open(path, "rb").read()).decode("utf-8").replace("=", "")
        }

        sleep(3)
        r = post(url=order.finalize, data=self.generate_JWS_request(
            protected=protected, payload=payload), verify=self.CA_KEY,
            headers={"Content-Type": "application/jose+json"})
        self.NONCE = r.headers["Replay-Nonce"]
        status = ""
        while status != "valid":
            protected = {
                "alg": "ES256",
                "kid": self.KID,
                "nonce": self.NONCE,
                "url": order.order_url
            }
            r = post(url=order.order_url, data=self.generate_JWS_request(
                protected=protected, payload=None), verify=self.CA_KEY,
                headers={"Content-Type": "application/jose+json"})
            self.NONCE = r.headers["Replay-Nonce"]
            sleep(3)
            status = r.json()["status"]

        certificate_url = r.json()["certificate"]
        print("Certificate successfully issued !")
        return certificate_url

    def download_certificate(self, url: str):
        protected = {
            "alg": "ES256",
            "kid": self.KID,
            "nonce": self.NONCE,
            "url": url
        }
        r = post(url=url, data=self.generate_JWS_request(
            protected=protected, payload=None), verify=self.CA_KEY,
            headers={"Content-Type": "application/jose+json"})
        self.NONCE = r.headers["Replay-Nonce"]
        cert = r.content.decode("utf-8")
        with open("certificates/certificate.pem", "w") as f:
            f.write(cert)

        print("Downloaded and saved certificate.")

    def start_https_server(self):
        httpd = HTTPServer(
            (self.RECORD, 5001), SimpleHTTPRequestHandler)

        httpd.socket = wrap_socket(httpd.socket, certfile="certificates/certificate.pem",
                                   keyfile='keys/serverkey.der', server_side=True)
        print("Started HTTPS server with created certificate at", self.RECORD)
        httpd.serve_forever()

    def revoke_certificate(self):
        cert = x509.load_pem_x509_certificate(
            open("certificates/certificate.pem", "rb").read()).public_bytes(serialization.Encoding.DER)
        print("Ici c'est bon")
        count = 0
        payload = {
            "certificate": urlsafe_b64encode(cert).decode("utf-8").replace("=", "")
        }
        protected = {
            "alg": "ES256",
            "kid": self.KID,
            "nonce": self.NONCE,
            "url": self.DIR.revokeCert
        }
        r = post(url=self.DIR.revokeCert, data=self.generate_JWS_request(
            protected=protected, payload=payload), verify=self.CA_KEY,
            headers={"Content-Type": "application/jose+json"})
        self.NONCE = r.headers["Replay-Nonce"]
        status = r.status_code
        print(status)
        print(r.text)
        sleep(2)
        count += 1
        if status == 200:
            print("Certificate successfully revoked!")
        else:
            print("Error revoking certificate.")


if __name__ == "__main__":
    # Set up the parsing of command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "challenge_type",
        help="Defines the challenge type",
        choices=["http01", "dns01"],
        type=str
    )
    parser.add_argument(
        "--dir",
        required=True,
        help="Directory URL of the ACME server that should be used",
        type=str,
    )
    parser.add_argument(
        "--record",
        required=True,
        help="IPv4 address of the DNS Server",
        type=str,
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="Domain for  which to request the certificate",
        type=str,
        action="append"
    )
    parser.add_argument(
        "--revoke",
        required=False,
        help="If present, your application should immediately revoke the certificate after obtaining it",
        action="store_true"
    )
    args = parser.parse_args()

    print(args)

    # Set the client up
    client = ACMEClient()
    client.set_args_parameters(
        args.dir, args.challenge_type, args.revoke, args.record, args.domain)
    client.generate_keys_if_absent()

    # Start requesting certificates
    client.get_directory()
    client.get_nonce()
    client.create_account()
    client.post_new_order()
    client.complete_order()
    if client.REVOKE:
        print("Ok bg")
        client.revoke_certificate()
    client.start_https_server()
