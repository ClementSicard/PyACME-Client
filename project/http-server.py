from flask import Flask, request
from json import dumps
import argparse

app = Flask(__name__)

default_url = "/.well-known/acme-challenge"
pairs = {}


@app.route(default_url + "/<token>")
def handler(token):
    if token in pairs.keys():
        return pairs[token]
    return "404: Wrong URL"


@app.route('/http_challenge')
def http_challenge():
    path = request.args.get("path")
    key_auth = request.args.get("key_auth")
    if (path, key_auth) != (None, None):
        pairs[path] = key_auth
        print("path:", path, "key_auth:", key_auth)
    return dumps({
        "status": "OK" if path != None and key_auth != None else "One of the arguments is None"
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--record",
        required=True,
        help="IPv4 address of the DNS Server",
        type=str,
    )
    args = parser.parse_args()
    app.run(host=args.record, port=5002)
