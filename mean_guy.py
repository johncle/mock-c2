import requests
import json

# curl -k -X POST https://127.0.0.1:8443/task \
#     -H "Content-Type: application/json" \
#     -d '{"cmd": "ls"}'


url = "https://127.0.0.1:8443/task"
headers = {"Content-Type": "application/json"}
data = {"cmd": "ls"}

response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

print(response.status_code)
print(response.text)