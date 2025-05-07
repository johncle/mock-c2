# Apache HTTP Server Path Traversal & Remote Code Execution (CVE-2021-41773 & CVE-2021-42013)

[CVE-2021-41773 Description](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)

> A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

[CVE-2021-42013 Description](https://nvd.nist.gov/vuln/detail/CVE-2021-42013)

> It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

# C2 and Implant Features

## C2 Functions

-   Sending implant to stager
-   Tasking with remote code execution
-   File exfiltration
-   Implant destruction

## C2-Implant Communications

-   HTTPS (TLS) encryption for transport (requires installing attacker's certificate authority on target)
-   X25519 Elliptic-Curve Diffie-Hellman (AES) Key Exchange between client and server
-   Random ephemeral 256-bit AES key generation every time client starts
    -   Pre-shared key is used only during key exchange
-   AES-256-GCM encryption on all messages with random nonce

## Implant Obfuscation

-   Obfuscated with Pyarmor and compiled into standalone binary with PyInstaller
    -   Our target uses an alpine docker container to run apache2 so we compile for that (uses musl libc)

# Timeline of Operation

1. C2 - Attacker starts C2 and leaves it waiting for connections
2. Initial exploit - Attacker exploits the file traversal + RCE vulnerability to make Apache2 open a reverse shell from the target
3. Stager - Attacker sends a Python command to run a stager which downloads the implant from the C2
4. Implant - The python command then runs the implant for full communications with the C2
5. RCE and file exfil - Now the attacker can send any commands to the implant, including for file exfiltration
6. Destroy implant - When operation is over, attacker sends a self-destruct command to the implant

# Setup

1. Run target with `docker compose up -d`
2. Get IP of target by running `ip a` in the device running the docker container and looking for the local IPv4 address with "state UP"
3. Set your C2_IP in `stripped_implant.py` and `setup.sh`
4. Set your C2_IP and TARGET_IP in `exploit.py`
5. Set up certs, keys, and payload by running `./setup.sh` (in parent dir)
6. Run `c2.py` then `exploit.py` in separate shells
