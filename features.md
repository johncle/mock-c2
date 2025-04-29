# C2 and Implant Features

## C2-Implant Communications

-   HTTPS (TLS) encryption for transport (requires installing attacker's certificate authority on target)
-   X25519 Elliptic-Curve Diffie-Hellman (AES) Key Exchange between client and server
-   AES-256-GCM encryption on all messages with random nonce
-   Random ephemeral 256-bit AES key generation every time client starts
    -   Pre-shared key is used only during key exchange

## Implant Obfuscation

-   Obfuscated with Pyarmor
-   Compiled into standalone binary with PyInstaller with `--one-file` flag

