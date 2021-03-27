# Cryptography, authentication, identity

Encryption vs Encoding vs Hashing vs Obfuscation vs Signing

    Be able to explain the differences between these things.
    Various attack models (e.g. chosen-plaintext attack).

Encryption standards + implementations

    RSA (asymmetrical).
    AES (symmetrical).
    ECC (namely ed25519) (asymmetric).
    Chacha/Salsa (symmetric)
    
Asymmetric vs symmetric

    Asymmetric is slow, but good for establishing a trusted connection.
    Symmetric has a shared key and is faster. Protocols often use asymmetric to transfer symmetric key.
    Perfect forward secrecy - eg Signal uses this.

Ciphers

    Block vs stream ciphers.
    Block cipher modes of operation.
    AES-GCM

Trusted Platform Module

    (TPM)
    Trusted storage for certs and auth data locally on device/host.

Integrity and authenticity primitives

    Hashing functions, e.g. MD5, Sha-1, BLAKE. Used for identifiers, very useful for fingerprinting malware samples.
    Message Authentication Codes (MACs).
    Keyed-hash MAC (HMAC).

Entropy

    PRNG (pseudo random number generators).
    Entropy buffer draining.
    Methods of filling entropy buffer.

Certificates

    What info do certs contain, how are they signed?
    Look at DigiNotar.

O-auth

    Bearer tokens, this can be stolen and used, just like cookies.

Auth Cookies

    Client side.

Sessions

    Server side.

Auth systems

    SAMLv2o.
    OpenID.

Biometrics

    Can't rotate unlike passwords.

Password management

    Rotating passwords (and why this is bad).
    Different password lockers.

U2F / FIDO

    Eg. Yubikeys.
    Helps prevent successful phishing of credentials.
    Compare and contrast multi-factor auth methods
