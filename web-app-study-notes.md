# Web application

Same origin policy

    Only accept requests from the same origin domain.

CORS

    Cross-Origin Resource Sharing. Can specify allowed origins in HTTP headers. Sends a preflight request with options set asking if the server approves, and if the server approves, then the actual request is sent (eg. should client send auth cookies).

HSTS

    Policies, eg what websites use HTTPS.

Cert transparency

    Can verify certificates against public logs

HTTP Public Key Pinning (HPKP)
    
    Deprecated by Google Chrome

Cookies
    
    httponly - cannot be accessed by javascript.

CSRF

    Cross-Site Request Forgery.
    Cookies.

XSS

    Reflected XSS.
    Persistent XSS.
    DOM based /client-side XSS.
    <img scr=””> will often load content from other websites, making a cross-origin HTTP request.
    
SQLi

    (Wo)man in the browser (flash / java applets) (malware).
    Validation / sanitisation of webforms.

POST

    Form data.

GET

    Queries.
    Visible from URL.

Directory traversal

    Find directories on the server you’re not meant to be able to see.
    There are tools that do this.

APIs

    Think about what information they return.
    And what can be sent.

Beefhook

    Get info about Chrome extensions.

User agents

    Is this a legitimate browser? Or a botnet?

Browser extension take-overs

    Miners, cred stealers, adware.

Local file inclusion

Remote file inclusion (not as common these days)

SSRF

    Server Side Request Forgery.

Web vuln scanners.

SQLmap.

Malicious redirects
