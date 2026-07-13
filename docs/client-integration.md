# Client integration guide

How to support keyword-gated In-Band Registration (IBR) from an XMPP client.

If your client already renders XEP-0004 data forms generically, **you likely
need zero code changes** — the `keyword` field will appear automatically as a
masked text input alongside `username` and `password`. This guide is for
clients that need explicit support, or for developers who want to verify their
form-rendering path handles this case.

---

## TL;DR

A server running `mod_signup_keyword` returns a standard XEP-0004 data form
inside a `jabber:iq:register` IQ, with three fields:

| Field | XEP-0004 type | Required | Notes |
|-------|---------------|----------|-------|
| `username` | `text-single` | yes | The localpart of the JID |
| `password` | `text-private` | yes | Masked input |
| `keyword` | `text-private` | yes | The shared signup keyword; masked |

Plus a hidden `FORM_TYPE` field = `urn:xmpp:signup:keyword:0`.

The `keyword` field is the gate. Without it (or with a wrong value), the server
rejects the registration with `<not-allowed/>`.

---

## Connection

Connect to the server using whatever transport you normally use (DirectTLS,
STARTTLS, etc.). The stream `to=` attribute must be the XMPP domain — not an
IP address (a wrong/missing `to=` produces `<host-unknown/>`).

After stream negotiation, the server advertises:

```xml
<register xmlns='http://jabber.org/features/iq-register'/>
```

This indicates IBR is available before authentication. The entire registration
exchange happens on an **unauthenticated stream** — the user doesn't have
credentials yet; that's the point.

---

## The exchange

### 1. GET the form (recommended)

```xml
<iq type='get' id='form-1' to='example.org'>
  <query xmlns='jabber:iq:register'/>
</iq>
```

Server reply:

```xml
<iq type='result' id='form-1' from='example.org'>
  <query xmlns='jabber:iq:register'>
    <instructions>Enter your chosen username, password, and the signup keyword.</instructions>
    <x xmlns='jabber:x:data' type='form'>
      <title>Create an account</title>
      <instructions>...</instructions>
      <field var='FORM_TYPE' type='hidden'>
        <value>urn:xmpp:signup:keyword:0</value>
      </field>
      <field var='username' type='text-single' label='Username' required='true'>
        <desc>Lowercase letters, digits, dot, dash, or underscore. 1-31 chars.</desc>
      </field>
      <field var='password' type='text-private' label='Password' required='true'>
        <desc>At least 10 characters.</desc>
      </field>
      <field var='keyword' type='text-private' label='Signup keyword' required='true'>
        <desc>The keyword you were given by the person who invited you.</desc>
      </field>
    </x>
  </query>
</iq>
```

**Render this form generically.** The field labels, descriptions, required-ness,
and ordering all come from the server. Don't hardcode field names if you can
avoid it — that future-proofs against new fields or policy changes.

The `keyword` field is `text-private` — render it masked (secure keyboard on
mobile, no autocorrect, no autofill), same as a password.

### 2. Submit

```xml
<iq type='set' id='reg-1' to='example.org'>
  <query xmlns='jabber:iq:register'>
    <x xmlns='jabber:x:data' type='submit'>
      <field var='FORM_TYPE'><value>urn:xmpp:signup:keyword:0</value></field>
      <field var='username'><value>alice</value></field>
      <field var='password'><value>correct-horse-battery</value></field>
      <field var='keyword'><value>your-shared-keyword</value></field>
    </x>
  </query>
</iq>
```

### 3. Success

```xml
<iq type='result' id='reg-1' from='example.org'/>
```

The account is created. Close the registration stream and authenticate normally
(SASL + bind) with the new credentials. A welcome message may arrive as the
first `<message/>` after authentication.

---

## Error handling

All errors come back as `type='error'` IQs. Map them to user-facing strings:

| Server condition | XMPP error | User message |
|------------------|------------|--------------|
| Wrong/missing keyword | `<error type='auth'><not-allowed/></error>` | "Incorrect signup keyword. Check with whoever invited you." |
| Username taken or reserved | `<error type='cancel'><conflict/></error>` | "That username is taken. Try another." |
| Bad username | `<error type='modify'><jid-malformed/></error>` | "Username must be 1-31 chars: lowercase letters, digits, dot, dash, underscore." |
| Weak password | `<error type='modify'><not-acceptable/></error>` | "Password must be at least 10 characters." |
| Rate limited | `<error type='wait'><resource-constraint/></error>` | "Too many attempts. Please wait a few minutes." |
| Server error | `<error type='wait'><internal-server-error/></error>` | "Service temporarily unavailable. Try again later." |

Example (wrong keyword):

```xml
<iq type='error' id='reg-1' from='example.org'>
  <error type='auth'>
    <not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
    <text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>Incorrect keyword</text>
  </error>
</iq>
```

---

## Rate limiting

The server enforces `registration_timeout` — a per-IP cooldown between
registration attempts. The default in the example config is **600 seconds
(10 minutes)**.

When the user hits `<resource-constraint/>` (`type='wait'`):
- Surface the wait time clearly ("Please wait 10 minutes before trying again")
- Disable the Register button until the window passes
- Do NOT auto-retry — it won't work and just generates log noise

The rate limit is **per source IP**, so users behind the same NAT share a
budget. This is intentional (brute-force protection on the keyword).

---

## UX recommendations

1. **Validate client-side before submit:** username `^[a-z0-9][a-z0-9._-]{0,30}$`,
   password ≥ 10 chars, keyword non-empty. This avoids burning the rate-limit
   window on trivial rejections.

2. **On success, auto-authenticate.** Don't make the user re-type their
   credentials — close the registration stream, open a fresh c2s stream,
   SASL-auth, bind, land them in the chat view.

3. **Duplicate detection:** if the user picks a taken username, they get
   `<conflict/>`. Offer to retry with a different username **without losing
   the keyword field** (the keyword is still valid; only the username clashed).

4. **Label the keyword field sensibly.** The server sends `label='Signup keyword'`
   but you may prefer "Invite code", "Invite keyword", or "Registration code"
   depending on your audience. The `var` is always `keyword`.

---

## Security notes

- The keyword is a **shared static secret**, not a per-user credential.
  Do not cache it client-side beyond the registration session.
- The keyword travels inside the TLS-encrypted XMPP stream — protected in
  transit as long as the connection is encrypted (DirectTLS or STARTTLS).
  **Do not log it.**
- The server **never** returns the keyword in any response. Do not attempt
  to "recover" it by re-fetching the form.

---

## What this is NOT

- **Not XEP-0445** (Pre-Authenticated IBR). XEP-0445 uses single-use per-person
  tokens; this server uses a reusable shared keyword. The field name and
  semantics differ. If your client only implements XEP-0445's token flow, it
  will not work here — implement standard XEP-0004 data-form IBR as described
  above.
- **No CAPTCHA.** The keyword is the gate. There is no `<media>` element in
  the form, so a CAPTCHA-rendering code path should not trigger. If your
  client keys off "is there a `keyword` field OR a `<media>` element" to decide
  what to render, the `keyword` branch wins.

---

## Testing

Use the included test script to verify against any server running this module:

```sh
# Just check the form (no account created):
python3 scripts/test-ibr-keyword.py --host example.org --form-only

# Full flow: GET form, wrong-keyword rejection, successful registration,
# duplicate conflict:
python3 scripts/test-ibr-keyword.py --host example.org --keyword 'your-shared-keyword'
```

The script uses random usernames so it's re-runnable without manual cleanup.
