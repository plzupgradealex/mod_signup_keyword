# mod_signup_keyword

Keyword-gated In-Band Registration for [ejabberd](https://www.ejabberd.im/).

A custom ejabberd module that lets you gate XEP-0077 account registration behind
a **reusable shared keyword** — the simplest onboarding model for small/private
XMPP servers where you want friends-of-friends to self-register without
per-person invite tokens.

```
┌────────┐    IBR (XEP-0077 + XEP-0004 data form)    ┌──────────┐
│ Client │ ────────────────────────────────────────▶ │ ejabberd │
│        │   fields: username, password, keyword      │  + this  │
│        │ ◀──────────────────────────────────────── │  module  │
└────────┘    account created (or error)              └──────────┘
```

## Why?

ejabberd gives you two built-in registration models, and both are awkward for
a personal server:

| Model | Problem |
|-------|---------|
| Open IBR (`mod_register`) | Anyone on the internet can create accounts. Spam magnet. |
| XEP-0445 tokens (`mod_invites`, ejabberd 26.01+) | Each token is single-use — you must mint one per person. Friction. |
| `ejabberdctl register` / admin API | Fully manual. No self-service. |
| **This module** | **One shared keyword for everyone.** Give it to your friends; they register themselves. |

The keyword is a **password gate on IBR**: the server returns a data form with
a `keyword` field, validates it (constant-time comparison), and creates the
account only on match. Clients that render XEP-0004 forms generically (most do)
need **zero changes** — the keyword field just appears alongside username and
password.

### Honest trade-off

If the keyword leaks, anyone who finds your host can register until you rotate
it. This is by design (lowest-friction onboarding) but it's strictly weaker
than XEP-0445 per-person tokens. Mitigations built in:

- **Constant-time** keyword comparison (no timing side-channel)
- **Per-IP rate limiting** via the module's `registration_timeout_ms` option
  (the module implements its own throttle — ejabberd's top-level
  `registration_timeout` does **not** apply, because it's enforced inside
  `mod_register`, which this module replaces)
- **Failed-attempt logging** (IP + username; the keyword itself is never logged)
- **On-box-only keyword storage** (never in source control)
- **Rotation** by editing config + restarting

If you need per-person accountability or revocation, use XEP-0445 instead.
This module is for the "give my friends one word" case.

## Requirements

- ejabberd **23.x+** (uses the `gen_mod` `{iq_handler, ...}` start/2 return
  tuple and `c2s_unauthenticated_packet` hook, both long-established)
- Erlang/OTP 25+ (tested on OTP 27; should work on 25+)
- A c2s listener reachable by clients

## Install

### 1. Compile the module

```sh
# Set these to your ejabberd build tree:
BUILD=/path/to/ejabberd          # the dir containing ebin/ and include/
ERLC=/path/to/erlc               # erlang compiler (matching your ejabberd's OTP)

erlc -I "$BUILD/include" -I "$BUILD/_build/default/lib" \
     -o "$BUILD/ebin" src/mod_signup_keyword.erl
```

This produces `mod_signup_keyword.beam` in your ebin directory. You should see
only one warning, which is expected when compiling outside ejabberd's build
system:

```
mod_signup_keyword.erl:65: Warning: behaviour gen_mod undefined
```

It resolves at load time once ejabberd's `gen_mod` is on the code path.

### 2. Configure

Add the module to your `ejabberd.yml`:

```yaml
modules:
  # ... your other modules ...

  mod_signup_keyword:
    keyword: "your-shared-keyword"   # REQUIRED — set this to your secret
    welcome_message: "Welcome! Your account is ready."
    reserved_users:
      - admin
      - root
      - support
      - info
    instructions: "Enter your chosen username, password, and the signup keyword."
    registration_timeout_ms: 600000  # per-IP rate limit (ms). 600000 = 10 min.

# NOTE: ejabberd's top-level registration_timeout does NOT apply to this
# module (it's enforced inside mod_register, which we don't load). Use the
# module's registration_timeout_ms option above instead.
```

**Do NOT load `mod_register` at the same time** — both modules register the
`jabber:iq:register` IQ handler and will conflict. This module owns that
namespace and calls `ejabberd_auth:try_register/3` directly.

### 3. Restart ejabberd

```sh
# systemd:
systemctl restart ejabberd

# SRC (AIX):
stopsrc -s ejabberd && sleep 3 && startsrc -s ejabberd
```

### 4. Verify

```sh
python3 scripts/test-ibr-keyword.py --host your.host --port 5222 \
    --no-tls --keyword 'your-shared-keyword' --form-only
# Should print: PASS: form advertises 'keyword' field
```

Or test over TLS:
```sh
python3 scripts/test-ibr-keyword.py --host your.host --keyword 'your-shared-keyword'
```

## Configuration options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keyword` | binary | *(none, required)* | The shared signup keyword. Set on-box, never commit. |
| `welcome_message` | binary | `"Welcome! ..."` | Message body sent to a newly registered user. Empty string to disable. |
| `reserved_users` | `[binary]` | *(common admin names)* | Usernames that can't be registered even with the right keyword. |
| `instructions` | binary | *(auto-generated)* | Instructions text shown in the registration form. |
| `registration_timeout_ms` | `pos_int \| infinity` | `600000` (10 min) | Minimum milliseconds between attempts from the same source IP. `infinity` disables (not recommended). This is the module's own throttle; ejabberd's top-level `registration_timeout` does not apply. |

## How it works

1. Client opens a stream. The module advertises `<register xmlns='urn:xmpp:features:register'/>`.
2. Client sends `<iq type='get'><query xmlns='jabber:iq:register'/></iq>`.
3. Module returns a XEP-0004 data form with fields: `username`, `password`, `keyword`.
4. Client submits the form with the three fields filled in.
5. Module validates the keyword (constant-time), checks the username isn't
   reserved, and calls `ejabberd_auth:try_register/3` — so SCRAM hashing,
   Mnesia/SQL storage, and the existing auth stack are reused unchanged.
6. On success: account created, welcome message sent, result IQ returned.
   On failure: appropriate XMPP error (see table below).

### Error mapping

| Condition | XMPP error | Meaning |
|-----------|------------|---------|
| Wrong/missing keyword | `not-allowed` (auth) | Keyword didn't match |
| Username taken/reserved | `conflict` (cancel) | Pick another username |
| Bad username format | `jid-malformed` (modify) | Invalid characters/length |
| Weak password | `not-acceptable` (modify) | Doesn't meet password policy |
| Rate limited | `resource-constraint` (wait) | Too many attempts from this IP |
| Server error | `internal-server-error` (wait) | Transient |

## Client compatibility

**Any client that renders XEP-0004 data forms generically works with zero
changes.** The keyword field appears as a `text-private` input (masked like a
password) alongside username and password.

Verified with:
- **Mach** (build 221+) — detects the `keyword` field and renders it as an
  "Invite Code" input. [Integration guide for client developers](docs/client-integration.md).

If your client renders the form fields but calls the keyword field "keyword"
verbatim, you may want to customize the `label` in `signup_form/1` in the
source (e.g., to "Invite code" or "Signup code" for your audience).

## Files

```
src/mod_signup_keyword.erl       The ejabberd module
scripts/test-ibr-keyword.py      End-to-end test (GET form, wrong/right keyword, duplicate)
scripts/deploy-signup-keyword.ksh  Example deploy script (compile + restart, Mnesia-safe)
docs/client-integration.md       Wire-protocol spec for client developers
LICENSE                          GPLv2+
```

## License

**GPL-2.0-or-later.** Same license as ejabberd itself. This is required because
the module is a derivative work of ejabberd (it declares `-behaviour(gen_mod)`
and calls ejabberd internal APIs). See [LICENSE](LICENSE).

## Alternatives

| If you need... | Use |
|----------------|-----|
| One keyword for everyone (this module) | `mod_signup_keyword` |
| One token per person, revocable | ejabberd 26.01+ `mod_invites` (XEP-0445) |
| Admin-created accounts only | `ejabberdctl register` / HTTP API |
| Web signup with geo/rate/audit gates | A separate web app calling the API |

## Acknowledgments

The module's structure (IQ handler registration, `c2s_unauthenticated_packet`
hook, error handling) closely follows ejabberd's own `mod_register.erl` by
Alexey Shchepin / ProcessOne. The keyword-gating logic and data-form design
are original to this module.
