#!/usr/bin/env python3
"""
test-ibr-keyword.py -- end-to-end test of keyword-gated IBR on example.org.

Connects to the production DirectTLS c2s port (:443), performs the XEP-0077
In-Band Registration exchange with the custom mod_signup_keyword data form,
and verifies the server enforces the keyword gate.

Tests run (in order, stopping on first failure):
  1. GET form  -- the advertised form has a 'keyword' field
  2. SET wrong -- registration with a bad keyword is rejected (not-allowed)
  3. SET right -- registration with the right keyword + valid creds succeeds
  4. Duplicate -- a second registration with the same username is rejected
                 (conflict) -- proves the account was actually created

Usage:
    # Full suite against prod (needs the real keyword):
    python3 test-ibr-keyword.py --host example.org --port 443 --tls \\
        --keyword 'your-shared-keyword'

    # Just fetch and print the form (no registration):
    python3 test-ibr-keyword.py --host example.org --port 443 --tls --form-only

    # Against the dev node via SSH tunnel (plaintext):
    ssh -L 25222:127.0.0.1:25222 your-server
    python3 test-ibr-keyword.py --host 127.0.0.1 --port 25222 \\
        --keyword 'dev-keyword'

No third-party libraries -- raw XML over a (TLS-wrapped) socket. Pure stdlib.

NOTE on the username: the suite mints a random username so re-runs don't
collide with prior test accounts. Pass --username to override.
"""

import argparse
import socket
import ssl
import sys
import time
import uuid
import xml.etree.ElementTree as ET

NS_REGISTER = "jabber:iq:register"
NS_DATA = "jabber:x:data"
RECV_TIMEOUT = 20  # seconds


class IBRClient:
    """Minimal XMPP IBR client: open stream, GET form, SET registration."""

    def __init__(self, host, port, domain, use_tls):
        self.host, self.port = host, port
        self.domain = domain
        self.use_tls = use_tls
        self.sock = None
        self.buf = b""

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=10)
        raw.settimeout(RECV_TIMEOUT)
        if self.use_tls:
            ctx = ssl.create_default_context()
            # The server presents a real cert (Let's Encrypt via haproxy SNI);
            # leave verification on. Use --insecure to disable for self-signed.
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            self.sock = ctx.wrap_socket(raw, server_hostname=self.domain)
        else:
            self.sock = raw
        # Stream init.
        self._send(
            '<?xml version="1.0"?>'
            '<stream:stream xmlns="jabber:client" '
            'xmlns:stream="http://etherx.jabber.org/streams" '
            f'to="{self.domain}" version="1.0">'
        )
        feats = self._read_until("</stream:features>")
        if b"urn:ietf:params:xml:ns:xmpp-sasl" not in feats:
            raise RuntimeError(f"SASL not advertised; features:\n{feats.decode()}")
        return feats

    def get_form(self):
        """Send GET iq; return the parsed <query xmlns=jabber:iq:register> element."""
        iq_id = "form-1"
        self._send(
            f'<iq type="get" id="{iq_id}" to="{self.domain}">'
            f'<query xmlns="{NS_REGISTER}"/></iq>'
        )
        resp = self._read_until(f'id="{iq_id}"')
        return _extract_stanzas(resp.decode(errors="replace"), "iq")

    def submit_registration(self, username, password, keyword):
        """Submit a SET iq with a data form carrying username/password/keyword."""
        iq_id = f"reg-{uuid.uuid4().hex[:8]}"
        xml = (
            f'<iq type="set" id="{iq_id}" to="{self.domain}">'
            f'<query xmlns="{NS_REGISTER}">'
            f'<x xmlns="{NS_DATA}" type="submit">'
            f'<field var="username"><value>{_esc(username)}</value></field>'
            f'<field var="password"><value>{_esc(password)}</value></field>'
            f'<field var="keyword"><value>{_esc(keyword)}</value></field>'
            f'</x></query></iq>'
        )
        self._send(xml)
        resp = self._read_until(f'id="{iq_id}"')
        return _extract_stanzas(resp.decode(errors="replace"), "iq")

    def disconnect(self):
        if self.sock:
            try:
                self._send("</stream:stream>")
            except Exception:
                pass
            self.sock.close()

    # -- internal --
    def _send(self, xml):
        self.sock.sendall(xml.encode())

    def _read_until(self, *markers):
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(1, int(deadline - time.time())))
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
                if any(m.encode() in self.buf if isinstance(m, str) else m in self.buf
                       for m in markers):
                    out, self.buf = self.buf, b""
                    return out
            except socket.timeout:
                break
        out, self.buf = self.buf, b""
        return out


# -- XML helpers --
def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _extract_stanzas(buf, tag):
    """Best-effort extraction of <tag>...</tag> from a byte buffer."""
    results = []
    open_t, close_t = f"<{tag}", f"</{tag}>"
    idx = 0
    while True:
        start = buf.find(open_t, idx)
        if start == -1:
            break
        end = buf.find(close_t, start)
        if end == -1:
            break
        fragment = buf[start:end + len(close_t)]
        try:
            results.append(ET.fromstring(fragment))
        except ET.ParseError:
            pass
        idx = end + len(close_t)
    return results


def iq_type(elem):
    return elem.attrib.get("type", "?")


def iq_error_condition(elem):
    """Return the defined-condition (e.g. 'not-allowed') of an error iq, or None."""
    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "error":
            for ec in child:
                ct = ec.tag.split("}")[-1] if "}" in ec.tag else ec.tag
                return ct
    return None


def form_has_field(elem, var):
    """Check for a data-form field named var anywhere inside elem (iq or query)."""
    # Walk all descendants looking for <x xmlns='jabber:x:data'> then its fields.
    for child in elem.iter():
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "x":
            for field in child:
                if field.attrib.get("var") == var:
                    return True
    return False


# -- test suite --
def run(args):
    domain = args.domain or args.host
    username = args.username or f"ibrtest-{uuid.uuid4().hex[:6]}"
    password = args.password or f"Test-{uuid.uuid4().hex[:10]}!xx"

    print(f"=== connecting to {args.host}:{args.port} "
          f"(tls={args.tls}) domain={domain} ===")
    client = IBRClient(args.host, args.port, domain, args.tls)
    results = {"pass": 0, "fail": 0}
    try:
        client.connect()
        print("  stream initialized")

        # ---- Test 1: GET form advertises a keyword field ----
        print("\n--- Test 1: GET registration form ---")
        iqs = client.get_form()
        if not iqs:
            _fail(results, "no <iq> reply to GET form")
            return results
        iq = iqs[0]
        if iq_type(iq) != "result":
            _fail(results, f"GET form returned type={iq_type(iq)}, expected 'result'")
            return results
        if not form_has_field(iq, "keyword"):
            _fail(results, "form does NOT advertise a 'keyword' field -- "
                           "mod_signup_keyword not loaded or wrong form?")
            return results
        _ok(results, "form advertises 'keyword' field")

        if args.form_only:
            print("\n(form-only mode; stopping after GET)")
            return results

        # ---- Test 2: SET with WRONG keyword is rejected ----
        print("\n--- Test 2: SET with WRONG keyword (expect not-allowed) ---")
        bad = client.submit_registration(username, password, "WRONG-KEYWORD!")
        if not bad:
            _fail(results, "no reply")
            return results
        cond = iq_error_condition(bad[0]) if bad else None
        if iq_type(bad[0]) == "error" and cond in ("not-allowed", "forbidden"):
            _ok(results, f"rejected as expected ({cond})")
        else:
            _fail(results, f"expected not-allowed, got type={iq_type(bad[0])} "
                           f"cond={cond} -- server accepted wrong keyword?!")
            return results

        # ---- Test 3: SET with RIGHT keyword + valid creds succeeds ----
        print(f"\n--- Test 3: SET with right keyword "
              f"(user={username}, expect success) ---")
        good = client.submit_registration(username, password, args.keyword)
        if not good:
            _fail(results, "no reply")
            return results
        if iq_type(good[0]) == "result":
            _ok(results, f"account created: {username}@{domain}")
        else:
            cond = iq_error_condition(good[0])
            if cond == "wait":
                _fail(results, f"rate-limited (registration_timeout). "
                               f"Wait {args.ratelimit_wait}s and re-run. "
                               f"Condition={cond}")
            else:
                _fail(results, f"expected success, got type={iq_type(good[0])} "
                               f"cond={cond}")
            return results

        # ---- Test 4: Duplicate username is rejected (conflict) ----
        print(f"\n--- Test 4: duplicate username (expect conflict) ---")
        time.sleep(args.ratelimit_wait)
        dup = client.submit_registration(username, password, args.keyword)
        if not dup:
            _fail(results, "no reply")
            return results
        cond = iq_error_condition(dup[0])
        if iq_type(dup[0]) == "error" and cond == "conflict":
            _ok(results, "duplicate rejected as expected (conflict)")
        elif cond == "wait":
            print(f"  SKIP: rate-limited (registration_timeout). "
                  f"Account WAS created in test 3 -- rerun later to verify "
                  f"conflict path.")
        else:
            _fail(results, f"expected conflict, got type={iq_type(dup[0])} cond={cond}")
            return results

    except Exception as e:
        _fail(results, f"exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()

    return results


def _ok(results, msg):
    results["pass"] += 1
    print(f"  PASS: {msg}")


def _fail(results, msg):
    results["fail"] += 1
    print(f"  FAIL: {msg}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="End-to-end test of keyword-gated IBR on example.org")
    ap.add_argument("--host", default="example.org")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--domain", default=None,
                    help="XMPP domain (defaults to --host)")
    ap.add_argument("--tls", action="store_true", default=True,
                    help="wrap the socket in TLS (DirectTLS). Default on.")
    ap.add_argument("--no-tls", dest="tls", action="store_false",
                    help="plaintext (dev node via SSH tunnel)")
    ap.add_argument("--keyword", required=False,
                    help="the real signup keyword (required unless --form-only)")
    ap.add_argument("--username", default=None,
                    help="username to register (default: random ibrtest-XXXX)")
    ap.add_argument("--password", default=None,
                    help="password (default: random)")
    ap.add_argument("--form-only", action="store_true",
                    help="only GET and print the form; don't attempt registration")
    ap.add_argument("--ratelimit-wait", type=int, default=15,
                    help="seconds to wait between submissions (registration_timeout)")
    args = ap.parse_args()

    if not args.form_only and not args.keyword:
        ap.error("--keyword is required (or use --form-only)")

    results = run(args)
    print(f"\n=== results: {results['pass']} passed, {results['fail']} failed ===")
    sys.exit(0 if results["fail"] == 0 else 1)


if __name__ == "__main__":
    main()
