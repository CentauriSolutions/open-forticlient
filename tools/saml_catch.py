#!/usr/bin/env python3
"""Loopback catcher for the FortiGate SAML-over-IPsec redirect.

Stands in for FortiTray's short-lived loopback HTTP server. The FortiGate, after
a successful browser SSO, redirects to:

    http://localhost:<PORT>/?tokenid=<TOKENID>&username=<USERNAME>

This server captures that request so you can see the handshake shape. It prints
every request with the token VALUE MASKED by default (only its length and a short
prefix), because the tokenid is a single-use IKE credential — treat it like a
password. Pass --show-secrets only on a machine you control when you actually need
the raw value to drive an IKE auth.

Usage:
    python3 saml_catch.py --port 56299
    python3 saml_catch.py --port 56299 --show-secrets     # prints raw tokenid

End-to-end probe (all on the operator's own machine, with their consent):
    1. start this catcher on <PORT>
    2. POST the bootstrap request to the gateway and open the returned SAML URL:
         curl -sk -X POST \
           -H 'Content-Type: application/x-www-form-urlencoded' \
           -H "UID: $(uuidgen | tr -d - | tr a-f A-F)" \
           --data "UID=<uid>&REDIRECT_PORT=<PORT>" \
           "https://<gateway>:9443/saml_login?"
       -> returns  <script>window.location="https://<gateway>:9443/saml?<id>"</script>
    3. open that https://<gateway>:9443/saml?<id> URL in a browser and log in
    4. the browser is redirected back to this catcher; the tokenid+username land here

See ../docs/saml-ipsec-protocol.md for the full flow.
"""
import argparse
import http.server
import re
import time
from urllib.parse import urlparse, parse_qs

SECRET_KEYS = {"tokenid", "token", "svpncookie", "id", "csrftoken"}


def mask(key, value, show):
    if show or key.lower() not in SECRET_KEYS:
        return value
    return f"<{len(value)} chars, starts {value[:4]!r}>"


def make_handler(show_secrets, log_path):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _handle(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("latin1") if n else ""
            q = parse_qs(urlparse(self.path).query)

            lines = [f"=== {time.strftime('%H:%M:%S')} {self.command} {self.path.split('?')[0]}"]
            for k, vs in q.items():
                for v in vs:
                    lines.append(f"    query {k} = {mask(k, v, show_secrets)}")
            # also pull tokenid/username out of an HTML form body, the way FortiTray does
            for k in ("tokenid", "username"):
                m = re.search(rf'name="{k}" value="([^"]+)"', body)
                if m:
                    lines.append(f"    form  {k} = {mask(k, m.group(1), show_secrets)}")
            out = "\n".join(lines)
            print(out)
            if log_path:
                with open(log_path, "a") as f:
                    f.write(out + "\n")

            page = (b"<html><body><h3>open-forticlient: SAML callback captured. "
                    b"You can close this tab.</h3></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        do_GET = do_POST = _handle

        def log_message(self, *a):  # silence default stderr logging
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True, help="loopback port to listen on")
    ap.add_argument("--show-secrets", action="store_true",
                    help="print raw tokenid instead of masking it")
    ap.add_argument("--log", help="also append captures to this file")
    args = ap.parse_args()

    srv = http.server.HTTPServer(("127.0.0.1", args.port),
                                 make_handler(args.show_secrets, args.log))
    print(f"listening on http://127.0.0.1:{args.port}  "
          f"(secrets {'SHOWN' if args.show_secrets else 'masked'}); Ctrl-C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
