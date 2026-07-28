#!/usr/bin/env python3
"""
Servidor DELIBERADAMENTE VULNERÁVEL — apenas para validar os detectores do
ParamHunter em laboratório local (127.0.0.1). NÃO EXPOR NA REDE.

Endpoints:
  /page?q=            reflete q (XSS / reflexão)
  /read?file=         path traversal real (lê arquivo do disco -> LFI)
  /ping?host=         command injection real (echo <host> via shell)
  /fetch?url=         SSRF real (faz GET server-side na url)
  /tpl?name=          SSTI simulada (avalia {{expr}} aritmética)
  /go?next=           open redirect (302 Location: next)
  /hdr?lang=          CRLF (header refletido)
  /sqli?id=           SQLi simulada (erro / boolean / time-based)
"""
import re
import json
import time
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

HOST, PORT = "127.0.0.1", 8000

# resposta de introspection mínima: Query.user(id: String): User
GRAPHQL_SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": None,
    "types": [
        {"kind": "OBJECT", "name": "Query", "inputFields": None, "enumValues": None, "fields": [
            {"name": "user",
             "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
            {"name": "search",
             "args": [{"name": "q", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
        ]},
        {"kind": "OBJECT", "name": "User", "inputFields": None, "enumValues": None, "fields": [
            {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]},
    ]}}}


SESSIONS = set()          # tokens de sessão válidos (mock de login)
_COUNTER = [0]            # p/ baseline dinâmico
import threading, time as _t
_RACE = {"used": False, "ts": 0.0}          # cupom vulnerável (sem trava)
_RACE_SAFE = {"used": False, "ts": 0.0}     # cupom com trava
_RACE_LOCK = threading.Lock()


def _b64d(s):
    import base64
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _jwt_ok(tok):
    """Mock VULNERÁVEL: aceita alg=none e HMAC com segredo 'secret'."""
    import json as _j, hmac, hashlib, base64
    parts = tok.split(".")
    if len(parts) < 2:
        return False
    try:
        header = _j.loads(_b64d(parts[0]))
    except Exception:
        return False
    alg = str(header.get("alg", "")).lower()
    if alg == "none":                        # vuln: alg=none aceito
        return True
    if alg == "hs256" and len(parts) == 3:   # vuln: segredo fraco 'secret'
        signing = f"{parts[0]}.{parts[1]}".encode()
        sig = hmac.new(b"secret", signing, hashlib.sha256).digest()
        want = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return want == parts[2]
    return False


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencia
        pass

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    def _send(self, body="", code=200, headers=None, ctype="text/html"):
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            try:
                self.send_header(k, v)
            except Exception:
                pass
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        u = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        # -------- login: valida user/pass/csrf e cria sessão --------
        if u.path == "/login":
            form = dict(parse_qs(raw, keep_blank_values=True))
            def gv(k): return form.get(k, [""])[0]
            if gv("user") == "admin" and gv("pass") == "admin" and gv("csrf_token") == "tok-abc-123":
                import secrets as _s
                sess = _s.token_hex(8)
                SESSIONS.add(sess)
                return self._send('<html>Bem-vindo admin</html>', code=200,
                                  headers={"Set-Cookie": f"session={sess}; Path=/"})
            return self._send("<html>login invalido</html>", code=401)
        # -------- API: SSTI via corpo JSON  POST /api/render {"name":...} --------
        if u.path == "/api/render":
            try:
                body = json.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:
                body = {}
            name = str(body.get("name", ""))
            def _e(m):
                e = m.group(1)
                return str(eval(e)) if re.fullmatch(r"[0-9\s\*\+\-]+", e) else m.group(0)  # noqa: S307
            rendered = re.sub(r"\{\{([^}]+)\}\}", _e, name)
            return self._send(json.dumps({"rendered": rendered}), ctype="application/json")
        # -------- mass assignment: ecoa o corpo JSON recebido --------
        if u.path == "/mass":
            try:
                body = json.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:
                body = {}
            return self._send(json.dumps({"saved": body}), ctype="application/json")

        # -------- API field discovery: ecoa só campos de um whitelist --------
        if u.path == "/apidisc":
            try:
                body = json.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:
                body = {}
            allow = {"email", "role", "is_admin", "plan", "balance", "token"}
            echoed = {k: v for k, v in body.items() if k in allow}
            return self._send(json.dumps({"accepted": echoed}), ctype="application/json")

        # -------- deserialização: erro ao ver blob serializado --------
        if u.path == "/deser":
            low = raw
            if "rO0" in low or "\xac\xed" in low:
                return self._send("java.io.InvalidClassException: local class incompatible", code=500)
            if low.startswith("O:") or "O:8:" in low or "Error at offset" in low:
                return self._send("PHP Warning: unserialize(): Error at offset 0 of 5 bytes", code=500)
            if "gASV" in low or "\x80\x04" in low:
                return self._send("_pickle.UnpicklingError: invalid load key", code=500)
            if "AAEAAAD" in low:
                return self._send("System.Runtime.Serialization.SerializationException", code=500)
            return self._send("ok")

        # -------- XXE: resolve entidade externa (simulado) --------
        if u.path == "/xxe":
            m = re.search(r'SYSTEM\s+"([^"]+)"', raw)
            if m:
                uri = m.group(1)
                if uri.startswith("file://"):
                    fp = uri[len("file://"):]
                    try:
                        with open(fp, "r", errors="replace") as fh:
                            return self._send("<r>" + fh.read(300) + "</r>", ctype="application/xml")
                    except Exception:
                        return self._send("<r></r>", ctype="application/xml")
                if uri.startswith("http"):
                    try:
                        urllib.request.urlopen(uri, timeout=3)   # dispara callback OOB
                    except Exception:
                        pass
                    return self._send("<r>ok</r>", ctype="application/xml")
            return self._send("<r>ok</r>", ctype="application/xml")

        # -------- GraphQL: introspection + resolver com SQLi --------
        if u.path == "/graphql":
            try:
                q = json.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:
                q = {}
            query = q.get("query", "")
            if "__schema" in query or "IntrospectionQuery" in query:
                return self._send(json.dumps(GRAPHQL_SCHEMA), ctype="application/json")
            for v in (q.get("variables") or {}).values():
                if isinstance(v, str) and ("'" in v or "union select" in v.lower()):
                    return self._send(json.dumps({"errors": [{"message":
                        "You have an error in your SQL syntax (MySQL) near ''"}]}),
                        code=500, ctype="application/json")
            return self._send(json.dumps({"data": {"user": {"__typename": "User"}}}),
                              ctype="application/json")

        # fallback: ecoa o corpo (reflexão)
        return self._send(json.dumps({"echo": raw[:300]}), ctype="application/json")

    def do_GET(self):
        u = urlsplit(self.path)
        path = u.path
        qs = parse_qs(u.query, keep_blank_values=True)

        def g(name, default=""):
            return qs.get(name, [default])[0]

        # -------- reflexão / XSS --------
        if path == "/page":
            q = g("q")
            return self._send(f"<html><body>Resultado para: {q}</body></html>")

        # -------- LFI real --------
        if path == "/read":
            f = unquote(g("file"))
            try:
                with open(f, "r", errors="replace") as fh:
                    return self._send(fh.read())
            except Exception as e:
                return self._send(f"erro ao ler: {e}", code=200)

        # -------- Command Injection real --------
        if path == "/ping":
            host = g("host")
            try:
                out = subprocess.run(f"echo pong {host}", shell=True,
                                     capture_output=True, text=True, timeout=20)
                return self._send(f"<pre>{out.stdout}{out.stderr}</pre>")
            except subprocess.TimeoutExpired:
                return self._send("timeout", code=200)

        # -------- SSRF real --------
        if path == "/fetch":
            url = g("url")
            try:
                r = urllib.request.urlopen(url, timeout=5)
                return self._send(f"fetched {r.status}: {r.read(200).decode('latin1')}")
            except Exception as e:
                return self._send(f"fetch erro: {e}")

        # -------- SSTI simulada --------
        if path == "/tpl":
            name = g("name")
            def _eval(m):
                expr = m.group(1)
                if re.fullmatch(r"[0-9\s\*\+\-]+", expr):
                    try:
                        return str(eval(expr))  # noqa: S307 (lab)
                    except Exception:
                        return m.group(0)
                return m.group(0)
            rendered = re.sub(r"\{\{([^}]+)\}\}", _eval, name)
            return self._send(f"<h1>Olá {rendered}</h1>")

        # -------- Open Redirect --------
        if path == "/go":
            nxt = g("next")
            return self._send("", code=302, headers={"Location": nxt})

        # -------- CRLF --------
        if path == "/hdr":
            lang = g("lang")
            # simula app que reflete valor cru num header
            hdrs = {}
            for line in lang.replace("\r\n", "\n").split("\n"):
                if ":" in line and line.strip() and not line.startswith(("http", "/")):
                    k, v = line.split(":", 1)
                    if re.fullmatch(r"[A-Za-z0-9_-]+", k.strip()):
                        hdrs[k.strip()] = v.strip()
            hdrs.setdefault("Content-Language", lang.split("\n")[0][:40])
            return self._send("ok", headers=hdrs)

        # -------- API: LFI via PATH PARAM  /api/files/{file} --------
        m = re.match(r"/api/files/(.+)", path)
        if m:
            f = unquote(m.group(1))
            try:
                with open(f, "r", errors="replace") as fh:
                    return self._send(json.dumps({"content": fh.read(300)}), ctype="application/json")
            except Exception as e:
                return self._send(json.dumps({"error": str(e)}), ctype="application/json")

        # ===== endpoints LIMPOS (sem vulnerabilidade) — medir falso-positivo =====
        import html as _html
        if path == "/clean_static":       # ignora o input, página fixa
            return self._send("<html><body>Bem-vindo. Nada para ver aqui.</body></html>")
        if path == "/clean_esc":          # reflete com escape (XSS mitigado)
            return self._send(f"<html>busca por: {_html.escape(g('q'))}</html>")
        if path == "/clean_num":          # id numérico validado; nada refletido cru
            idv = g("id")
            if not idv.isdigit():
                return self._send("<html>id invalido</html>", code=400)
            return self._send("<html>usuario numero valido</html>")
        if path == "/clean_json":         # API que ignora o input
            return self._send(json.dumps({"status": "ok", "items": 3}), ctype="application/json")

        # -------- DOM/XSS que EXECUTA (reflete q em contexto executável) --------
        if path == "/dom":
            return self._send(f"<html><body><div>resultado: {g('q')}</div></body></html>")

        # -------- race: cupom VULNERÁVEL (sem trava, janela TOCTOU) --------
        if path == "/race":
            now = _t.time()
            if now - _RACE["ts"] > 2:      # reset entre execuções de teste
                _RACE["used"] = False
            _RACE["ts"] = now
            if not _RACE["used"]:
                _t.sleep(0.02)             # alarga a janela check->set
                _RACE["used"] = True
                return self._send("<html>CUPOM APLICADO saldo +100</html>")
            return self._send("<html>CUPOM JA UTILIZADO</html>")

        # -------- race_safe: cupom com TRAVA (mutex) — não deve dar FP --------
        if path == "/race_safe":
            now = _t.time()
            with _RACE_LOCK:
                if now - _RACE_SAFE["ts"] > 2:
                    _RACE_SAFE["used"] = False
                _RACE_SAFE["ts"] = now
                if not _RACE_SAFE["used"]:
                    _t.sleep(0.02)
                    _RACE_SAFE["used"] = True
                    return self._send("<html>CUPOM APLICADO saldo +100</html>")
                return self._send("<html>CUPOM JA UTILIZADO</html>")

        # -------- login (GET form c/ CSRF) --------
        if path == "/login":
            return self._send('<form method="post" action="/login">'
                              '<input type="hidden" name="csrf_token" value="tok-abc-123">'
                              '<input name="user"><input name="pass"></form>')
        # -------- dashboard protegido (marcador "Bem-vindo") --------
        if path == "/dashboard":
            if self._cookie("session") in SESSIONS:
                return self._send(f"<html><body><h1>Bem-vindo admin</h1>"
                                  f"<p>busca: {g('q')}</p></body></html>")
            return self._send("<html>faca login</html>", code=401)
        # -------- crawler: HTML com links + JS com endpoints --------
        if path == "/crawl":
            return self._send(
                '<html><body>'
                '<a href="/idor?id=1">perfil</a> <a href="/sqli?id=1">busca</a> '
                '<a href="/page?q=x">q</a>'
                '<form method=get action="/search"><input name=term></form>'
                '<script>fetch("/api/search?q=test");var u="/api/files/report.pdf";'
                'axios.get("/graphql");</script>'
                '</body></html>')
        # -------- JWT: aceita alg=none e segredo "secret" --------
        if path == "/jwt":
            auth = self.headers.get("Authorization", "")
            tok = auth.replace("Bearer ", "").strip() or (self._cookie("jwt") or "")
            if _jwt_ok(tok):
                return self._send("<html>acesso admin concedido</html>")
            return self._send("<html>401 token invalido</html>", code=401)
        # -------- baseline DINÂMICO (instável de propósito) --------
        if path == "/dynamic":
            _COUNTER[0] += 1
            import random, html as _h
            return self._send(f"<html>id={_h.escape(g('id'))} nonce={random.random()} "
                              f"hits={_COUNTER[0]} {'x'*random.randint(0,200)}</html>")

        # -------- IDOR: cada id retorna um objeto (usuário) diferente e válido --------
        if path == "/idor":
            idv = g("id")
            users = {
                "1": "Alice Silva  alice@corp.com  saldo R$ 1200  cpf 111.111.111-11",
                "2": "Bob Souza    bob@corp.com    saldo R$ 8800  cpf 222.222.222-22",
                "3": "Admin Root   root@corp.com   saldo R$ 99999 cpf 000.000.000-00",
                "0": "System       sys@corp.com    saldo R$ 0     cpf 999.999.999-99",
            }
            u = users.get(idv)
            if u is None:
                return self._send("<html><body>usuario nao encontrado</body></html>", code=404)
            return self._send(f"<html><body><h2>Perfil</h2><p>{u}</p></body></html>")

        # -------- cache poisoning: reflete X-Forwarded-Host + headers de cache --------
        if path == "/cache":
            xfh = self.headers.get("X-Forwarded-Host", "")
            return self._send(f'<link rel=canonical href="https://{xfh}/">',
                              headers={"Age": "42", "X-Cache": "HIT",
                                       "Cache-Control": "public, max-age=300"})

        # -------- Host-header injection: reflete X-Forwarded-Host no corpo --------
        if path == "/hh":
            xfh = (self.headers.get("X-Forwarded-Host") or self.headers.get("X-Host")
                   or self.headers.get("X-Forwarded-Server") or self.headers.get("Host", ""))
            return self._send(f'<html><a href="https://{xfh}/reset?token=abc">redefinir senha</a></html>')

        # -------- API: XSS/reflexão via QUERY  /api/search?q= --------
        if path == "/api/search":
            return self._send(json.dumps({"results_for": g("q")}), ctype="application/json")

        # -------- NoSQLi / LDAP / XPath (erro simulado) --------
        if path == "/nosql":
            v = g("user")
            if "'" in v or "||" in v or "$" in v or "\"" in v:
                return self._send("{\"error\":\"MongoError: unexpected token near '\"}", code=500,
                                  ctype="application/json")
            return self._send("{\"ok\":true}", ctype="application/json")
        if path == "/ldap":
            v = g("u")
            if "*" in v or ")(" in v or "|" in v or "(" in v:
                return self._send("javax.naming: LDAP: error code 4 - Bad search filter", code=500)
            return self._send("ok")
        if path == "/xpath":
            v = g("q")
            if "'" in v or "]" in v or "\"" in v:
                return self._send("Warning: SimpleXMLElement::xpath(): Invalid expression XPathException", code=500)
            return self._send("ok")

        # -------- /hpptest: WAF vê o 1º valor, backend usa o ÚLTIMO (bypass HPP) --------
        if path == "/hpptest":
            vals = qs.get("id", [""])
            first, last = vals[0], vals[-1]
            if "'" in first or "\"" in first:            # "WAF" inspeciona só o 1º
                return self._send("403 blocked by WAF", code=403)
            if "'" in last:                              # backend usa o ÚLTIMO
                return self._send("You have an error in your SQL syntax (MySQL) near ''", code=500)
            return self._send("ok")

        # -------- /wafmulti: WAF em 2 params (testa cache de bypass) --------
        if path == "/wafmulti":
            for name in ("a", "b"):
                raw = g(name)
                if not raw:
                    continue
                if any(x in raw.lower() for x in ("../", "etc/passwd", "<script", "union select")):
                    return self._send("<title>Attention Required! | Cloudflare</title>blocked",
                                      code=403, headers={"Server": "cloudflare", "CF-RAY": "aa11bb22-GRU"})
                real = unquote(raw)
                try:
                    with open(real, "r", errors="replace") as fh:
                        return self._send(fh.read(200))
                except Exception:
                    pass
            return self._send("ok")

        # -------- /waf: "WAF" bloqueia payload cru mas backend RE-decodifica --------
        # (só variantes codificadas/encadeadas passam pelo filtro -> LFI)
        if path == "/waf":
            raw = g("file")                       # já veio url-decodificado 1x pelo parse_qs
            blocked = ("../", "..\\", "etc/passwd", "<script", "<svg", "union select",
                       "onerror", "system(", "jndi:", "169.254")
            if any(b in raw.lower() for b in blocked):
                # simula bloqueio da Cloudflare (fingerprint de fabricante)
                return self._send(
                    "<html><head><title>Attention Required! | Cloudflare</title></head>"
                    "<body>Sorry, you have been blocked</body></html>",
                    code=403,
                    headers={"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f6789-GRU"})
            real = unquote(raw)                   # camada extra de decode do backend
            try:
                with open(real, "r", errors="replace") as fh:
                    return self._send(fh.read(400))
            except Exception:
                return self._send("(sem arquivo)")

        # -------- multi-parâmetro: cada param com uma vuln diferente --------
        if path == "/multi":
            # file -> LFI ; name -> SSTI ; id -> SQLi ; q -> XSS ; next -> redirect
            f = unquote(g("file"))
            out = []
            if f:
                try:
                    with open(f, "r", errors="replace") as fh:
                        out.append(fh.read(400))
                except Exception:
                    out.append("(sem arquivo)")
            name = g("name")
            def _e(m):
                e = m.group(1)
                return str(eval(e)) if re.fullmatch(r"[0-9\s\*\+\-]+", e) else m.group(0)  # noqa: S307
            out.append("tpl:" + re.sub(r"\{\{([^}]+)\}\}", _e, name))
            idv = g("id")
            if "'" in idv or '"' in idv:
                out.append("SQL syntax error near '' (MySQL)")
            q = g("q")
            out.append(f"busca: {q}")
            nxt = g("next")
            hdrs = {"Location": nxt} if nxt else {}
            code = 302 if nxt else 200
            return self._send("<html>" + " | ".join(out) + "</html>", code=code, headers=hdrs)

        # -------- SQLi simulada --------
        if path == "/sqli":
            idv = g("id")
            low = idv.lower()
            if "sleep(5)" in low or "pg_sleep(5)" in low or "waitfor delay" in low \
                    or "dbms_pipe" in low:
                time.sleep(5)
                return self._send("<html>ok</html>")
            if "'" in idv or '"' in idv or idv.endswith("\\"):
                return self._send(
                    "<b>You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version near ''</b>",
                    code=500)
            if "1=2" in idv.replace(" ", ""):
                return self._send("<html>nenhum resultado</html>")
            return self._send("<html>usuario: admin (id=1) email a@b.c telefone 123</html>")

        return self._send("ParamHunter vuln-lab. rotas: /page /read /ping /fetch /tpl /go /hdr /sqli")


if __name__ == "__main__":
    print(f"[vuln-lab] http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
