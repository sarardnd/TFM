#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tfm_dkim_check.py
Lee un mensaje EML desde stdin (raw bytes) y:
 - intenta verificar DKIM (usando dkimpy)
 - consulta selector DNS (selector._domainkey.domain) con dnspython
 - reporta alineamiento d= vs From:
 - indica si el dominio está en una whitelist local (dominios que suelen firmar)
Salida: JSON en stdout
"""
from __future__ import annotations
import sys, json, re, os
from email import policy
from email.parser import BytesParser

# Dependencias: dkim (dkimpy), dns.resolver (dnspython)
try:
    import dkim
    import dns.resolver
except Exception as e:
    sys.stdout.write(json.dumps({"error": "missing_dependency", "msg": str(e)}))
    sys.exit(2)

# Ajustes
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE_DIR, "dkim_whitelist.txt")  # opcional

DKIM_SIG_RE = re.compile(r'\bd=([^;\s]+)', re.I)
SELECTOR_RE = re.compile(r'\bs=([^;\s]+)', re.I)

def read_whitelist(path):
    if not os.path.exists(path):
        return set()
    out = set()
    try:
        with open(path, 'r') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#'):
                    out.add(line.lower())
    except:
        pass
    return out

def get_domain_from_from_header(from_hdr):
    if not from_hdr:
        return None
    # intentar extraer lo que hay detrás de '@'
    m = re.search(r'@([A-Za-z0-9.\-]+)', from_hdr)
    if m:
        return m.group(1).lower()
    # fallback: coger el último token con punto
    parts = from_hdr.split()
    for p in reversed(parts):
        if '.' in p:
            return p.strip('<>,"').lower()
    return None

def org_domain_simple(host):
    if not host: return host
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host

def extract_dkim_headers(msg):
    vals = msg.get_all('DKIM-Signature') or []
    return vals

def parse_sig_params(sig_text):
    # divide por ';' y extrae pares k=v
    parts = re.split(r';\s*', sig_text)
    d=None; s=None
    for p in parts:
        if p.strip() == '': continue
        m = re.match(r'\s*d\s*=\s*([^;\s]+)', p, re.I)
        if m: d = m.group(1)
        m2 = re.match(r'\s*s\s*=\s*([^;\s]+)', p, re.I)
        if m2: s = m2.group(1)
    return d, s

def dns_txt_lookup(fqdn):
    try:
        answers = dns.resolver.resolve(fqdn, 'TXT', lifetime=5.0)
        txts = []
        for r in answers:
            # r.strings is list of bytes in py3; join them
            try:
                if hasattr(r, 'strings'):
                    txts.append(b"".join(r.strings).decode('utf-8', 'ignore'))
                else:
                    txts.append(str(r))
            except:
                txts.append(str(r))
        return True, txts
    except Exception as e:
        return False, str(e)

def verify_dkim(raw_bytes):
    """
    Usa dkim.verify(raw_bytes). dkim.verify devuelve True si al menos
    una firma verifica (por defecto). Para más granularidad
    podríamos usar dkim.signatures() / dkim._get_signature(...), pero
    dkim.verify es suficiente para el objetivo práctico.
    """
    try:
        ok = dkim.verify(raw_bytes)
        return True, bool(ok), None
    except Exception as e:
        return False, False, str(e)

def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        print(json.dumps({"error": "no_input"}))
        return

    # parseamos el mensaje (solo headers suficientes aquí)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        # fallback a parsing más permisivo
        from email.parser import Parser
        try:
            txt = raw.decode('utf-8', 'ignore')
            msg = Parser().parsestr(txt)
        except Exception as e:
            print(json.dumps({"error": "parse_error", "msg": str(e)}))
            return

    from_hdr = msg.get('From') or msg.get('from') or ""
    from_dom = get_domain_from_from_header(from_hdr)
    from_org = org_domain_simple(from_dom)

    signatures = extract_dkim_headers(msg)
    whitelist = read_whitelist(WHITELIST_FILE)

    results = []
    for sig in signatures:
        d, s = parse_sig_params(sig)
        entry = {"raw": sig, "d": d, "s": s}
        # DNS selector check
        if s and d:
            fqdn = "{}._domainkey.{}".format(s, d)
            dns_ok, dns_val = dns_txt_lookup(fqdn)
            entry["selector_dns_ok"] = dns_ok
            entry["selector_txt"] = dns_val if dns_ok else []
        else:
            entry["selector_dns_ok"] = False
            entry["selector_txt"] = []

        # alignment: org domain compare
        if d and from_dom:
            entry["alignment"] = "ALIGNED" if org_domain_simple(d) == from_org else "MISALIGNED"
        else:
            entry["alignment"] = "UNKNOWN"

        results.append(entry)

    # verification (cryptographic) — dkim.verify on whole message
    ok_env, verified_flag, verify_err = verify_dkim(raw)
    verify_info = {
        "verify_attempted": ok_env,
        "verified": verified_flag,
        "verify_error": verify_err
    }

    # mark domain usually signing (whitelist)
    domain_signs = False
    if from_dom and from_dom.lower() in whitelist:
        domain_signs = True

    out = {
        "from_header": from_hdr if from_hdr else None,
        "from_domain": from_dom,
        "dkim_signatures_count": len(signatures),
        "signatures": results,
        "verify": verify_info,
        "domain_usually_signs": domain_signs,
    }

    print(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
