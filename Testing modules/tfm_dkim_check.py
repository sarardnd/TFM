#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tfm_dkim_check.py
Lee un mensaje EML desde --file (o stdin si no se pasa) y:
 - intenta verificar DKIM (dkimpy)
 - consulta selector DNS (dnspython)
 - reporta alineación d= vs From:
 - indica si el dominio está en whitelist local
Salida: JSON en stdout
"""
from __future__ import annotations
import sys, json, re, os, argparse
from email import policy
from email.parser import BytesParser

# Dependencias
try:
    import dkim
    import dns.resolver
except Exception as e:
    sys.stdout.write(json.dumps({"error": "missing_dependency", "msg": str(e)}))
    sys.exit(2)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE_DIR, "dkim_whitelist.txt")

DKIM_SIG_RE = re.compile(r'\bd=([^;\s]+)', re.I)
SELECTOR_RE = re.compile(r'\bs=([^;\s]+)', re.I)

# -------- CLI
ap = argparse.ArgumentParser(add_help=False)
ap.add_argument("--file", dest="file", default=None)
args, _ = ap.parse_known_args()

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
    m = re.search(r'@([A-Za-z0-9.\-]+)', from_hdr)
    if m:
        return m.group(1).lower()
    parts = from_hdr.split()
    for p in reversed(parts):
        if '.' in p:
            return p.strip('<>,"').lower()
    return None

def org_domain_simple(host):
    if not host: return host
    parts = host.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host

def extract_dkim_headers(msg):
    return msg.get_all('DKIM-Signature') or []

def parse_sig_params(sig_text):
    parts = re.split(r';\s*', sig_text)
    d=None; s=None
    for p in parts:
        if p.strip() == '': 
            continue
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

# ---- Variantes de verificación para diagnóstico
def normalize_lf_to_crlf(b):
    # Convierte a '\n' primero para evitar duplicar CR
    return b.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

def ensure_final_crlf(b):
    return b if b.endswith(b"\r\n") else (b + b"\r\n")

def verify_variant(label, raw):
    try:
        ok = dkim.verify(raw)
        return {"variant": label, "attempted": True, "verified": bool(ok), "error": None}
    except Exception as e:
        return {"variant": label, "attempted": False, "verified": False, "error": str(e)}

def read_raw():
    if args.file:
        with open(args.file, "rb") as fh:
            return fh.read()
    return sys.stdin.buffer.read()

def main():
    raw = read_raw()
    if not raw:
        print(json.dumps({"error": "no_input"})); return

    # Parse headers para contexto (no re-serializar)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        from email.parser import Parser
        msg = Parser().parsestr(raw.decode('utf-8','ignore'))

    from_hdr = msg.get('From') or msg.get('from') or ""
    from_dom = get_domain_from_from_header(from_hdr)
    from_org = org_domain_simple(from_dom) if from_dom else None

    signatures = extract_dkim_headers(msg)
    whitelist = read_whitelist(WHITELIST_FILE)

    results = []
    for sig in signatures:
        d, s = parse_sig_params(sig)
        entry = {"raw": sig, "d": d, "s": s}
        if s and d:
            fqdn = "{}._domainkey.{}".format(s, d)
            dns_ok, dns_val = dns_txt_lookup(fqdn)
            entry["selector_dns_ok"] = dns_ok
            entry["selector_txt"] = dns_val if dns_ok else []
        else:
            entry["selector_dns_ok"] = False
            entry["selector_txt"] = []
        if d and from_dom:
            entry["alignment"] = "ALIGNED" if org_domain_simple(d) == from_org else "MISALIGNED"
        else:
            entry["alignment"] = "UNKNOWN"
        results.append(entry)

    # — Verificación (triage)
    variants = [
        verify_variant("raw", raw),
        verify_variant("lf_to_crlf", normalize_lf_to_crlf(raw)),
        verify_variant("crlf_ensure_eof", ensure_final_crlf(raw)),
    ]
    verified_any = any(v["verified"] for v in variants)
    attempted_any = any(v["attempted"] for v in variants)

    domain_signs = bool(from_dom and whitelist and from_dom.lower() in whitelist)

    out = {
        "from_header": from_hdr or None,
        "from_domain": from_dom,
        "dkim_signatures_count": len(signatures),
        "signatures": results,
        "verify": {
            "verify_attempted": attempted_any,
            "verified": verified_any,
            "variants": variants
        },
        "domain_usually_signs": domain_signs,
    }
    print(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
