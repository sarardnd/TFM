#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# tfm_auth_policies_check.py  (externo activo)
# - SPF/DMARC: DNS publicados (dnspython)
# - SPF (recalc): verificación real con pyspf (contraste con AR)
# - ARC: verificación criptográfica (dkimpy) + parseo pasivo
# - Devuelve JSON (para Autopsy vía core)

import sys, json, re, os
from email import policy
from email.parser import BytesParser

# -------------------- utils --------------------
def u(x):
    if x is None:
        return ""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "ignore")
        except Exception:
            return x.decode("latin-1", "ignore")
    return str(x)

def org_domain_simple(host):
    if not host: return None
    parts = host.lower().strip().split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower().strip()

def find_from_domain(from_hdr):
    if not from_hdr:
        return None
    s = u(from_hdr).strip()
    if '<' in s and '>' in s:
        s = s.split('<')[-1].split('>')[0]
    if '@' in s:
        return s.split('@')[-1].strip().lower()
    return s.strip().lower() or None

def _extract_domain(val):
    if not val: return None
    s = u(val).strip().strip('<>').strip('"').strip("'")
    if '@' in s:
        s = s.split('@')[-1]
    return s.strip(' ;:,()[]').lower() or None

# -------------------- DNS (dnspython) --------------------
_dns_error = None
try:
    import dns.resolver
except Exception as e:
    _dns_error = str(e)
    dns = None

def dns_txt(name, timeout=5.0):
    if _dns_error is not None:
        return False, _dns_error
    try:
        answers = dns.resolver.resolve(name, 'TXT', lifetime=timeout)
        vals = []
        for r in answers:
            try:
                if hasattr(r, 'strings'):
                    vals.append(b"".join(r.strings).decode('utf-8', 'ignore'))
                else:
                    vals.append(str(r))
            except Exception:
                vals.append(str(r))
        return True, vals
    except Exception as e:
        return False, str(e)

# -------------------- Authentication-Results parse --------------------
def parse_authentication_results(msg):
    ars = msg.get_all('Authentication-Results') or []
    out = []
    AR_ITEM_RE = re.compile(r'(?P<key>[a-zA-Z0-9_.-]+)\s*=\s*(?P<val>[^;\s]+)')
    AR_AUTHRES_ID_RE = re.compile(r'^\s*([a-z0-9.-]+)\s*;', re.IGNORECASE)
    for raw in ars:
        line = ' '.join(u(raw).split())
        d = {'raw': line, 'authserv_id': None, 'kv': {}, 'spf': [], 'dmarc': [], 'dkim': [], 'arc': [], 'other': []}
        m = AR_AUTHRES_ID_RE.search(line or '')
        if m:
            d['authserv_id'] = m.group(1).strip().lower()
        for m in AR_ITEM_RE.finditer(line or ''):
            k = m.group('key').strip().lower()
            v = m.group('val').strip()
            d['kv'][k] = v
            if k.startswith('spf') or k == 'spf':
                d['spf'].append((k, v))
            elif k.startswith('dmarc') or k == 'dmarc':
                d['dmarc'].append((k, v))
            elif k.startswith('dkim') or k == 'dkim':
                d['dkim'].append((k, v))
            elif k.startswith('arc') or k == 'arc':
                d['arc'].append((k, v))
            else:
                d['other'].append((k, v))
        out.append(d)
    return out

def _pick_spf_context_from_ar(ar_list):
    """Extrae client-ip, helo y mailfrom de AR (primer bloque útil)."""
    client_ip = helo = mailfrom = None
    for ar in ar_list:
        kv = ar.get('kv') or {}
        if not client_ip and kv.get('smtp.client-ip'):
            client_ip = kv.get('smtp.client-ip')
        if not helo and kv.get('smtp.helo'):
            helo = kv.get('smtp.helo')
        if not mailfrom:
            for key in ('smtp.mailfrom','mailfrom','envelope-from'):
                if kv.get(key):
                    mailfrom = kv.get(key)
                    break
        if client_ip and (helo or mailfrom):
            break
    return client_ip, helo, mailfrom

# -------------------- ARC pasivo --------------------
def parse_arc_chain(msg):
    seals = msg.get_all('ARC-Seal') or []
    ams   = msg.get_all('ARC-Message-Signature') or []
    aar   = msg.get_all('ARC-Authentication-Results') or []

    def _i_list(values):
        out = []
        for raw in values:
            m = re.search(r'\bi\s*=\s*([0-9]+)', u(raw))
            if m:
                try:
                    out.append(int(m.group(1)))
                except:
                    pass
        return sorted(set(out))

    def _i_to_cv_map(seals_list):
        d = {}
        for raw in seals_list:
            i_m = re.search(r'\bi\s*=\s*([0-9]+)', u(raw))
            if not i_m:
                continue
            try:
                i = int(i_m.group(1))
            except:
                continue
            cv_m = re.search(r'\bcv\s*=\s*([a-zA-Z]+)', u(raw))
            if cv_m:
                d[i] = cv_m.group(1).strip().lower()
        return d

    i_seal = _i_list(seals)
    i_ams  = _i_list(ams)
    i_aar  = _i_list(aar)

    instances = sorted(set(i_seal) | set(i_ams) | set(i_aar))
    complete = False
    if instances:
        expected = list(range(1, max(instances) + 1))
        if instances == expected:
            complete = all(i in i_seal for i in expected) and \
                       all(i in i_ams  for i in expected) and \
                       all(i in i_aar  for i in expected)

    cv_map = _i_to_cv_map(seals)
    last_cv = cv_map.get(max(cv_map.keys())) if cv_map else None

    return {
        "instances": instances,
        "complete": bool(complete),
        "last_cv": last_cv or "none",
        "count": len(instances)
    }

# -------------------- ARC criptográfico (dkimpy) --------------------
def arc_crypto_verify(raw_bytes):
    """
    Verificación ARC robusta para diferentes builds de dkimpy.
    Orden:
      1) dkim.arcverify.verify(msg)
      2) dkim.arcverify.ArcVerifier/ARCVerifier(...).verify()/validate()
      3) Fallback CLI:  python -m dkim.arcverify  (lee msg por stdin)
    Devuelve: {supported, ok, result, details, impl}
    """
    import sys as _sys
    import importlib
    try:
        import dkim
    except Exception as e:
        return {"supported": False, "ok": False, "result": "missing_dkimpy", "details": str(e), "impl": None}

    # ---- helper para normalizar resultado ----
    def _pack(result, details, impl):
        r = (str(result).lower() if result is not None else "unknown")
        ok = r in ("pass", "ok", "valid", "true", "success")
        return {"supported": True, "ok": ok, "result": str(result), "details": (details.decode("utf-8","ignore") if isinstance(details, bytes) else details), "impl": impl}

    last_err = None

    # 1) dkim.arcverify.verify
    try:
        arcverify = importlib.import_module("dkim.arcverify")
        if hasattr(arcverify, "verify") and callable(getattr(arcverify, "verify")):
            res = arcverify.verify(raw_bytes)
            if isinstance(res, tuple):
                return _pack(res[0], res[1] if len(res) > 1 else None, "dkim.arcverify.verify")
            else:
                return _pack(res, None, "dkim.arcverify.verify")
        last_err = "no arcverify.verify"
    except Exception as e:
        last_err = "import dkim.arcverify failed: {}".format(e)

    # 2) ArcVerifier / ARCVerifier con verify()/validate()
    try:
        arcverify = importlib.import_module("dkim.arcverify")
        for cname in ("ArcVerifier", "ARCVerifier"):
            if hasattr(arcverify, cname):
                Cls = getattr(arcverify, cname)
                try:
                    v = Cls(raw_bytes)  # algunas versiones aceptan msg en el ctor
                except TypeError:
                    try:
                        v = Cls()       # o sin argumentos
                        if hasattr(v, "set_message"):
                            v.set_message(raw_bytes)
                    except Exception as e2:
                        last_err = "cannot instantiate {}: {}".format(cname, e2); continue
                # busca método
                for mname in ("verify", "validate", "verify_arc"):
                    if hasattr(v, mname) and callable(getattr(v, mname)):
                        try:
                            res = getattr(v, mname)()
                            if isinstance(res, tuple):
                                return _pack(res[0], res[1] if len(res) > 1 else None, "dkim.arcverify.{}().{}".format(cname, mname))
                            else:
                                return _pack(res, None, "dkim.arcverify.{}().{}".format(cname, mname))
                        except Exception as e3:
                            last_err = "{}.{} raised: {}".format(cname, mname, e3)
                last_err = "no verifier method"
    except Exception as e:
        last_err = "arcverify class route failed: {}".format(e)

    # 5) Fallback CLI: python -m dkim.arcverify  (lee stdin, parsea salida)
    try:
        import subprocess, shlex
        cmd = [_sys.executable, "-m", "dkim.arcverify"]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(raw_bytes, timeout=15)
        text = (out or b"").decode("utf-8", "ignore").strip().lower()
        # dkimpy suele imprimir 'pass' / 'fail' / 'neutral' o mensajes más largos
        if "pass" in text:
            return _pack("pass", out.decode("utf-8","ignore"), "cli:python -m dkim.arcverify")
        if "fail" in text:
            return _pack("fail", out.decode("utf-8","ignore"), "cli:python -m dkim.arcverify")
        if p.returncode == 0 and text:
            # no incluye 'pass'/'fail' explícito; damos salida textual
            return {"supported": True, "ok": False, "result": "unknown", "details": text, "impl": "cli:python -m dkim.arcverify"}
        last_err = "cli exit rc={} out={} err={}".format(p.returncode, text, (err or b"").decode("utf-8","ignore"))
    except Exception as e:
        last_err = "cli arcverify failed: {}".format(e)

    return {"supported": False, "ok": False, "result": "no_arc_api", "details": last_err, "impl": None}

# -------------------- SPF recalc (pyspf) --------------------
def spf_recalc(client_ip, helo, mailfrom, from_domain):
    """
    Recalcula SPF con pyspf: check2(i=IP, s=sender, h=helo)
    Devuelve diccionario con resultado y alineación organizativa con From.
    """
    try:
        import spf  # pyspf
    except Exception as e:
        return {"supported": False, "error": "missing_pyspf: {}".format(e)}

    if not client_ip:
        return {"supported": True, "skipped": True, "reason": "no client-ip in AR"}

    # Elegir sender 's=': si no hay mailfrom (<>), usar postmaster@HELO
    sender_domain = _extract_domain(mailfrom) or _extract_domain(helo) or None
    if sender_domain:
        sender = "postmaster@" + sender_domain if '@' not in (mailfrom or '') else mailfrom
    else:
        return {"supported": True, "skipped": True, "reason": "no helo/mailfrom domain"}

    try:
        res, code, txt = spf.check2(i=client_ip, s=sender, h=helo or sender_domain)
        # res: 'pass','fail','softfail','neutral','permerror','temperror','none'
        spf_dom = _extract_domain(sender_domain)
        from_org = org_domain_simple(from_domain)
        spf_org  = org_domain_simple(spf_dom)
        aligned = (from_domain and spf_dom) and (
            from_domain.lower() == spf_dom.lower() or
            (from_org and spf_org and from_org == spf_org)
        )
        return {
            "supported": True,
            "result": (res or "").lower(),
            "explanation": txt,
            "used": {
                "ip": client_ip,
                "helo": helo,
                "mailfrom": mailfrom,
                "sender_checked": sender,
                "sender_domain": spf_dom
            },
            "aligned_with_from": bool(aligned)
        }
    except Exception as e:
        return {"supported": True, "error": "spf_check_exception: {}".format(e)}

# -------------------- main --------------------
def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        print(json.dumps({"error": "no_input"}))
        return
    # Parse
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        from email.parser import Parser
        try:
            txt = raw.decode('utf-8', 'ignore')
            msg = Parser().parsestr(txt)
        except Exception as e:
            print(json.dumps({"error": "parse_error", "msg": str(e)}))
            return

    from_hdr = msg.get('From') or msg.get('from') or ""
    from_dom = find_from_domain(from_hdr)
    from_org = org_domain_simple(from_dom) if from_dom else None

    # AR
    ar_list = parse_authentication_results(msg)

    # SPF recalc (pyspf) a partir de AR
    client_ip, helo, mailfrom = _pick_spf_context_from_ar(ar_list)
    spf_recalc_block = spf_recalc(client_ip, helo, mailfrom, from_dom)

    # SPF DNS (publicados)
    spf_targets = []
    if from_dom:
        spf_targets.append(from_dom)
        org = org_domain_simple(from_dom)
        if org and org != from_dom:
            spf_targets.append(org)
    spf_dns = {}
    for dom in spf_targets:
        ok, val = dns_txt(dom)
        if ok:
            spf_dns[dom] = [t for t in val if t.lower().startswith('v=spf1')]
        else:
            spf_dns[dom] = {"error": u(val)}

    # ---------- DMARC DNS ----------
    dmarc_dns = {}
    if from_dom:
        dmarc_target = "_dmarc." + from_dom
        ok, val = dns_txt(dmarc_target)
        if ok:
            recs = [t for t in val if t.lower().startswith('v=dmarc1')]
            parsed = {}
            if recs:
                for tok in recs[0].split(';'):
                    tok = tok.strip()
                    if '=' in tok:
                        k,v = tok.split('=',1)
                        parsed[k.strip().lower()] = v.strip()
            dmarc_dns = {"found": bool(recs), "records": recs, "parsed": parsed, "source": from_dom}
        else:
            # si el subdominio no existe, intentamos el dominio organizativo
            org = org_domain_simple(from_dom)
            if org and org != from_dom:
                org_target = "_dmarc." + org
                ok2, val2 = dns_txt(org_target)
                if ok2:
                    recs2 = [t for t in val2 if t.lower().startswith('v=dmarc1')]
                    parsed2 = {}
                    if recs2:
                        for tok in recs2[0].split(';'):
                            tok = tok.strip()
                            if '=' in tok:
                                k,v = tok.split('=',1)
                                parsed2[k.strip().lower()] = v.strip()
                    dmarc_dns = {
                        "found": bool(recs2),
                        "records": recs2,
                        "parsed": parsed2,
                        "source": org + " (heredado)"
                    }
                else:
                    dmarc_dns = {"error": u(val2)}
            else:
                dmarc_dns = {"error": u(val)}


    # ARC pasivo y cripto
    arc_state = parse_arc_chain(msg)
    arc_crypto = arc_crypto_verify(raw)

    out = {
        "from_header": from_hdr if from_hdr else None,
        "from_domain": from_dom,
        "from_org": from_org,
        "authentication_results": ar_list,
        "spf_dns": spf_dns,
        "dmarc_dns": dmarc_dns,
        "arc": arc_state,
        "arc_crypto": arc_crypto,
        "spf_recalc": spf_recalc_block
    }

    for k in ("spf_dns", "dmarc_dns", "arc", "arc_crypto", "spf_recalc"):
        if out.get(k) is None:
            out[k] = {}
    print(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
