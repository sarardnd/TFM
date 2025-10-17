# -*- coding: utf-8 -*-
# tfm_email_core.py — utilities


import re, hashlib
from email.utils import parsedate_tz, mktime_tz
from email.Header import decode_header

from email.Header import decode_header

def u_(x):
    """Asegura unicode (Jython)."""
    try:
        if isinstance(x, unicode): return x
        return unicode(x, "utf-8", "ignore")
    except:
        return unicode(str(x), "utf-8", "ignore")

def decode_mime_header(val):
    """Decodifica cabeceras MIME (Subject, From, etc.)."""
    if not val: return u""
    parts = []
    for b, c in decode_header(val):
        if c:
            try:
                parts.append(unicode(b, c, "ignore"))
            except:
                parts.append(unicode(b, "utf-8", "ignore"))
        else:
            if isinstance(b, unicode):
                parts.append(b)
            else:
                try:
                    parts.append(unicode(b, "utf-8"))
                except:
                    parts.append(unicode(b, "latin-1", "ignore"))
    return u"".join(parts)

def date_to_epoch(date_str):
    """Convierte 'Date:' a epoch (segundos)."""
    try:
        import email.Utils as EU
        tup = EU.parsedate_tz(u_(date_str))
        if tup: return long(EU.mktime_tz(tup))
    except:
        pass
    return long(0)

def received_to_epoch(msg):
    """Devuelve el epoch del primer 'Received:' (fecha tras el último ';')."""
    rec_list = msg.get_all('Received') or []
    for r in rec_list:
        try:
            parts = r.rsplit(';', 1)
            if len(parts) == 2:
                ts = date_to_epoch(parts[1])
                if ts > 0: return ts
        except:
            pass
    return long(0)

def sha256_bytes(b): 
    """SHA-256 hex de bytes."""
    return hashlib.sha256(b).hexdigest()

# ---------- utilidades de host / dominios ----------
def _norm_host(h):
    """Normaliza host (lower, sin corchetes/paréntesis)."""
    if not h: return None
    h = h.strip().lower()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    h = h.strip('()')
    return h or None

def _org_domain(h):
    """Dominio organizativo simple (dos labels finales)."""
    if not h: return None
    parts = h.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return h

def _cluster_domain(h):
    """3-4 labels finales para agrupar clusters (útil M365)."""
    if not h: return None
    parts = h.split('.')
    if len(parts) >= 4:
        return '.'.join(parts[-4:])
    if len(parts) >= 3:
        return '.'.join(parts[-3:])
    return h

def _same_host(a, b):
    return _norm_host(a) == _norm_host(b)

def _same_cluster(a, b):
    return _cluster_domain(_norm_host(a)) == _cluster_domain(_norm_host(b))

def _same_org(a, b):
    return _org_domain(_norm_host(a)) == _org_domain(_norm_host(b))

# ---------- utilidades IP (IPv4 privadas, IPv6 privadas) ----------
# CIDRs privados/reservados IPv4
_PRIVATE_V4 = [
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("127.0.0.0", 8),        # loopback
    ("169.254.0.0", 16),     # link-local
    ("100.64.0.0", 10),      # CGNAT
]

def ip_to_int(ip):
    try:
        a,b,c,d = [int(x) for x in ip.split(".")]
        return (a<<24) + (b<<16) + (c<<8) + d
    except:
        return None

def in_cidr(ip, base, prefix):
    ipi = ip_to_int(ip); basei = ip_to_int(base)
    if ipi is None or basei is None: return False
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ipi & mask) == (basei & mask)

def is_private_v4(ip):
    for base, pref in _PRIVATE_V4:
        if in_cidr(ip, base, pref):
            return True
    return False

# Extractores principales: IPs en corchetes
_IPV4_BRACKET_RE = re.compile(r'\[(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]')
_IPV6_BRACKET_RE = re.compile(r'\[(?:IPv6:)?(?P<ip>[0-9A-Fa-f:]{2,})\]')

# Fallback seguro: IPs en paréntesis, pero SOLO justo tras 'from'/'by'
_FROM_PAREN = re.compile(r'\bfrom\s+[^\s;()]+\s*\((?P<paren>[^)]*)\)', re.IGNORECASE)
_BY_PAREN   = re.compile(r'\bby\s+[^\s;()]+\s*\((?P<paren>[^)]*)\)',   re.IGNORECASE)
_IPV4_BARE  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
_IPV6_BARE  = re.compile(r'\b[0-9A-Fa-f:]{2,}\b')

def _ips_in_paren_blob(blob):
    """Busca IPv4/IPv6 en el contenido de paréntesis de from/by."""
    v4 = _IPV4_BARE.findall(blob or '')
    v6 = [s for s in _IPV6_BARE.findall(blob or '') if ':' in s and any(c in s.lower() for c in 'abcdef:')]
    return v4, v6

def extract_ips_from_received(raw):
    """Extrae IPs priorizando [corchetes]; si no hay, fallback a (paréntesis) de from/by."""
    # 1) Fuerte: corchetes
    v4 = [m.group('ip') for m in _IPV4_BRACKET_RE.finditer(raw)]
    v6 = [m.group('ip') for m in _IPV6_BRACKET_RE.finditer(raw)
          if ':' in m.group('ip') and any(c in m.group('ip').lower() for c in 'abcdef:')]

    # 2) Fallback: paréntesis SOLO tras from/by
    if not v4 and not v6:
        mfrom = _FROM_PAREN.search(raw)
        if mfrom:
            a4, a6 = _ips_in_paren_blob(mfrom.group('paren'))
            v4 += a4; v6 += a6
        mby = _BY_PAREN.search(raw)
        if mby:
            a4, a6 = _ips_in_paren_blob(mby.group('paren'))
            v4 += a4; v6 += a6

    # deduplicar manteniendo orden
    def _dedup(seq):
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    return _dedup(v4), _dedup(v6)

def looks_private_v6_addr(ip):
    """IPv6 privada: ::1, fe80::/10 (link-local), fc00::/7 (ULA)."""
    low = ip.lower()
    if low == '::1':
        return True
    # fe80::/10 (fe80..febf)
    if low.startswith('fe8') or low.startswith('fe9') or low.startswith('fea') or low.startswith('feb'):
        return True
    # ULA fc00::/7 (fc.. o fd..)
    if low.startswith('fc') or low.startswith('fd'):
        return True
    return False

# ---------- parseo & análisis de Received ----------
# from ... by ... (permitir saltos de línea y rarezas)
_FROM_BY_RE = re.compile(
    r'\bfrom\s+([^\s;()]+).*?\bby\s+([^\s;()]+)',
    re.IGNORECASE | re.DOTALL
)
# by-only (Gmail hop #0)
_BY_ONLY_RE = re.compile(r'\bby\s+([^\s;()]+)', re.IGNORECASE)

def _parse_received_timestamp(raw):
    """Extrae la fecha tras el último ';' y la convierte a epoch UTC."""
    parts = raw.rsplit(';', 1)
    if len(parts) < 2:
        return (None, None)
    date_part = parts[1].strip()
    t = parsedate_tz(date_part)
    if t is None:
        return (None, None)
    try:
        epoch = mktime_tz(t)
        return (epoch, date_part)
    except:
        return (None, None)

def normalize_header_spacing(raw):
    """Une líneas dobladas y colapsa espacios."""
    return ' '.join(raw.split())

def parse_received_chain(msg):
    """Devuelve lista de hops con campos clave para análisis."""
    hops = []
    recvs = msg.get_all('Received') or []
    for i, raw in enumerate(recvs):
        norm = normalize_header_spacing(raw)
        epoch, datestr = _parse_received_timestamp(norm)

        # from/by o by-only
        m = _FROM_BY_RE.search(norm)
        if m:
            frm = m.group(1)
            by  = m.group(2)
        else:
            m2 = _BY_ONLY_RE.search(norm)
            frm = None
            by  = m2.group(1) if m2 else None

        v4, v6 = extract_ips_from_received(norm)
        has_priv = any(is_private_v4(ip) for ip in v4) or any(looks_private_v6_addr(ip) for ip in v6)

        hops.append({
            'idx': i,
            'raw': raw,
            'norm': norm,
            'epoch': epoch,
            'date_str': datestr,
            'from': frm,
            'by': by,
            'ipv4': v4,
            'ipv6': v6,
            'has_priv': bool(has_priv),
        })
    return hops

def analyze_received_chain(hops):
    """
    Hallazgos:
      - reverse_order: pares (i-1, i) cuando epoch[i] > epoch[i-1]
      - no_date: indices sin fecha parseable
      - priv_ip: indices con IP privada/loopback
      - link_breaks: indices donde falla la continuidad BY[i+1] == FROM[i]
                     (relajada por cluster/organización)
    """
    issues = {
        'reverse_order': [],
        'no_date': [],
        'priv_ip': [],
        'link_breaks': [],
    }
    # Fechas faltantes + IPs privadas
    for h in hops:
        if h['epoch'] is None:
            issues['no_date'].append(h['idx'])
        if h['has_priv']:
            issues['priv_ip'].append(h['idx'])

    # Orden cronológico (de 0→n deben ser no crecientes)
    for i in range(1, len(hops)):
        prev, cur = hops[i-1], hops[i]
        if prev['epoch'] is not None and cur['epoch'] is not None:
            if cur['epoch'] > prev['epoch']:
                issues['reverse_order'].append((i-1, i))

    # Continuidad BY[i+1] == FROM[i] (relajada por cluster/organización)
    for i in range(0, len(hops)-1):
        frm_i = hops[i]['from']
        by_next = hops[i+1]['by']
        if not frm_i or not by_next:
            continue
        if _same_host(by_next, frm_i):
            continue
        if _same_cluster(by_next, frm_i):
            continue
        if _same_org(by_next, frm_i):
            continue
        issues['link_breaks'].append(i+1)  # ruptura observada en el hop siguiente

    return issues

def summarize_received_findings(hops, issues):
    """Construye el texto para Analysis Results + puntuación."""
    parts = []
    n = len(hops)
    parts.append("Cadena Received: {} hops".format(n))

    if issues['reverse_order']:
        pairs = ["{}→{}".format(a,b) for (a,b) in issues['reverse_order']]
        parts.append("\n• Orden cronológico inverso en pares de hops: " + ", ".join(pairs))
    if issues['no_date']:
        parts.append("\n• Hops sin fecha parseable: " + ", ".join(str(i) for i in issues['no_date']))

    # Desglosar IP privada en ALERTA vs INFO (local/org)
    priv_info = []
    priv_alert = []
    for i in issues['priv_ip']:
        h = hops[i]
        iplist = (h['ipv4'] + h['ipv6']) or []
        text = "\n#{} [{}]".format(i, ", ".join(iplist) if iplist else "priv/loopback")
        if _same_host(h.get('from'), h.get('by')) or _same_org(h.get('from'), h.get('by')):
            priv_info.append(text)
        else:
            priv_alert.append(text)

    if priv_alert:
        parts.append("\n• IP privada/loopback potencialmente expuesta en hops: " + ", ".join(priv_alert))
    if priv_info:
        parts.append("\n• INFO: IP privada/loopback en hop local/organización: " + ", ".join(priv_info))

    if issues['link_breaks']:
        parts.append("\n• Posibles hops faltantes (continuidad BY[i+1]≠FROM[i]) en: " +
                     ", ".join(str(i) for i in issues['link_breaks']))

    # Detalle compacto por hop
    parts.append("— Detalle por hop —")
    for h in hops:
        v4 = ", ".join(h['ipv4']) if h['ipv4'] else "-"
        v6 = ", ".join(h['ipv6']) if h['ipv6'] else "-"
        parts.append("\n#{} from={} by={} date={} ipv4={} ipv6={}{}".format(
            h['idx'],
            h['from'] or "-",
            h['by'] or "-",
            h['date_str'] or "-",
            v4, v6,
            " [PRIV]" if h['has_priv'] else ""
        ))

    if len(parts) == 2:
        parts.insert(1, "\n• Sin anomalías evidentes en Received.")

    # Puntuación: severidad simple
    score = 0
    score += 20 * len(issues['reverse_order'])
    score += 10 * len(issues['no_date'])

    # Penalización ajustada por IP privada (leve si hop local/org)
    priv_penalty = 0
    for i in issues['priv_ip']:
        h = hops[i]
        if _same_host(h.get('from'), h.get('by')) or _same_org(h.get('from'), h.get('by')):
            priv_penalty += 5
        else:
            priv_penalty += 15
    score += priv_penalty

    score += 15 * len(issues['link_breaks'])

    return "\n".join(parts), score