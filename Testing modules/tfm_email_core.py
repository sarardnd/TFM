# -*- coding: utf-8 -*-
# tfm_email_core.py — utilities
from __future__ import unicode_literals

import re, hashlib, base64
from email.utils import parsedate_tz, mktime_tz
from email.Header import decode_header
import math
import sys, os

def u_(x):
    """Ensure unicode (Jython)."""
    try:
        if isinstance(x, unicode): return x
        return unicode(x, "utf-8", "ignore")
    except:
        return unicode(str(x), "utf-8", "ignore")

def decode_mime_header(val):
    """Decode MIME headers(Subject, From...)"""
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
# --- Helpers de destinatarios ---
def _decode_addrlist(pairs):
    """
    Decode [(name, addr)] -> string list "Nombre <addr>" or "addr".
    """
    out = []
    for nm, addr in pairs:
        nm_dec = decode_mime_header(nm) if nm else u""
        addr_u  = u_(addr) if addr else u""
        if nm_dec and addr_u:
            out.append(u"%s <%s>" % (nm_dec, addr_u))
        elif addr_u:
            out.append(addr_u)
        elif nm_dec:
            out.append(nm_dec)
    return out

def best_recipient(msg):
    """
    Returns a string with the 'best' recipients to display:
    - To, Forward To, Delivered To, X-Original-To, Envelope-To.
    - Supports multiple headers and multiple addresses per header.
    - Deduplicates while maintaining order.
    """
    try:
        # Py2/Jython: getaddresses is in email.Utils
        import email.Utils as EUtils
    except:
        import email.utils as EUtils  # fallback

    candidate_headers = [
        'To', 'Resent-To', 'Delivered-To', 'X-Original-To', 'Envelope-To'
    ]

    seen = set()
    ordered = []

    for h in candidate_headers:
        raw_vals = msg.get_all(h)
        if not raw_vals:
            continue
        # There can be multiple headers and multiple addresses per header
        addrs = []
        for raw in raw_vals:
            try:
                addrs.extend(EUtils.getaddresses([u_(raw)]))
            except:
                # at least add the raw string
                addrs.append((u"", u_(raw)))

        decoded = _decode_addrlist(addrs)
        for item in decoded:
            key = item.strip().lower()
            if key and key not in seen:
                seen.add(key)
                ordered.append(item)

    return u", ".join(ordered)

def date_to_epoch(date_str):
    """Convert 'Date:' to epoch (secs)."""
    try:
        import email.Utils as EU
        tup = EU.parsedate_tz(u_(date_str))
        if tup: return long(EU.mktime_tz(tup))
    except:
        pass
    return long(0)

def received_to_epoch(msg):
    """Returns the epoch of the first 'Received:' (date after the last ';')"""
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
    """SHA-256 bytes."""
    return hashlib.sha256(b).hexdigest()

# ---------- utilidades de host / dominios ----------
def _norm_host(h):
    """Normalize host (lower, without brackets/parentheses)."""
    if not h: return None
    h = h.strip().lower()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    h = h.strip('()')
    return h or None

def _org_domain(h):
    """Simple organizational domain (two final labels)."""
    if not h: return None
    parts = h.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return h

def _cluster_domain(h):
    """3-4 final labels for grouping clusters (useful M365)."""
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

# ---------- IP utilities (IPv4 private, IPv6 private) ----------
# CIDRs private/reserved IPv4
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

# Main extractors: IPs in brackets
_IPV4_BRACKET_RE = re.compile(r'\[(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]')
_IPV6_BRACKET_RE = re.compile(r'\[(?:IPv6:)?(?P<ip>[0-9A-Fa-f:]{2,})\]')

# Safe fallback: IPs in parentheses, but ONLY right after 'from'/'by'
_FROM_PAREN = re.compile(r'\bfrom\s+[^\s;()]+\s*\((?P<paren>[^)]*)\)', re.IGNORECASE)
_BY_PAREN   = re.compile(r'\bby\s+[^\s;()]+\s*\((?P<paren>[^)]*)\)',   re.IGNORECASE)
_IPV4_BARE  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
_IPV6_BARE  = re.compile(r'\b[0-9A-Fa-f:]{2,}\b')

def _ips_in_paren_blob(blob):
    """Search for IPv4/IPv6 in the parenthetical content of from/by."""
    v4 = _IPV4_BARE.findall(blob or '')
    v6 = [s for s in _IPV6_BARE.findall(blob or '') if ':' in s and any(c in s.lower() for c in 'abcdef:')]
    return v4, v6

def extract_ips_from_received(raw):
    """Extract IPs prioritizing [brackets]; if none, fallback to (parentheses) of from/by."""
    # 1) Brackets
    v4 = [m.group('ip') for m in _IPV4_BRACKET_RE.finditer(raw)]
    v6 = [m.group('ip') for m in _IPV6_BRACKET_RE.finditer(raw)
          if ':' in m.group('ip') and any(c in m.group('ip').lower() for c in 'abcdef:')]

    # 2) Fallback: parentheses only after from/by
    if not v4 and not v6:
        mfrom = _FROM_PAREN.search(raw)
        if mfrom:
            a4, a6 = _ips_in_paren_blob(mfrom.group('paren'))
            v4 += a4; v6 += a6
        mby = _BY_PAREN.search(raw)
        if mby:
            a4, a6 = _ips_in_paren_blob(mby.group('paren'))
            v4 += a4; v6 += a6

    # deduplicate taking into acount the order
    def _dedup(seq):
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    return _dedup(v4), _dedup(v6)

def looks_private_v6_addr(ip):
    """IPv6 private: ::1, fe80::/10 (link-local), fc00::/7 (ULA)."""
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

# ---------- parse & analysis of Received ----------
# from ... by ... (allow line breaks and oddities)
_FROM_BY_RE = re.compile(
    r'\bfrom\s+([^\s;()]+).*?\bby\s+([^\s;()]+)',
    re.IGNORECASE | re.DOTALL
)
# by-only (Gmail hop #0)
_BY_ONLY_RE = re.compile(r'\bby\s+([^\s;()]+)', re.IGNORECASE)

def _parse_received_timestamp(raw):
    """Extract the date after the last ';' and convert it to epoch UTC."""
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
    """Join folded lines and collapse spaces."""
    return ' '.join(raw.split())

def parse_received_chain(msg):
    """Returns a list of hops with key fields for analysis."""
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
    Findings:
    - reverse_order: (i-1, i) pairs where epoch[i] > epoch[i-1] 
    - no_date: indices without a parseable date
    - priv_ip: indices with private IPs/loopbacks
    - link_breaks: indices where continuity fails under BY[i+1] == FROM[i]
                            (relaxed by cluster/organization)
    """
    issues = {
        'reverse_order': [],
        'no_date': [],
        'priv_ip': [],
        'link_breaks': [],
    }
    # Missing dates + private IPs
    for h in hops:
        if h['epoch'] is None:
            issues['no_date'].append(h['idx'])
        if h['has_priv']:
            issues['priv_ip'].append(h['idx'])

    # Chronological order (from 0→n they must be non-increasing)
    for i in range(1, len(hops)):
        prev, cur = hops[i-1], hops[i]
        if prev['epoch'] is not None and cur['epoch'] is not None:
            if cur['epoch'] > prev['epoch']:
                issues['reverse_order'].append((i-1, i))

    # Continuity BY[i+1] == FROM[i] (relaxed by cluster/organization)
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
        issues['link_breaks'].append(i+1)  # break observed on the next hop

    return issues

def summarize_received_findings(hops, issues):
    """Build the text for Analysis Results + punctuation."""
    parts = []
    n = len(hops)
    parts.append("Received Chain: {} hops".format(n))

    if issues['reverse_order']:
        pairs = ["{}→{}".format(a,b) for (a,b) in issues['reverse_order']]
        parts.append("\n- Reverse chronological order in pairs of hops: " + ", ".join(pairs))
    if issues['no_date']:
        parts.append("\n- Hops without a parsable date: " + ", ".join(str(i) for i in issues['no_date']))

    # Break down private IP in ALERT vs INFO (local/org)
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
        parts.append("\n- Private IP/loopback potentially exposed in hops: " + ", ".join(priv_alert))
    if priv_info:
        parts.append("\n- INFO: Private IP/loopback in local hop/organization: " + ", ".join(priv_info))

    if issues['link_breaks']:
        parts.append("\n- Possible missing hops (continuity BY[i+1]≠FROM[i]) in: " +
                     ", ".join(str(i) for i in issues['link_breaks']))

    #Compact detail per hop
    parts.append("— Detail per hop —")
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
        parts.insert(1, "\n- No apparent anomalies in Received.")

    #Score: simple severity
    score = 0
    score += 20 * len(issues['reverse_order'])
    score += 10 * len(issues['no_date'])

    # Penalty adjusted for private IP (mild if hop local/org)
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

# =============== DATE COHERENCE (helpers) ===============
def get_date_header_epoch(msg):
    """
    Extrae y convierte la cabecera 'Date:' a epoch UTC.
    Detecta y reporta múltiples cabeceras Date:
    Devuelve (epoch, date_str, is_multiple_date_header)
    """
    date_list = msg.get_all('Date') or []
    
    is_multiple = len(date_list) > 1
    
    if not date_list:
        return None, None, False
        
    # Usamos la primera Date: si hay múltiples, pero marcamos la anomalía
    date_str = date_list[0] 
    
    if date_str:
        epoch = date_to_epoch(date_str)
        if epoch > 0:
            return epoch, u_(date_str), is_multiple
    return None, None, is_multiple

def get_all_time_headers(msg):
    """
    Recopila épocas de cabeceras de tiempo alternativas.
    Útiles como contexto, pero no para comprobaciones de coherencia fuertes.
    """
    ALT_HEADERS = ['X-Received', 'Delivery-date', 'Resent-Date', 'X-Original-ArrivalTime']
    alt_dates = {}
    
    for h_name in ALT_HEADERS:
        h_values = msg.get_all(h_name) or []
        for val in h_values:
            val = u_(val)
            # X-Original-ArrivalTime es especial: "DD Mon YY HH:MM:SS.mmm (UTC) [IP]"
            if h_name == 'X-Original-ArrivalTime':
                # Intentamos extraer el timestamp del formato de Exchange
                m = re.match(r'\s*(.+?)\s+\(UTC\)', val)
                date_part = m.group(1) if m else val
            else:
                # Para otras, el valor completo es la fecha
                date_part = val
                
            epoch = date_to_epoch(date_part)
            if epoch > 0:
                if h_name not in alt_dates:
                    alt_dates[h_name] = []
                alt_dates[h_name].append({'epoch': epoch, 'str': val})
                
    return alt_dates

def analyze_date_coherence(date_epoch, date_str, is_multiple_date, hops, f_date, ingest_time):
    """
    Analiza la coherencia entre Date: (declarada), Received (último hop), 
    metadatos de archivo (f_date), y la hora de ingesta (ingest_time).
    
    date_epoch: epoch de la cabecera Date:
    is_multiple_date: True si se encontraron múltiples cabeceras Date:
    hops: lista de hops de Received (del parser original)
    f_date: epoch de la última modificación/creación del archivo EML
    ingest_time: epoch del momento en que Autopsy está procesando
    
    Devuelve un diccionario de hallazgos.
    """
    issues = {
        'no_date_header': False, 
        'multiple_date_header': is_multiple_date, # Nuevo: Más de una Date:
        'date_after_last_recv': None, 
        'file_before_date': None, 
        'file_after_last_recv': None,
        'date_in_future': None, # Nuevo: Date: en el futuro (respecto a ingest_time)
        'last_recv_epoch': None,
        'last_recv_idx': None
    }
    
    if date_epoch is None:
        issues['no_date_header'] = True
        return issues
        
    # 1. Obtener la fecha del primer hop Received (el último en el tiempo)
    last_recv_epoch = None
    last_recv_idx = None
    for h in hops:
        if h['epoch'] is not None:
            # Encontramos la Received: con el timestamp más grande (más reciente)
            if last_recv_epoch is None or h['epoch'] > last_recv_epoch:
                last_recv_epoch = h['epoch']
                last_recv_idx = h['idx']

    issues['last_recv_epoch'] = last_recv_epoch
    issues['last_recv_idx'] = last_recv_idx

    # 2. Date: posterior al último Received
    # Un desfase mayor a 5 minutos (300s) es sospechoso
    if last_recv_epoch is not None:
        diff = date_epoch - last_recv_epoch
        if diff > 300: 
            issues['date_after_last_recv'] = diff

    # 3. Date: en el futuro (respecto al reloj de ingesta)
    # Si Date: es más de 24h (86400s) en el futuro, es ALERTA fuerte
    if ingest_time is not None:
        diff_future = date_epoch - ingest_time
        if diff_future > 86400: 
            issues['date_in_future'] = diff_future
    
    # 4. Metadato de archivo EML (f_date) vs Date:
    if f_date is not None and f_date > 0:
        diff = date_epoch - f_date
        # Si f_date es más de 7 días (604800s) anterior a Date:
        if diff > 604800: 
            issues['file_before_date'] = diff 
        
        # 5. Metadato de archivo EML (f_date) vs Último Received
        if last_recv_epoch is not None:
            diff_recv = f_date - last_recv_epoch
            # Si f_date es más de 7 días (604800s) posterior al último Received:
            if diff_recv > 604800: 
                issues['file_after_last_recv'] = diff_recv

    return issues

def summarize_date_coherence_findings(date_str, f_date, issues, alt_dates):
    """Construye el texto para Analysis Results + puntuación."""
    parts = []
    score = 0
    
    # Valores de entrada
    parts.append("Fecha Declarada (Date:): {}".format(date_str or "AUSENTE / INVÁLIDA"))
    parts.append("Último Received (Epoch): {}".format(issues['last_recv_epoch'] or "AUSENTE"))
    parts.append("Metadato Archivo EML (M/C Time): {}".format(f_date or "AUSENTE"))
    
    # Nuevo: Cabeceras alternativas (solo contexto)
    if alt_dates:
        parts.append("\n--- Cabeceras de Tiempo Alternativas ---")
        for h_name, dates in alt_dates.items():
            for d in dates:
                parts.append("• {}: {} (Epoch {})".format(h_name, d['str'], d['epoch']))
    
    parts.append("\n--- Hallazgos ---")
    
    if issues['no_date_header']:
        parts.append("• ALERTA: Cabecera 'Date:' ausente o formato inválido.")
        score += 30
    else:
        # Nuevo: Múltiples Date:
        if issues['multiple_date_header']:
            parts.append("• ALERTA: Múltiples cabeceras 'Date:' encontradas. Posible manipulación/reencapsulado.")
            score += 45
            
        # Nuevo: Date en el futuro
        if issues['date_in_future'] is not None:
            diff_d = float(issues['date_in_future']) / (3600.0 * 24)
            parts.append("• ¡SEVERA! 'Date:' está en el futuro (>{:.2f} días respecto a la hora de ingesta).".format(diff_d))
            score += 80 # Subimos la severidad por esta anomalía
            
        # Desfase Date: vs Último Received
        if issues['date_after_last_recv'] is not None:
            diff_h = float(issues['date_after_last_recv']) / 3600.0
            parts.append("• ALERTA: 'Date:' es posterior al último 'Received' (Hop #{}) por {:.2f} horas.".format(
                issues['last_recv_idx'], diff_h
            ))
            score += 50 

        # Desfase Metadato Archivo vs Date:
        if issues['file_before_date'] is not None:
            diff_d = float(issues['file_before_date']) / (3600.0 * 24)
            parts.append("• INFO: 'Date:' es mucho posterior a la fecha del archivo EML ({:.2f} días).".format(diff_d))
            score += 15 

        # Desfase Metadato Archivo vs Último Received
        if issues['file_after_last_recv'] is not None:
            diff_d = float(issues['file_after_last_recv']) / (3600.0 * 24)
            parts.append("• ALERTA: Fecha del archivo EML es posterior al último 'Received' ({:.2f} días). Sugiere manipulación del archivo.".format(diff_d))
            score += 40 
            
    if score == 0:
        parts.append("• Sin incongruencias temporales significativas detectadas.")

    return "\n".join(parts), score

# ==== Message-ID utilities (duplicados / formato sospechoso) ====
# Regex básica que captura algo tipo local@dominio dentro o fuera de '< >'
_MSGID_RE = re.compile(r'\<?\s*([^>\s]+@[^>\s]+)\s*\>?', re.UNICODE)

# Memoria por ejecución (ingest run):
#   clave: msgid normalizado
#   valor: lista de records: {'file_id': long, 'file_name': u'', 'from': u'', 'date': long, 'raw': u''}
_MSGID_STORE = {}

def msgid_normalize(raw):
    """Normaliza el Message-ID (quita < >, trim, lower)."""
    if not raw:
        return None
    r = u_(raw).strip()
    if r.startswith(u'<') and r.endswith(u'>'):
        r = r[1:-1].strip()
    r = r.strip().lower()
    return r or None

def msgid_extract_candidates(header_value):
    """
    Dado el valor de la cabecera Message-ID (posible múltiple por malformación),
    devuelve lista de candidatos normalizados.
    """
    if not header_value:
        return []
    hv = u_(header_value)
    found = _MSGID_RE.findall(hv)
    if not found:
        nm = msgid_normalize(hv)
        return [nm] if nm else []
    out = []
    for f in found:
        nm = msgid_normalize(f)
        if nm:
            out.append(nm)
    # dedup preservando orden
    seen = set(); dedup = []
    for x in out:
        if x not in seen:
            seen.add(x); dedup.append(x)
    return dedup

def msgid_get_local_part(msgid):
    """Extrae la parte local (antes de @) del Message-ID."""
    if not msgid or u'@' not in msgid:
        return None
    # Devuelve solo la primera parte
    return msgid.split(u'@', 1)[0]

def msgid_token_entropy(s):
    """
    Entropía de Shannon del string completo.
    Devuelve: (H_total, H_normalizada) donde H_normalizada = H / Hmax (0..1).
    """
    if not s: 
        return 0.0, 0.0
    from collections import Counter
    c = Counter(s)
    n = float(len(s))
    H = -sum((cnt/n)*math.log((cnt/n), 2) for cnt in c.values())
    # Hmax = log2(#símbolos distintos); evita división por 0
    uniq = len(c)
    Hmax = math.log(uniq, 2) if uniq > 1 else 1.0
    return H, (H / Hmax)

def msgid_has_valid_format(msgid):
    """
    Formato válido mínimo: contiene '@' y la parte de dominio tiene letras/números
    (admite localhost/hosts raros, pero descarta basura evidente).
    """
    if not msgid or u'@' not in msgid:
        return False
    local, domain = msgid.split(u'@', 1)
    if not local or not domain:
        return False
    if len(local)< 5:
        return False
    return True if re.search(r'[A-Za-z0-9]', domain) else False

def msgid_register(msgid, file_id, file_name, from_header=None, date_epoch=None, raw_msgid=None):
    """Registra una aparición de msgid (por archivo) en el store global del run."""
    nm = msgid_normalize(raw_msgid or msgid)
    if not nm:
        return
    rec = {
        'file_id'  : long(file_id) if file_id is not None else long(-1),
        'file_name': u_(file_name) if file_name else u'',
        'from'     : u_(from_header) if from_header else u'',
        'date'     : long(date_epoch) if date_epoch else long(0),
        'raw'      : u_(raw_msgid) if raw_msgid else u_(msgid),
    }
    _MSGID_STORE.setdefault(nm, []).append(rec)

def msgid_clear_store():
    """Limpia el índice en memoria."""
    _MSGID_STORE.clear()

def msgid_find_duplicates():
    """Devuelve dict {msgid: [records]} SOLO para los msgids con más de una aparición."""
    return {mid: recs for (mid, recs) in _MSGID_STORE.items() if len(recs) > 1}

def msgid_score_and_labels(msgid, records):
    """
    Score SOLO para la pasada global (evita duplicidades con el análisis local):
      +20 si remitentes distintos (posible spoof)
      +10 si es duplicado (>1)
    """
    score = 0
    labels = []

    froms = set([ (r.get('from') or u'').lower() for r in records if r.get('from') ])
    if len([f for f in froms if f]) > 1:
        score += 20
        labels.append('SPOOF_POSSIBLE')

    if len(records) > 1:
        score += 10
        labels.append('DUPLICATE')

    return score, labels

def msgid_summarize(msgid, records):
    """Estructura de resumen coherente con otros módulos."""
    score, labels = msgid_score_and_labels(msgid, records)
    return {
        'msgid' : msgid,
        'count' : len(records),
        'files' : [u"{} (#{} )".format(r.get('file_name', u''), r.get('file_id', -1)) for r in records],
        'froms' : list(sorted(set([u_(r.get('from')) for r in records if r.get('from')]))) or [],
        'dates' : [long(r.get('date') or 0) for r in records],
        'raws'  : [u_(r.get('raw')) for r in records],
        'score' : score,
        'labels': labels,
    }

# ==== X-HEADERS (X-Mailer, X-Exported-By, etc.) ====

def extract_x_headers(msg):
    """
    Devuelve un dict con:
      - 'all': lista de dicts {'name', 'value'}
      - 'signals': dict con campos útiles normalizados/heurísticos
    No lanza excepciones: valores siempre en unicode.
    """
    try:
        items = msg.items() or []
    except Exception:
        items = []
    x_all = []
    for (k, v) in items:
        try:
            if not k: 
                continue
            kn = u_(k)
            if kn.upper().startswith(u"X-"):
                x_all.append({
                    'name': kn,
                    'value': decode_mime_header(v) if v else u""
                })
        except Exception:
            # continúa con lo que se pueda
            continue

    # Señales específicas
    def _first_value(prefix):
        for h in x_all:
            if h['name'].lower() == prefix.lower():
                return h['value']
        return None

    # Conjuntos útiles
    x_mailer   = _first_value('X-Mailer')
    x_exported = _first_value('X-Exported-By')
    x_mimeole  = _first_value('X-MimeOLE')
    x_origip   = _first_value('X-Originating-IP')

    # Familia Exchange/Microsoft (muy frecuente en export/servidor)
    ms_family = [h for h in x_all if h['name'].lower().startswith('x-ms-') or
                                   h['name'].lower().startswith('x-forefront-') or
                                   h['name'].lower().startswith('x-microsoft-')]

    # Heurística conservadora de "posible exportación"
    # Caso fuerte: X-Exported-By presente
    possible_export = True if x_exported else False

    # Caso débil (solo INFO): cadenas típicas de clientes en X-Mailer
    weak_client_hint = False
    if x_mailer:
        low = x_mailer.lower()
        weak_client_hint = any(s in low for s in [
            'outlook', 'thunderbird', 'apple mail', 'gmail', 'iphone mail', 'android mail'
        ])

    return {
        'all': x_all,
        'signals': {
            'x_mailer'        : x_mailer,
            'x_exported_by'   : x_exported,
            'x_mimeole'       : x_mimeole,
            'x_originating_ip': x_origip,
            'ms_family_count' : len(ms_family),
            'possible_export' : possible_export,
            'weak_client_hint': weak_client_hint,
        }
    }

def summarize_x_headers_findings(xdata):
    """
    Construye texto y puntuación para publicar en Analysis Results.
    Puntuación:
      +40 si X-Exported-By presente (posible exportación)
      +10 si hay X-Mailer (solo contexto)
      +5  si hay familia MS (solo contexto)
    """
    parts = []
    score = 0

    allx = xdata.get('all') or []
    sigs = xdata.get('signals') or {}

    parts.append("Cabeceras X-* encontradas: {}".format(len(allx)))

    # Listado compacto (máximo 12 para no saturar)
    max_list = 12
    if allx:
        parts.append("\n— Lista X-* (máx {} mostradas) —".format(max_list))
        for i, h in enumerate(allx[:max_list]):
            parts.append("• {}: {}".format(h.get('name', ''), h.get('value', '')))
        if len(allx) > max_list:
            parts.append("… ({} más)".format(len(allx) - max_list))
    else:
        parts.append("\n(no hay cabeceras X-*)")

    parts.append("\n— Señales —")
    if sigs.get('x_exported_by'):
        parts.append("• POSIBLE EXPORTACIÓN: X-Exported-By = {}".format(sigs['x_exported_by']))
        score += 40
    else:
        parts.append("• X-Exported-By: ausente")

    if sigs.get('x_mailer'):
        parts.append("• X-Mailer: {}".format(sigs['x_mailer']))
        score += 10
    else:
        parts.append("• X-Mailer: ausente")

    if sigs.get('x_mimeole'):
        parts.append("• X-MimeOLE: {}".format(sigs['x_mimeole']))

    if sigs.get('x_originating_ip'):
        parts.append("• X-Originating-IP: {}".format(sigs['x_originating_ip']))

    ms_count = int(sigs.get('ms_family_count') or 0)
    if ms_count > 0:
        parts.append("• Familia Microsoft/Exchange presente ({} cabeceras).".format(ms_count))
        score += 5

    # Nota: weak_client_hint es solo informativo, no suma puntos
    if sigs.get('weak_client_hint'):
        parts.append("• INFO: X-Mailer parece indicar un cliente reconocido.")

    if score == 0:
        parts.append("• Sin señales fuertes de exportación o manipulación derivables solo de X-*.")

    return "\n".join(parts), int(score)

# ==== DKIM UTILITIES ====
def parse_dkim_headers(msg):
    """
    Extrae todas las cabeceras DKIM-Signature.
    Devuelve una lista de dicts con campos principales.
    """
    dkims = msg.get_all('DKIM-Signature') or []
    parsed = []
    for raw in dkims:
        try:
            fields = {}
            for part in re.split(r';\s*', raw):
                if '=' in part:
                    k, v = part.split('=', 1)
                    fields[k.strip()] = v.strip()
            parsed.append(fields)
        except Exception:
            continue
    return parsed

def verify_dkim_structure(fields):
    """
    Verifica la presencia mínima de campos DKIM y coherencia básica.
    No realiza validación criptográfica completa (sin DNS),
    pero detecta firmas truncadas, hash/body inconsistente, etc.
    """
    required = ['v', 'a', 'b', 'bh', 'd', 's', 'h','c','i','l','q','t','x']
    missing = [k for k in required if k not in fields]
    issues = []
    if missing:
        issues.append("Faltan campos: {}".format(', '.join(missing)))

    # Longitud de firma base64 b= (típicamente >100 chars)
    if 'b' in fields:
        try:
            siglen = len(fields['b'])
            if siglen < 50:
                issues.append("Firma (b=) inusualmente corta.")
        except:
            pass

    # Hash body (bh=) debería ser base64
    if 'bh' in fields:
        bh = fields['bh']
        try:
            base64.b64decode(bh)
        except Exception:
            issues.append("Campo bh= no es base64 válido.")

    return issues

def check_dkim_domain_alignment(dkim_domain, from_header):
    # Extraer la parte de la dirección y luego el dominio.
    from_part = from_header.strip().lower()
    
    # 1. Limpieza de display name y corchetes angulares
    if '<' in from_part and '>' in from_part:
        from_part = from_part.split('<')[-1].split('>')[0]
    
    # 2. Extracción del dominio tras el '@'
    if '@' in from_part:
        from_domain = from_part.split('@')[-1]
    else:
        # Si no hay @, asumimos que from_part ya es el dominio o está malformado
        from_domain = from_part
    
    return "ALIGNED" if _same_org(dkim_domain, from_domain) else "MISALIGNED"

def dkim_selector_dns_exists(selector, domain):
    """
    Comprobación DNS simulada: no realiza query real (Jython sin red),
    pero valida formato plausible de selector._domainkey.domain.
    Devuelve True si selector/domino tienen formato correcto.
    """
    if not selector or not domain:
        return False
    fqdn = "{}._domainkey.{}".format(selector, domain)
    return bool(re.match(r'^[A-Za-z0-9._-]+\._domainkey\.[A-Za-z0-9.-]+$', fqdn))

# Lista para simular la reputación/expectativa de firma (basada en el dominio organizativo)
_EXPECTED_SIGNERS = {
    'gmail.com':    True,  # Siempre debería firmar
    'google.com':   True,
    'microsoft.com': True,
    'outlook.com':  True,
    'yahoo.com':    True,
}

def dkim_expected_to_sign(dkim_domain):
    """
    Comprueba si el dominio organizativo DKIM está en la lista de firmantes esperados.
    Si AUSENTE, el score penaliza más. Si PRESENTE y NO FIRMA, penaliza AÚN MÁS.
    """
    if not dkim_domain: return False
    org_dom = _org_domain(_norm_host(dkim_domain))
    return _EXPECTED_SIGNERS.get(org_dom, False)

def summarize_dkim_findings(parsed, from_header):
    """
    Construye el resumen textual + puntuación global DKIM.
    """
    parts = []
    score = 0

    if not parsed:
        parts.append("Cabecera DKIM-Signature: AUSENTE")
        
        from_part = u_(from_header).strip().lower() 
        # 1. Limpieza de display name y corchetes angulares
        if u'<' in from_part and u'>' in from_part:
            from_part = from_part.split(u'<')[-1].split(u'>')[0]
        
        # 2. Extracción del dominio tras el '@'
        if u'@' in from_part:
            from_domain = from_part.split(u'@')[-1].strip()
        else:
            from_domain = from_part.strip()

        # Chequeo de Reputación
        if from_domain:
            if dkim_expected_to_sign(from_domain):
                parts.append("• ¡ALERTA! El dominio organizativo '{}' normalmente firma sus correos (Firma Esperada: AUSENTE).".format(_org_domain(_norm_host(from_domain))))
                score += 50 # Penalización muy alta
            else:
                parts.append("• Contexto: El dominio organizativo '{}' no está marcado como firmante esperado.".format(_org_domain(_norm_host(from_domain))))
        else:
            parts.append("• Contexto: No todos los dominios firman sus correos (depende del remitente).")

        return "\n".join(parts), score

    parts.append("Cabeceras DKIM-Signature encontradas: {}".format(len(parsed)))

    for i, f in enumerate(parsed):
        d = f.get('d'); s = f.get('s')
        issues = verify_dkim_structure(f)
        align = check_dkim_domain_alignment(d, from_header)
        dns_ok = dkim_selector_dns_exists(s, d)

        parts.append("\n— Firma #{:d} —".format(i+1))
        parts.append("Dominio (d=): {}".format(d or "N/D"))
        parts.append("Selector (s=): {}".format(s or "N/D"))
        parts.append("Alineación DKIM↔From: {}".format(align))
        parts.append("Selector DNS formato válido: {}".format("Sí" if dns_ok else "No"))
        if issues:
            parts.append("Problemas: " + "; ".join(issues))
            score += 20 * len(issues)
        if align == "MISALIGNED":
            score += 30
        if not dns_ok:
            score += 10

    if len(parsed) > 1:
        parts.append("\nALERTA: múltiples firmas DKIM encontradas (posible reenvío o conflicto).")
        score += 15

    if score == 0:
        parts.append("\nSin anomalías DKIM evidentes (firma válida o formato coherente).")

    return "\n".join(parts), score

# === External DKIM verifier bridge ===
import subprocess, json, tempfile, time

def _find_python_exe_for_tools():
    core_dir = os.path.dirname(os.path.abspath(__file__))       # ...\python_modules\core
    pm_root  = os.path.dirname(core_dir)                         # ...\python_modules
    venv_py  = os.path.join(pm_root, "venv_autopsy", "Scripts", "python.exe")
    if os.path.exists(venv_py):
        return venv_py
    return "python"  # fallback

def _find_external_dkim_script():
    """
    Ruta esperada:
    CORE/tfm_dkim_check.py
    """
    base = os.path.dirname(os.path.abspath(__file__))  # core directory
    candidate = os.path.join(base, "tfm_dkim_check.py")
    if os.path.exists(candidate):
        return os.path.normpath(candidate)
    return None

def run_external_dkim_check(raw_bytes, timeout=15):
    """
    Lanza el checker Python3 externo pasando la RUTA de un archivo temporal
    con los bytes crudos. Evita problemas de stdin en Jython.
    """
    script = _find_external_dkim_script()
    if not script:
        raise Exception("DKIM script not found (core\\tfm_dkim_check.py)")
    pyexe = _find_python_exe_for_tools()

    import tempfile, os, subprocess, time, json
    fd, tmppath = tempfile.mkstemp(prefix="tfm_dkim_", suffix=".eml")
    try:
        try:
            os.write(fd, raw_bytes if raw_bytes else b"")
        finally:
            os.close(fd)

        cmd = [pyexe, script, "--file", tmppath]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        start = time.time()
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if (time.time() - start) > timeout:
                try:
                    proc.kill()
                except:
                    pass
                raise Exception("DKIM script timeout")
            time.sleep(0.2)

        out = proc.stdout.read() or b""
        err = proc.stderr.read() or b""

        if rc not in (0, 2):
            raise Exception("DKIM checker failed (rc={}): {}".format(rc, err.decode('utf-8','ignore')))

        return json.loads(out.decode('utf-8','ignore'))
    finally:
        try:
            os.remove(tmppath)
        except:
            pass

def _diagnose_dkim_variants(variants):
    """
    Recibe la lista de variantes del verificador externo y devuelve
    un diagnóstico humano-leyible del motivo probable del fallo/pase.
    """
    if not variants:
        return "Sin variantes reportadas (verificador externo no devolvió detalles)."

    # Map rápidos para inspección
    by = {v.get("variant"): v for v in variants}
    raw_ok   = bool(by.get("raw", {}).get("verified"))
    lf_ok    = bool(by.get("lf_to_crlf", {}).get("verified"))
    eof_ok   = bool(by.get("crlf_ensure_eof", {}).get("verified"))

    # Errores explícitos
    errors = [v for v in variants if v.get("error")]
    if errors and not (raw_ok or lf_ok or eof_ok):
        # devuelve el primer error visible
        e = errors[0]
        return u"Error de verificación en '{}': {}".format(e.get("variant"), e.get("error"))

    if raw_ok:
        return "RAW=OK → los bytes del .eml son íntegros; al menos una firma verifica."

    # Patrones de fallo típicos por EOL
    if (not raw_ok) and lf_ok and (not eof_ok):
        return "Fallo por EOL: el archivo venía con \\n (LF) sueltos; tras normalizar a CRLF verifica."
    if (not raw_ok) and eof_ok and (not lf_ok):
        return "Fallo por EOL final: faltaba CRLF final tras el cuerpo/boundary; al añadirlo verifica."
    if (not raw_ok) and lf_ok and eof_ok:
        return "Fallo por EOL/terminación: combinación de \\n sueltos y ausencia de CRLF final."

    # Si ninguna variante verifica
    return "Ninguna variante verifica: posible alteración del cuerpo/cabeceras o dependencia del entorno."

def summarize_external_dkim_result(dkim_json):
    """
    Convierte la estructura retornada por run_external_dkim_check() a
    un string compacto y puntuación para Analysis Results, incluyendo
    el detalle de variantes para diagnosticar por qué falla/pasa.
    """
    if not dkim_json:
        return ("No hay resultado DKIM (error interno).", 50)

    if "error" in dkim_json:
        return ("Error DKIM externo: {} - {}".format(dkim_json.get('error'), dkim_json.get('msg', '')), 60)

    parts = []
    score = 0

    sig_count = int(dkim_json.get('dkim_signatures_count', 0))
    parts.append("DKIM signatures: {}".format(sig_count))

    # --- Detalle de firmas (DNS/alineación) ---
    aligned_any = False
    dns_ok_any = False
    for i, s in enumerate(dkim_json.get('signatures', [])):
        d = s.get('d') or '-'
        sel = s.get('s') or '-'
        align = s.get('alignment') or 'UNKNOWN'
        sel_ok = bool(s.get('selector_dns_ok'))
        if align == 'ALIGNED': aligned_any = True
        if sel_ok: dns_ok_any = True

        parts.append("\n- Firma #{}: d={} s={}".format(i+1, d, sel))
        parts.append("  alignment={}".format(align))
        if not sel_ok:
            parts.append("  selector DNS: NO encontrado")
            score += 15
        else:
            txts = s.get('selector_txt') or []
            parts.append("  selector DNS: encontrado ({} records)".format(len(txts) if isinstance(txts, list) else 1))

        if align == "MISALIGNED":
            parts.append("  Nota: dominio DKIM distinto del dominio From: (MISALIGNED)")
            score += 25

    # --- Variantes de verificación (triage) ---
    verify = dkim_json.get('verify', {}) or {}
    variants = verify.get('variants') or []

    # Línea compacta de estado por variante
    if variants:
        compact = []
        for v in variants:
            tag = v.get('variant', '?')
            if v.get('verified'):
                compact.append("{}=OK".format(tag))
            else:
                compact.append("{}={}".format(tag, "ERR" if v.get('error') and not v.get('attempted') else "NO"))
        parts.append("\nVerificación (variantes): " + ", ".join(compact))

        # Diagnóstico legible
        diag = _diagnose_dkim_variants(variants)
        parts.append("Diagnóstico: " + diag)

        # Puntuación según resultado global
        if any(v.get('verified') for v in variants):
            parts.append("Verificación criptográfica: OK (al menos una variante verificó).")
        else:
            parts.append("Verificación criptográfica: FALLIDA (ninguna variante verificó).")
            score += 20
            # Heurística de “copia alterada” solo si hay indicios sólidos
            usually = bool(dkim_json.get('domain_usually_signs'))
            if dns_ok_any and aligned_any and usually:
                parts.append("Indicador fuerte: Selector DNS OK, alineación ALIGNED y el dominio suele firmar → posible alteración de bytes (EOL/cuerpo).")
                score += 30
    else:
        # Compatibilidad con versiones antiguas del checker
        if verify.get('verify_attempted'):
            if verify.get('verified'):
                parts.append("Verificación criptográfica: OK.")
            else:
                parts.append("Verificación criptográfica: FALLIDA. Error: {}".format(verify.get('verify_error')))
                score += 20
                usually = bool(dkim_json.get('domain_usually_signs'))
                if dns_ok_any and aligned_any and usually:
                    parts.append("Indicador fuerte: Selector DNS OK, alineación ALIGNED y el dominio suele firmar → posible alteración de bytes (EOL/cuerpo).")
                    score += 30
        else:
            parts.append("Verificación criptográfica: NO REALIZADA (fallo en el entorno).")
            score += 40

    # Contexto de whitelist (informativo)
    if dkim_json.get('domain_usually_signs'):
        parts.append("\nContexto: Dominio del remitente suele firmar (whitelist).")
    else:
        parts.append("\nContexto: Dominio no marcado como 'suele firmar' en whitelist.")

    if score == 0:
        parts.append("\nResumen: DKIM OK / sin problemas detectados por el verificador externo.")

    return ("\n".join(parts), int(score))

# ==== SPF / DMARC / ARC (parsers & evaluators) ====

_AR_ITEM_RE = re.compile(r'(?P<key>[a-zA-Z0-9_.-]+)\s*=\s*(?P<val>[^;\s]+)')
_AR_AUTHRES_ID_RE = re.compile(r'^\s*([a-z0-9.-]+)\s*;', re.IGNORECASE)

def _parse_authres_line(line):
    """
    Parsea una línea de Authentication-Results en pares clave=valor.
    Devuelve dict con: 'authserv_id', 'kv' (dict llano), y listas por mecanismo.
    """
    out = {'raw': u_(line), 'authserv_id': None, 'kv': {}, 'spf': [], 'dmarc': [], 'dkim': [], 'arc': [], 'other': []}
    try:
        m = _AR_AUTHRES_ID_RE.search(line or '')
        if m:
            out['authserv_id'] = m.group(1).strip().lower()
        # Extraer tokens k=v
        for m in _AR_ITEM_RE.finditer(line or ''):
            k = m.group('key').strip().lower()
            v = m.group('val').strip()
            out['kv'][k] = v

            # Clasificación aproximada por prefijo/mecanismo
            if k.startswith('spf') or k == 'spf':
                out['spf'].append((k, v))
            elif k.startswith('dmarc') or k == 'dmarc':
                out['dmarc'].append((k, v))
            elif k.startswith('dkim') or k == 'dkim':
                out['dkim'].append((k, v))
            elif k.startswith('arc') or k == 'arc':
                out['arc'].append((k, v))
            else:
                out['other'].append((k, v))
    except Exception:
        pass
    return out

def parse_authentication_results(msg):
    """
    Devuelve lista de estructuras parseadas de 'Authentication-Results'.
    Mantiene orden (de arriba a abajo).
    """
    ars = msg.get_all('Authentication-Results') or []
    parsed = []
    for ar in ars:
        # Unir líneas dobladas para robustez
        line = ' '.join(u_(ar).split())
        parsed.append(_parse_authres_line(line))
    return parsed

def _find_header_from_domain(from_header):
    """Extrae dominio de From: para alineamientos DMARC/SPF."""
    if not from_header:
        return None
    fp = u_(from_header).strip().lower()
    if '<' in fp and '>' in fp:
        fp = fp.split('<')[-1].split('>')[0]
    if '@' in fp:
        return fp.split('@')[-1].strip()
    return fp.strip() or None

def extract_received_spf(msg):
    """
    Algunas plataformas añaden 'Received-SPF: ...'
    Acepta:
      - email.message.Message (preferido)
      - lista de líneas 'Received-SPF'
    Devuelve el primer veredicto normalizado, o None si no hay.
    """
    if msg is None:
        return None

    rs = []
    if hasattr(msg, 'get_all'):
        try:
            rs = msg.get_all('Received-SPF') or []
        except Exception:
            rs = []
    elif isinstance(msg, (list, tuple)):
        rs = list(msg)
    else:
        return None

    if not rs:
        return None

    line = ' '.join(u_(rs[0]).split()).lower()
    for tok in ('pass', 'softfail', 'fail', 'neutral', 'none', 'temperror', 'permerror'):
        if tok in line:
            return tok
    return None

def evaluate_spf(authres_list, from_header, msg=None):
    """
    Evalúa SPF según Authentication-Results (o Received-SPF como fallback con el objeto msg).
    Retorna dict: {'result', 'smtp_mailfrom', 'helo', 'ip', 'aligned'}
    """
    from_dom = _find_header_from_domain(from_header)

    def _extract_domain(val):
        if not val:
            return None
        s = u_(val).strip().strip("<>").strip('"').strip("'")
        if '@' in s:
            s = s.split('@')[-1]
        s = s.strip().strip(';:,()[]').lower()
        return s or None

    res = {'result': None, 'smtp_mailfrom': None, 'helo': None, 'ip': None, 'aligned': None}

    for ar in authres_list:
        for (k, v) in ar.get('spf') or []:
            if v in ('pass', 'softfail', 'fail', 'neutral', 'none', 'temperror', 'permerror'):
                res['result'] = v
        kv = ar.get('kv') or {}
        for key in ('smtp.mailfrom', 'mailfrom', 'envelope-from'):
            if kv.get(key):
                res['smtp_mailfrom'] = kv.get(key)
                break
        if kv.get('smtp.helo'):
            res['helo'] = kv.get('smtp.helo')
        if kv.get('smtp.client-ip'):
            res['ip'] = kv.get('smtp.client-ip')
        if res['result']:
            break

    # Fallback a Received-SPF solo si tenemos el objeto Message
    if not res['result'] and msg is not None:
        res['result'] = extract_received_spf(msg)

    # Dominio autenticado por SPF (MailFrom o HELO)
    mf_dom = _extract_domain(res['smtp_mailfrom'])
    helo_dom = _extract_domain(res['helo'])
    spf_dom = mf_dom or helo_dom

    if from_dom and spf_dom:
        from_org = _org_domain(from_dom)
        spf_org = _org_domain(spf_dom)
        res['aligned'] = (
            from_dom.lower() == spf_dom.lower() or
            (from_org and spf_org and from_org == spf_org)
        )
    else:
        res['aligned'] = False

    return res

def evaluate_dmarc(authres_list, from_header):
    """
    Usa Authentication-Results: dmarc=pass/fail; header.from=dom;
    Retorna dict: {'result','header_from','policy','aligned_spf_or_dkim'}
    """
    out = {'result': None, 'header_from': None, 'policy': None, 'aligned_spf_or_dkim': None}
    for ar in authres_list:
        kv = ar.get('kv') or {}
        if kv.get('dmarc'):
            # a veces aparece 'dmarc=pass' como par básico; _parse_authres_line ya lo añadió a kv
            val = kv.get('dmarc')
            if val in ('pass', 'fail'):
                out['result'] = val
        # Campos comunes: header.from=, policy=, p=...
        for key in ('header.from', 'from.header', 'h.from'):
            if kv.get(key):
                out['header_from'] = kv.get(key).lower()
                break
        for key in ('policy.p', 'p', 'disposition', 'policy'):
            if kv.get(key) and not out['policy']:
                out['policy'] = kv.get(key).lower()

        # A veces añade pistas: dmarc=pass (p=none) header.from=dom
        if out['result']:
            break

    # Alineamiento: si dmarc=pass asumimos que o SPF o DKIM alineó
    if out['result'] == 'pass':
        out['aligned_spf_or_dkim'] = True
    elif out['result'] == 'fail':
        out['aligned_spf_or_dkim'] = False

    # Si no hay header_from en AR, derivamos de From:
    if not out['header_from']:
        out['header_from'] = _find_header_from_domain(from_header)

    return out

def parse_arc_chain(msg):
    """
    Recolecta ARC-Seal, ARC-Message-Signature y ARC-Authentication-Results.
    Determina instancias por i=, verifica completitud por índice (1..max(i)),
    y obtiene last_cv como el cv del mayor i presente (no por orden de cabeceras).
    """
    import re
    seals = msg.get_all('ARC-Seal') or []
    ams   = msg.get_all('ARC-Message-Signature') or []
    aar   = msg.get_all('ARC-Authentication-Results') or []

    def _i_list(values):
        out = []
        for raw in values:
            m = re.search(r'\bi\s*=\s*([0-9]+)', u_(raw))
            if m:
                try:
                    out.append(int(m.group(1)))
                except:
                    pass
        return sorted(set(out))

    def _i_to_cv_map(seals_list):
        d = {}
        for raw in seals_list:
            i_m = re.search(r'\bi\s*=\s*([0-9]+)', u_(raw))
            if not i_m:
                continue
            try:
                i = int(i_m.group(1))
            except:
                continue
            cv_m = re.search(r'\bcv\s*=\s*([a-zA-Z]+)', u_(raw))
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
        # completitud: todos los i presentes y cada i aparece en las 3 familias
        if instances == expected:
            complete = all(i in i_seal for i in expected) and \
                       all(i in i_ams  for i in expected) and \
                       all(i in i_aar  for i in expected)

    # last_cv = cv del mayor i presente en ARC-Seal
    cv_map = _i_to_cv_map(seals)
    last_cv = None
    if cv_map:
        last_cv = cv_map.get(max(cv_map.keys())) or None

    return {
        'instances': instances,
        'complete': bool(complete),
        'last_cv': last_cv or 'none',
        'count': len(instances)
    }


def summarize_auth_policies(spf_res, dmarc_res, arc_res, from_header):
    """
    Texto + puntuación para Analysis Results (SPF/DMARC/ARC).
    """
    if not spf_res.get('result') and not dmarc_res.get('result') and not arc_res.get('count'):
        return ("No se encontraron evidencias de autenticación SPF, DMARC ni ARC.", 10) # 10 puntos para enseñar que no hay nada de autenticacion

    parts = []
    score = 0
    from_dom = _find_header_from_domain(from_header)

    parts.append("Identidad From: {}".format(from_dom or "AUSENTE"))
    parts.append("\n--- SPF ---")
    parts.append("Resultado: {}".format(spf_res.get('result') or "desconocido"))
    if spf_res.get('smtp_mailfrom'):
        parts.append("smtp.mailfrom: {}".format(spf_res['smtp_mailfrom']))
    if spf_res.get('ip'):
        parts.append("client-ip: {}".format(spf_res['ip']))
    parts.append("Alineación organizativa SPF↔From: {}".format("ALIGNED" if spf_res.get('aligned') else "MISALIGNED"))

    # Scoring SPF
    r = (spf_res.get('result') or '').lower()
    if r == 'pass':
        pass
    elif r in ('softfail', 'neutral', 'none'):
        score += 10
    elif r in ('fail', 'permerror'):
        score += 40
    elif r == 'temperror':
        score += 5
    if spf_res.get('aligned') is False and r == 'pass':
        # SPF pasa pero no alinea → útil para DMARC
        parts.append("Nota: SPF=pass pero dominio no alineado (no cumple DMARC por SPF).")
        score += 10

    parts.append("\n--- DMARC ---")
    parts.append("Resultado: {}".format(dmarc_res.get('result') or "desconocido"))
    if dmarc_res.get('policy'):
        parts.append("Política: {}".format(dmarc_res['policy']))
    if dmarc_res.get('header_from'):
        parts.append("header.from (AR): {}".format(dmarc_res['header_from']))
    if dmarc_res.get('result') == 'fail':
        score += 50

    parts.append("\n--- ARC ---")
    parts.append("Instancias: {}".format(arc_res.get('count') or 0))
    parts.append("Cadena completa: {}".format("Sí" if arc_res.get('complete') else "No"))
    parts.append("Último ARC-Seal cv: {}".format(arc_res.get('last_cv') or "none"))
    if arc_res.get('count', 0) > 0 and arc_res.get('last_cv') == 'fail':
        score += 30
        parts.append("ALERTA: cv=fail en el último sello ARC (cadena no confiable).")

    return "\n".join(parts), int(score)

# === External Auth Policies (SPF/DMARC/ARC) active checker ===

def _find_external_auth_script():
    base = os.path.dirname(os.path.abspath(__file__))  # core directory
    candidate = os.path.join(base, "tfm_auth_policies_check.py")
    return os.path.normpath(candidate) if os.path.exists(candidate) else None

def run_external_auth_policies(raw_bytes, timeout=15):
    """
    Lanza tfm_auth_policies_check.py (Python3) pasando el EML completo por stdin.
    Devuelve dict JSON o eleva excepción si hay error duro/timeout.
    """
    script = _find_external_auth_script()
    if not script:
        raise Exception("Auth policies script not found (core\tfm_auth_policies_check.py)")
    pyexe = _find_python_exe_for_tools() if "_find_python_exe_for_tools" in globals() else "python"
    cmd = [pyexe, script]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        raise Exception("Failed to start auth checker: {}".format(e))
    try:
        if raw_bytes is None:
            raw_bytes = b""
        try:
            if isinstance(raw_bytes, unicode):  # Jython
                raw_bytes = raw_bytes.encode('utf-8', 'ignore')
        except NameError:
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode('utf-8', 'ignore')
        proc.stdin.write(raw_bytes); proc.stdin.flush(); proc.stdin.close()
    except Exception:
        pass
    start = time.time()
    while True:
        rc = proc.poll()
        if rc is not None:
            break
        if (time.time() - start) > timeout:
            try: proc.kill()
            except Exception: pass
            raise Exception("Auth policies script timeout")
        time.sleep(0.2)
    try:
        out = proc.stdout.read()
    except Exception:
        out = b""
    try:
        err = proc.stderr.read()
    except Exception:
        err = b""
    if rc not in (0, 2):
        raise Exception("Auth policies checker failed (rc={}): {}".format(rc, (err or b"").decode('utf-8','ignore')))
    try:
        return json.loads((out or b"").decode('utf-8','ignore'))
    except Exception as e:
        raise Exception("Invalid JSON from auth policies checker: {}".format(e))
