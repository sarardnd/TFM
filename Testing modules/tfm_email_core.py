# -*- coding: utf-8 -*-
# tfm_email_core.py — utilities
from __future__ import unicode_literals

import re, hashlib, base64
from email.utils import parsedate_tz, mktime_tz
from email.Header import decode_header
import math
import sys, os

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
        parts.append("\n- Orden cronológico inverso en pares de hops: " + ", ".join(pairs))
    if issues['no_date']:
        parts.append("\n- Hops sin fecha parseable: " + ", ".join(str(i) for i in issues['no_date']))

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
        parts.append("\n- IP privada/loopback potencialmente expuesta en hops: " + ", ".join(priv_alert))
    if priv_info:
        parts.append("\n- INFO: IP privada/loopback en hop local/organización: " + ", ".join(priv_info))

    if issues['link_breaks']:
        parts.append("\n- Posibles hops faltantes (continuidad BY[i+1]≠FROM[i]) en: " +
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
        parts.insert(1, "\n- Sin anomalías evidentes en Received.")

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
    Lanza el checker Python3 externo pasando raw_bytes por stdin.
    Sin usar subprocess.TimeoutExpired (no existe en Jython).
    Implementa timeout propio con poll().
    """
    script = _find_external_dkim_script()
    if not script:
        raise Exception("DKIM script not found (core\tfm_dkim_check.py)")
    pyexe = _find_python_exe_for_tools()
    cmd = [pyexe, script]

    # Abrimos el proceso con pipes
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        raise Exception("Failed to start checker: {}".format(e))

    # Escribir stdin de forma segura en Jython
    try:
        if raw_bytes is None:
            raw_bytes = b""
        # En Jython, 'bytes' puede no existir; aseguramos tipo 'str' binaria
        try:
            # si ya son bytes, OK; si es unicode, codifica
            if isinstance(raw_bytes, unicode):  # Jython
                raw_bytes = raw_bytes.encode('utf-8', 'ignore')
        except NameError:
            # En CPython no hay 'unicode'
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode('utf-8', 'ignore')

        proc.stdin.write(raw_bytes)
        proc.stdin.flush()
        proc.stdin.close()
    except Exception:
        # si falla la escritura, intentaremos igualmente leer/terminar
        pass

    # Emular timeout: espera activa con poll()
    start = time.time()
    interval = 0.2
    while True:
        rc = proc.poll()
        if rc is not None:
            break
        if (time.time() - start) > timeout:
            try:
                proc.kill()
            except Exception:
                pass
            raise Exception("DKIM script timeout (poll emulation, no TimeoutExpired in Jython)")
        time.sleep(interval)

    # Proceso terminó: lee stdout/stderr
    try:
        out = proc.stdout.read()
    except Exception:
        out = b""
    try:
        err = proc.stderr.read()
    except Exception:
        err = b""

    # Manejo de códigos de retorno (el script usa rc=2 para deps faltantes)
    if rc not in (0, 2):
        raise Exception("DKIM checker failed (rc={}): {}".format(rc, (err or b"").decode('utf-8', 'ignore')))

    # Parsear JSON
    try:
        return json.loads((out or b"").decode('utf-8', 'ignore'))
    except Exception as e:
        raise Exception("Invalid JSON from DKIM checker: {}".format(e))
    
def summarize_external_dkim_result(dkim_json):
    """
    Convierte la estructura retornada por run_external_dkim_check() a
    un string compacto y puntuación para Analysis Results.
    """
    if not dkim_json:
        return ("No hay resultado DKIM (error interno).", 50)

    if "error" in dkim_json:
        return ("Error DKIM externo: {} - {}".format(dkim_json.get('error'), dkim_json.get('msg', '')), 60)

    parts = []
    score = 0

    # parts.append("From: {}".format(dkim_json.get('from_header') or "AUSENTE"))
    parts.append("DKIM signatures: {}".format(dkim_json.get('dkim_signatures_count', 0)))

    verify = dkim_json.get('verify', {})
    aligned_any = any(s.get('alignment') == 'ALIGNED' for s in dkim_json.get('signatures', []))
    dns_ok_any  = any(s.get('selector_dns_ok') for s in dkim_json.get('signatures', []))
    usually     = bool(dkim_json.get('domain_usually_signs'))
    if verify.get('verify_attempted'):
        if verify.get('verified'):
            parts.append("Verificación criptográfica: OK (al menos una firma verificó).")
        else:
            parts.append("Verificación criptográfica: FALLIDA. Error: {}".format(verify.get('verify_error')))
            score += 60
            if dns_ok_any and aligned_any and usually: # Heurística de manipulación:
                parts.append("Indicador fuerte: Selector DNS OK, alineación ALIGNED y el dominio suele firmar → "
                             "la copia parece ALTERADA (cambios en cabeceras/cuerpo/EOL).")
                score += 30
    else:
        parts.append("Verificación criptográfica: NO REALIZADA (fallo en el entorno).")
        score += 40

    # Por cada firma, resumir estado DNS/alignment
    for i, s in enumerate(dkim_json.get('signatures', []) ):
        parts.append("\n- Firma #{}: d={} s={}".format(i+1, s.get('d') or '-', s.get('s') or '-'))
        parts.append("  alignment={}".format(s.get('alignment') or 'UNKNOWN'))
        if not s.get('selector_dns_ok'):
            parts.append("  selector DNS: NO encontrado")
            score += 15
        else:
            # si txt presente, comprobar mínimo
            txts = s.get('selector_txt') or []
            if not txts:
                parts.append("  selector DNS: encontrado pero sin TXT legible")
                score += 10
            else:
                parts.append("  selector DNS: encontrado ({} records)".format(len(txts)))

        if s.get('alignment') == 'MISALIGNED':
            parts.append("  Nota: dominio DKIM distinto del dominio From: (MISALIGNED)")
            score += 25

    if dkim_json.get('domain_usually_signs'):
        parts.append("\nContexto: Dominio del remitente suele firmar (whitelist).")
    else:
        parts.append("\nContexto: Dominio no marcado como 'suele firmar' en whitelist.")
        # no puntuar fuerte, solo informativo

    if score == 0:
        parts.append("\nResumen: DKIM OK / sin problemas detectados por el verificador externo.")
    return ("\n".join(parts), int(score))
