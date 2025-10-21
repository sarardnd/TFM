# -*- coding: utf-8 -*-
# tfm_email_core.py — utilities
from __future__ import unicode_literals

import re, hashlib
from email.utils import parsedate_tz, mktime_tz
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