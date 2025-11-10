# -*- coding: utf-8 -*-
# tfm_email_msgid_module.py — Detect duplicates or built Message-ID (Jython / Autopsy 4.22.x)

import jarray, email, os, sys
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email Message-ID"
MODULE_VER  = u"1.2"

# Usamos SIEMPRE el mismo set name para este módulo
ANALYSIS_SET_NAME = u"Message-ID analysis"


class TFMMessageIDFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Detecta Message-ID duplicados o con formato/sitios sospechosos."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, ingestOptions): return TFMMessageIDModule()


class TFMMessageIDModule(FileIngestModule):
    def startUp(self, context):
        # Índice de ficheros para poder referenciar en shutDown()
        self._file_index = {}            # file_id (long) -> AbstractFile
        # Acumulador por fichero para fusionar hallazgos (locales + globales)
        # { file_id: { 'parts': [lista de strings], 'score': int } }
        self._agg = {}
        try:
            core.msgid_clear_store()
        except Exception:
            # En caso de que no exista o falle el store, continuamos
            pass

    # ---- utilidades internas de agregación/emit ----
    def _merge_hit(self, f, desc, value):
        """Acumula texto de comentario y suma score por fichero."""
        fid = long(f.getId())
        entry = self._agg.setdefault(fid, {'parts': [], 'score': 0})
        if desc:
            udesc = core.u_(desc)
            if udesc not in entry['parts']:  # evita duplicados de línea
                entry['parts'].append(udesc)
        try:
            entry['score'] += int(value or 0)
        except Exception:
            pass  # no bloquear por un cast raro

    def _emit_all(self):
        """Emite exactamente un artifact por fichero con todos los hallazgos fusionados."""
        try:
            bb = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            for fid, data in self._agg.items():
                f = self._file_index.get(fid)
                if not f:
                    continue
                parts = data.get('parts') or []
                duplicated = data.get('duplicated', False)
                if duplicated:
                    parts = [p for p in parts if not p.strip().startswith(u"Sin anomalías locales")]
                
                if not parts:
                    desc = u"Sin anomalías."
                else:
                    desc = u"\n".join(parts)
                
                val  = int(data.get('score') or 0)

                art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                art.addAttributes([
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, core.u_(ANALYSIS_SET_NAME)),
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, desc),
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, core.u_(val)),
                ])
                bb.postArtifact(art, MODULE_NAME)
        except Exception:
            # Evitar que un fallo de publicación rompa el ingest
            pass

    # ---- pipeline por fichero ----
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK

        try:
            fid = long(f.getId())
            self._file_index[fid] = f

            # Leer bytes
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()
            if not content:
                self._merge_hit(f, u"Sin contenido legible.", 0)
                return IngestModule.ProcessResult.OK

            # Parseo
            try:
                msg = email.message_from_string(content)
            except Exception:
                self._merge_hit(f, u"No se pudo parsear el correo.", 0)
                return IngestModule.ProcessResult.OK

            # Headers relevantes
            from_h = core.decode_mime_header(msg.get('From')) if msg.get('From') else u""
            date_h = msg.get('Date') or u""
            try:
                date_epoch = core.date_to_epoch(date_h) if date_h else 0
            except Exception:
                date_epoch = 0

            # Todas las variantes de Message-ID
            raw_headers = []
            for key in ['Message-ID', 'Message-Id', 'Message-id', 'MessageID', 'Messageid']:
                try:
                    arr = msg.get_all(key)
                    if arr:
                        raw_headers.extend(arr)
                except Exception:
                    v = msg.get(key)
                    if v:
                        raw_headers.append(v)

            # dedup de valores de header
            if raw_headers:
                seen = set()
                tmp = []
                for h in raw_headers:
                    uh = core.u_(h)
                    if uh not in seen:
                        seen.add(uh)
                        tmp.append(uh)
                raw_headers = tmp

            # === Análisis local por archivo ===
            local_issues = []
            local_score  = 0

            if not raw_headers:
                local_issues.append(u"Falta cabecera Message-ID.")
                local_score += 30
            else:
                if len(raw_headers) > 1:
                    local_issues.append(u"Múltiples cabeceras Message-ID ({})".format(len(raw_headers)))
                    local_score += 20

                # candidatos y chequeos de formato/entropía
                all_candidates = []
                for raw_mid in raw_headers:
                    cands = core.msgid_extract_candidates(raw_mid)
                    if not cands:
                        nm = core.msgid_normalize(raw_mid)
                        if nm:
                            cands = [nm]
                    for c in (cands or []):
                        all_candidates.append((c, raw_mid))

                if not all_candidates:
                    local_issues.append(u"No se pudieron extraer IDs válidos.")
                    local_score += 20
                else:
                    uniq = set([c for (c, _) in all_candidates])
                    if len(uniq) > 1:
                        local_issues.append(u"Varias IDs dentro del mismo email ({})".format(len(uniq)))
                        local_score += 15

                    for (mid, raw_mid) in all_candidates:
                        # formato básico <>
                        mid_strip = core.u_(raw_mid).strip()
                        if not (mid_strip.startswith(u'<') and mid_strip.endswith(u'>')):
                            local_issues.append(u"INVALID FORMAT: MISSING <> en: {}".format(raw_mid))
                            local_score += 5

                        # formato RFC y entropía
                        if not core.msgid_has_valid_format(mid):
                            local_issues.append(u"Formato sospechoso: {}".format(mid))
                            local_score += 15

                        local = core.msgid_get_local_part(mid)
                        H, H_norm = core.msgid_token_entropy(local)
                        if H_norm < 0.8:
                            local_issues.append(u"Baja entropía local(Hnorm={:.2f}) en: {}".format(H_norm, mid))
                            local_score += 10

                        # Registrar para detección de duplicados global
                        core.msgid_register(mid, f.getId(), name, from_h, date_epoch, raw_mid)

            # Agregar resultado local (no emitimos todavía)
            if local_issues:
                desc = u"\n".join(local_issues)
            else:
                desc = u"Sin anomalías locales."
            self._merge_hit(f, desc, int(local_score))

            return IngestModule.ProcessResult.OK

        except Exception:
            # Evita romper la ingest
            try:
                self._merge_hit(f, u"Error no controlado durante el análisis.", 0)
            except Exception:
                pass
            return IngestModule.ProcessResult.ERROR

    def shutDown(self):
        """
        Pasada global:
          - Detecta duplicados entre ficheros y agrega el hallazgo a cada file implicado.
          - Emite exactamente un artifact por fichero con todos los hallazgos combinados.
        """
        try:
            dup = core.msgid_find_duplicates() or {}
            for mid, recs in dup.items():
                summ = core.msgid_summarize(mid, recs)
                text = u"[Duplicado] Message-ID: {mid}\n" \
                       u"Ocurrencias: {cnt}\n" \
                       u"Archivos: {files}\n" \
                       u"Froms: {froms}\n" \
                       u"Etiquetas: {labels}".format(
                           mid=summ['msgid'],
                           cnt=summ['count'],
                           files=u", ".join(summ['files']),
                           froms=u", ".join(summ['froms']) if summ['froms'] else u"-",
                           labels=u", ".join(summ['labels']) if summ['labels'] else u"-"
                       )
                for r in recs:
                    f = self._file_index.get(long(r.get('file_id', -1)))
                    if f:
                        self._merge_hit(f, text, int(summ['score']))
        except Exception:
            # No frenar el cierre del módulo por errores de agregado global
            pass

        # Finalmente, publicamos un único artifact por cada fichero
        self._emit_all()
