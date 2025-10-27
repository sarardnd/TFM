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
MODULE_VER  = u"1.1"

ANALYSIS_SET_NAME = u"Message-ID analysis"  # <- SIEMPRE el mismo set name

class TFMMessageIDFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Detecta Message-ID duplicados o con formato/sitios sospechosos."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, ingestOptions): return TFMMessageIDModule()

class TFMMessageIDModule(FileIngestModule):
    def startUp(self, context):
        self._file_index = {}  # file_id -> file_obj
        try:
            core.msgid_clear_store()
        except Exception:
            pass

    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK

        try:
            self._file_index[long(f.getId())] = f

            # Leer bytes
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b'); istream.read(buf)
            content = buf.tostring()
            if not content:
                # Aun así dejamos constancia
                self._hit(f, ANALYSIS_SET_NAME, u"Sin contenido legible.", 0)
                return IngestModule.ProcessResult.OK

            # Parseo
            try:
                msg = email.message_from_string(content)
            except Exception:
                self._hit(f, ANALYSIS_SET_NAME, u"No se pudo parsear el correo.", 0)
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
            for key in ['Message-ID','Message-Id','Message-id','MessageID','Messageid']:
                try:
                    arr = msg.get_all(key)
                    if arr: raw_headers.extend(arr)
                except Exception:
                    v = msg.get(key)
                    if v: raw_headers.append(v)

            # dedup de valores de header
            if raw_headers:
                seen = set(); tmp = []
                for h in raw_headers:
                    uh = core.u_(h)
                    if uh not in seen:
                        seen.add(uh); tmp.append(uh)
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
                        # formato básico
                        mid_strip = core.u_(raw_mid).strip()
                        if not (mid_strip.startswith(u'<') and mid_strip.endswith(u'>')):
                            local_issues.append(u"INVALID FORMAT: MISSING <> en: {}".format(raw_mid))
                            local_score += 5 # Penalización alta por fallo de sintaxis estándar

                        if not core.msgid_has_valid_format(mid):
                            local_issues.append(u"Formato sospechoso: {}".format(mid))
                            local_score += 15

                        # ENTROPÍA SHANNON: usamos H_norm
                        local = core.msgid_get_local_part(mid)
                        H, H_norm = core.msgid_token_entropy(local)
                        if H_norm < 0.8: 
                            local_issues.append(u"Baja entropía local(Hnorm={:.2f}) en: {}".format(H_norm, mid))
                            local_score += 10

                        # Registra para pasada global
                        core.msgid_register(mid, f.getId(), name, from_h, date_epoch, raw_mid)

            # Crear SIEMPRE un artifact local (aunque no haya issues)
            if local_issues:
                desc = u"\n".join(local_issues)
            else:
                desc = u"Sin anomalías locales."
            self._hit(f, ANALYSIS_SET_NAME, desc, int(local_score))

            return IngestModule.ProcessResult.OK

        except Exception:
            # Evita romper la ingest
            self._hit(f, ANALYSIS_SET_NAME, u"Error no controlado durante el análisis.", 0)
            return IngestModule.ProcessResult.ERROR

    def shutDown(self):
        """
        Pasada global: marca duplicados entre ficheros.
        Crea un artifact por cada archivo implicado. Siempre usa el mismo Set Name.
        """
        try:
            dup = core.msgid_find_duplicates()
            if not dup:
                return

            for mid, recs in dup.items():
                summ = core.msgid_summarize(mid, recs)
                text = u"[Duplicado] Message-ID: {mid}\nOcurrencias: {cnt}\nArchivos: {files}\nFroms: {froms}\nEtiquetas: {labels}".format(
                    mid=summ['msgid'],
                    cnt=summ['count'],
                    files=u", ".join(summ['files']),
                    froms=u", ".join(summ['froms']) if summ['froms'] else u"-",
                    labels=u", ".join(summ['labels']) if summ['labels'] else u"-"
                )
                for r in recs:
                    f = self._file_index.get(long(r.get('file_id', -1)))
                    if f:
                        # score global del grupo
                        self._hit(f, ANALYSIS_SET_NAME, text, int(summ['score']))

        except Exception:
            pass

    def _hit(self, f, set_name, desc, value):
        art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        art.addAttributes([
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, core.u_(set_name)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, core.u_(desc)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, core.u_(value)),
        ])
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)
