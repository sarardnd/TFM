# -*- coding: utf-8 -*-
# messageID_consistency_module.py

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
MODULE_VER  = u"1.0"

ANALYSIS_SET_NAME = u"Message-ID analysis"


class TFMMessageIDFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Detects duplicates Message-IDs or suspicious formats."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, ingestOptions): return TFMMessageIDModule()


class TFMMessageIDModule(FileIngestModule):
    def startUp(self, context):
        # File index to be referenced in shutDown()
        self._file_index = {}            # file_id (long) -> AbstractFile
        # { file_id: { 'parts': [lista de strings], 'score': int } }
        self._agg = {}
        try:
            core.msgid_clear_store()
        except Exception:
            # If the store does not exist or fails, we continue
            pass

    # ---- utilities ----
    def _merge_hit(self, f, desc, value):
        """Accumulates comments and scores per file."""
        fid = long(f.getId())
        entry = self._agg.setdefault(fid, {'parts': [], 'score': 0})
        if desc:
            udesc = core.u_(desc)
            if udesc not in entry['parts']:  #avoid duplicates in line
                entry['parts'].append(udesc)
        try:
            entry['score'] += int(value or 0)
        except Exception:
            pass  # not blocking because of a rare cast

    def _emit_all(self):
        """It emits exactly one artifact per file with all the findings merged."""
        try:
            bb = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            for fid, f in self._file_index.items():
                
                # Buscamos si este archivo tiene datos en el acumulador (_agg)
                data = self._agg.get(fid)
                
                parts = []
                val = 0
                
                if data:
                    parts = data.get('parts') or []
                    val   = int(data.get('score') or 0)
                
                # Lógica de descripción
                if not parts:
                    # Si no había datos en _agg, o la lista parts estaba vacía
                    desc = u"Without anomalies."
                else:
                    desc = u"\n".join(parts)

                art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                art.addAttributes([
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, core.u_(ANALYSIS_SET_NAME)),
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, desc),
                    BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, core.u_(val)),
                ])
                bb.postArtifact(art, MODULE_NAME)
        except Exception:
            # Prevent a publishing failure from breaking the ingest
            pass

    # ---- pipeline per file ----
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK

        try:
            fid = long(f.getId())
            self._file_index[fid] = f

            # Read bytes
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()
            if not content:
                self._merge_hit(f, u"No readable content.", 0)
                return IngestModule.ProcessResult.OK

            # Parsing
            try:
                msg = email.message_from_string(content)
            except Exception:
                self._merge_hit(f, u"The email could not be parsed.", 0)
                return IngestModule.ProcessResult.OK

            # Relevant headers
            from_h = core.decode_mime_header(msg.get('From')) if msg.get('From') else u""
            date_h = msg.get('Date') or u""
            try:
                date_epoch = core.date_to_epoch(date_h) if date_h else 0
            except Exception:
                date_epoch = 0

            # Message-ID variants
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

            # dedup header's value
            if raw_headers:
                seen = set()
                tmp = []
                for h in raw_headers:
                    uh = core.u_(h)
                    if uh not in seen:
                        seen.add(uh)
                        tmp.append(uh)
                raw_headers = tmp

            # === Local analysis per file ===
            local_issues = []
            local_score  = 0

            if not raw_headers:
                local_issues.append(u"Missing Message-ID header.")
                local_score += 30
            else:
                if len(raw_headers) > 1:
                    local_issues.append(u"Multiple Message-ID headers({})".format(len(raw_headers)))
                    local_score += 20

                # checking entropy
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
                    local_issues.append(u"No valid IDs could be extracted.")
                    local_score += 20
                else:
                    uniq = set([c for (c, _) in all_candidates])
                    if len(uniq) > 1:
                        local_issues.append(u"Many IDs within the same email ({})".format(len(uniq)))
                        local_score += 15

                    for (mid, raw_mid) in all_candidates:
                        # basic format <>
                        mid_strip = core.u_(raw_mid).strip()
                        if not (mid_strip.startswith(u'<') and mid_strip.endswith(u'>')):
                            local_issues.append(u"INVALID FORMAT: MISSING <> en: {}".format(raw_mid))
                            local_score += 5

                        # format RFC and entropy
                        if not core.msgid_has_valid_format(mid):
                            local_issues.append(u"Suspicious format: {}".format(mid))
                            local_score += 15

                        local = core.msgid_get_local_part(mid)
                        H, H_norm = core.msgid_token_entropy(local)
                        if H_norm < 0.8:
                            local_issues.append(u"Low local entropy (Hnorm={:.2f}) at: {}".format(H_norm, mid))
                            local_score += 10

                        # Register for global duplicate detection
                        core.msgid_register(mid, f.getId(), name, from_h, date_epoch, raw_mid)

            # Add local result (we haven't issued it yet)
            if local_issues:
                desc = u"\n".join(local_issues)
            # else:
            #     desc = u""
                self._merge_hit(f, desc, int(local_score))

            return IngestModule.ProcessResult.OK

        except Exception:
            # Avoid breaking the ingest
            try:
                self._merge_hit(f, u"Uncontrolled error during analysis.", 0)
            except Exception:
                pass
            return IngestModule.ProcessResult.ERROR

    def shutDown(self):
        """
        Global pass:
        - Detects duplicates between files and adds the finding to each affected file.
        - Returns exactly one artifact per file with all findings combined."""
        try:
            dup = core.msgid_find_duplicates() or {}
            for mid, recs in dup.items():
                summ = core.msgid_summarize(mid, recs)
                text = u"[Duplicate] Message-ID: {mid}\n" \
                       u"Ocurrencies: {cnt}\n" \
                       u"Files: {files}\n" \
                       u"Froms: {froms}\n" \
                       u"Tags: {labels}".format(
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
            # Do not stop the module from closing due to global aggregation errors
            pass

        # Finally, we publish a single artifact per file.
        self._emit_all()
