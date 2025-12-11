
# -*- coding: utf-8 -*-
# authpolicies_module.py — SPF/DMARC/ARC

import jarray, email, os, sys, re
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email Auth (SPF/DMARC/ARC)"
MODULE_VER  = u"1.0"

ANALYSIS_SET_NAME = u"Auth policies analysis"

class TFMAuthUnifiedFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"SPF/DMARC/ARC"
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, ingestOptions): return TFMAuthUnifiedModule()

class TFMAuthUnifiedModule(FileIngestModule):
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
        try:
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()
            if not content:
                self._hit(f, ANALYSIS_SET_NAME, u"No readable content.", 0)
                return IngestModule.ProcessResult.OK

            msg = email.message_from_string(content)
            from_header = msg.get('From') or u""

            # 1) Try external checker first
            try:
                raw_bytes = content.encode('utf-8','ignore') if isinstance(content, unicode) else str(content).encode('utf-8','ignore')
                ext_json = core.run_external_auth_policies(raw_bytes, timeout=15)

                # Baseline result (from local AR for presentation consistency)
                ar_list = core.parse_authentication_results(msg)
                spf_res = core.evaluate_spf(ar_list, from_header, msg)
                dmarc_res = core.evaluate_dmarc(ar_list, from_header)
                arc_res = core.parse_arc_chain(msg)
                text_base, score = core.summarize_auth_policies(spf_res, dmarc_res, arc_res, from_header)

                # Extras of external checker
                extras = []

                # DMARC published
                dmarc = ext_json.get('dmarc_dns', {})
                if isinstance(dmarc, dict) and dmarc.get('found'):
                    src = dmarc.get('source','')
                    parsed = dmarc.get('parsed') or {}
                    extras.append(u"\n— DNS (published DMARC{}) — p={p} sp={sp} adkim={adkim} aspf={aspf}".format(
                                " inherited from {}".format(src) if "(inherited)" in src else "",
                                p=parsed.get('p','n/d'), sp=parsed.get('sp','n/d'),
                                adkim=parsed.get('adkim','n/d'), aspf=parsed.get('aspf','n/d')))
                elif isinstance(dmarc, dict) and dmarc.get('error'):
                    extras.append(u"\n— DNS (DMARC): error resolution — {}".format(dmarc.get('error')))

                # SPF published
                spf_dns = ext_json.get('spf_dns', {})
                if isinstance(spf_dns, dict):
                    for dom, rec in spf_dns.items():
                        if isinstance(rec, list) and rec:
                            extras.append(u"\n— DNS (published SPF) {} — {}".format(dom, " | ".join(rec)))
                        elif isinstance(rec, dict) and rec.get('error'):
                            extras.append(u"\n— DNS (SPF {}): error resolution — {}".format(dom, rec.get('error')))
                # ARC cripto
                # --- ARC cripto + comparing cv ---
                arc_crypto = (ext_json.get('arc_crypto') or {}) if isinstance(ext_json, dict) else {}
                if isinstance(arc_crypto, dict) and arc_crypto:
                    supported = arc_crypto.get('supported')
                    ok       = arc_crypto.get('ok')
                    details  = core.u_(arc_crypto.get('details') or u"")
                    status   = u"PASS" if ok else u"FAIL" if ok is not None else u"n/d"
                    if supported is False:
                        extras.append(u"\n— ARC (crypto): not supported ({})".format(arc_crypto.get('result') or u"n/d"))
                    else:
                        extras.append(u"\n— ARC (crypto): {}{}".format(status, u" ({})".format(details) if details else u""))

                    # cv calculated by crypto (if it appears in 'details')
                    m = re.search(r"cv\s*=\s*(?:b'?|)(pass|fail|none)", details, re.IGNORECASE)
                    cv_norm = m.group(1).lower() if m else None
                    if cv_norm:
                        extras.append(u" — cv={}".format(cv_norm))

                    # cv of the ARC-Seal header of the highest i (comes from external.arc)
                    arc_state = (ext_json.get('arc') or {}) if isinstance(ext_json, dict) else {}
                    last_cv = (arc_state.get('last_cv') or u"").lower()
                    try:
                        count = int(arc_state.get('count') or 0)
                    except Exception:
                        count = 0

                    # solo alertar si hay >1 saltos
                    if count > 1 and cv_norm and last_cv and cv_norm != last_cv:
                        extras.append(u"\nALERT: cv (crypto)={} differs from cv (header)={}".format(cv_norm, last_cv))
                        score += 15

                    # penalize if crypto verification fails
                    if supported and (ok is False):
                        score += 20

                # SPF recalc + compare
                spf_recalc = ext_json.get('spf_recalc')
                if isinstance(spf_recalc, dict) and spf_recalc.get('supported'):
                    if spf_recalc.get('skipped'):
                        extras.append(u"\n— SPF (recalc): omitted ({})".format(spf_recalc.get('reason','')))
                    elif spf_recalc.get('error'):
                        extras.append(u"\n— SPF (recalc): error — {}".format(spf_recalc['error']))
                    else:
                        ar_res = (spf_res.get('result') or u"unkown").lower()
                        rc_res = (spf_recalc.get('result') or u"unkown").lower()
                        extras.append(u"\n— SPF (AR vs recalc): {} vs {}".format(ar_res, rc_res))

                        used = spf_recalc.get('used') or {}
                        extras.append(u"\n— SPF (recalc, contexto): ip={} helo={} mailfrom={}".format(
                            used.get('ip','n/d'), used.get('helo','n/d'), used.get('mailfrom','n/d')
                        ))
                        extras.append(u"\n— SPF (recalc) alingment with From: {}".format(
                            u"ALIGNED" if spf_recalc.get('aligned_with_from') else u"MISALIGNED"
                        ))

                full_text = text_base + (u"".join(extras) if extras else u"")
                self._hit(f, ANALYSIS_SET_NAME, core.u_(full_text), int(score))
                return IngestModule.ProcessResult.OK
                 
            except Exception as e:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, core.u_(u"External authentication unavailable, using local fallback: {}".format(e)))
                )

            # 2) Fallback local (sin DNS)
            ar_list = core.parse_authentication_results(msg)
            spf_res   = core.evaluate_spf(ar_list, from_header, msg)
            dmarc_res = core.evaluate_dmarc(ar_list, from_header)
            arc_res   = core.parse_arc_chain(msg)
            text, score = core.summarize_auth_policies(spf_res, dmarc_res, arc_res, from_header)
            self._hit(f, ANALYSIS_SET_NAME, core.u_(text), int(score))
            return IngestModule.ProcessResult.OK

        except Exception as e:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(IngestMessage.MessageType.ERROR, MODULE_NAME, core.u_(e))
            )
            return IngestModule.ProcessResult.ERROR

    def _hit(self, f, set_name, desc, value):
        art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        art.addAttributes([
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, core.u_(set_name)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, core.u_(desc)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, core.u_(value)),
        ])
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)
