# -*- coding: utf-8 -*-
# dkim_check_module.py
from __future__ import unicode_literals

import jarray, email
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream
from java.io import ByteArrayOutputStream 

import sys, os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email DKIM Inspector"
MODULE_VER  = u"1.0"  

class TFMEmailDKIMFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Analize and verify DKIM signatures in emails."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return TFMEmailDKIMModule()

class TFMEmailDKIMModule(FileIngestModule):
    def _read_raw_bytes(self, f):
        istream = ReadContentInputStream(f)
        baos = ByteArrayOutputStream()
        buf = jarray.zeros(8192, 'b')
        while True:
            n = istream.read(buf)
            if n < 0:
                break
            baos.write(buf, 0, n)
        return baos.toByteArray() 

    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
        try:
            # --- RAW BYTES ---
            raw_bytes = self._read_raw_bytes(f)

            # Parse SOLO para UI/textos (NO usar para verificar DKIM)
            try:
                msg = email.message_from_string(raw_bytes.tostring())
            except:
                msg = None
            from_header = msg.get('From') if msg else u""

            try:
                # Pasa los bytes crudos al verificador externo (core usa archivo temp)
                dkim_json = core.run_external_dkim_check(raw_bytes, timeout=15)
                summary, score = core.summarize_external_dkim_result(dkim_json)

            except Exception as e:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(IngestMessage.MessageType.ERROR, MODULE_NAME, core.u_("DKIM external error: {}".format(e)))
                )
                # Fallback: análisis estructural sin cripto
                if msg is None:
                    msg = email.message_from_string(raw_bytes.tostring())
                parsed_dkim = core.parse_dkim_headers(msg)
                summary, score = core.summarize_dkim_findings(parsed_dkim, from_header or u"")

            self._hit(f, u"DKIM analysis", summary, score)
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
