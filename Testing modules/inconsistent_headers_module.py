# -*- coding: utf-8 -*-
# tfm_email_received_module.py

import jarray, email
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

import sys, os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email Received Inspector"
MODULE_VER  = u"1.0"

class TFMEmailReceivedFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Analiza Received: orden, continuidad y IPs privadas."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return TFMEmailReceivedModule()

class TFMEmailReceivedModule(FileIngestModule):
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
        try:
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b'); istream.read(buf)
            content = buf.tostring()
            if not content: return IngestModule.ProcessResult.OK

            msg = email.message_from_string(content)
            hops   = core.parse_received_chain(msg)
            issues = core.analyze_received_chain(hops)
            summary, score = core.summarize_received_findings(hops, issues)

            self._hit(f, u"Received  headers", summary, score)
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
