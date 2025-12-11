# -*- coding: utf-8 -*-
# xheaders_module.py

import jarray, email, os, sys
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email X-Headers"
MODULE_VER  = u"1.0"

ANALYSIS_SET_NAME = u"X-Headers analysis"  

class TFMXHeadersFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Extract X-headers (X-Mailer, X-Exported-By, etc.)."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, ingestOptions): return TFMXHeadersModule()

class TFMXHeadersModule(FileIngestModule):
    def startUp(self, context):
        pass

    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK

        try:
            # Read file
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()

            if not content:
                self._hit(f, ANALYSIS_SET_NAME, u"No readable content.", 0)
                return IngestModule.ProcessResult.OK

            # Parse email
            try:
                msg = email.message_from_string(content)
            except Exception:
                self._hit(f, ANALYSIS_SET_NAME, u"The email could not be parsed.", 0)
                return IngestModule.ProcessResult.OK

            # Extract X-*
            xdata = core.extract_x_headers(msg)
            text, score = core.summarize_x_headers_findings(xdata)

            self._hit(f, ANALYSIS_SET_NAME, core.u_(text), int(score))
            return IngestModule.ProcessResult.OK

        except Exception:
            self._hit(f, ANALYSIS_SET_NAME, u"Uncontrolled error during analysis.", 0)
            return IngestModule.ProcessResult.ERROR

    def _hit(self, f, set_name, desc, value):
        art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        art.addAttributes([
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, core.u_(set_name)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, core.u_(desc)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, core.u_(value)),
        ])
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)
