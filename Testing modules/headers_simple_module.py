# -*- coding: utf-8 -*-
# tfm_email_headers_module.py

import jarray, email
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

import sys, os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email Basic Headers"
MODULE_VER  = u"1.0"

class TFMEmailHeadersFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"From, To, Subject, Message-ID, Path y timestamps."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return TFMEmailHeadersModule()

class TFMEmailHeadersModule(FileIngestModule):
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
        istream = ReadContentInputStream(f)
        buf = jarray.zeros(int(f.getSize()), 'b'); istream.read(buf)
        content = buf.tostring()
        if not content: return IngestModule.ProcessResult.OK

        msg   = email.message_from_string(content)
        frm   = core.decode_mime_header(msg.get('From',''))
        to    = core.best_recipient(msg)
        subj  = core.decode_mime_header(msg.get('Subject',''))
        msgid = core.decode_mime_header(msg.get('Message-ID',''))
        date_sent = core.decode_mime_header(msg.get('Date',''))
        ts_sent = core.date_to_epoch(date_sent)
        ts_rcvd = core.date_to_epoch(core.u_(msg.get('X-Received-Date',''))) or ts_sent


        art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG)
        attrs = [
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM,    MODULE_NAME, frm),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO,      MODULE_NAME, to),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT,       MODULE_NAME, subj),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID,        MODULE_NAME, msgid),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH,          MODULE_NAME, f.getUniquePath()),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT, MODULE_NAME, ts_sent),
        ]
        # Algunas versiones no tienen RCVD:
        try:
            attrs.append(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD, MODULE_NAME, ts_rcvd))
        except:
            pass
        art.addAttributes(attrs)
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)
        return IngestModule.ProcessResult.OK
