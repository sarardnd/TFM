# -*- coding: utf-8 -*-
# hash_files_module.py

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

MODULE_NAME = u"TFM Email Hashes"
MODULE_VER  = u"1.0"

class TFMEmailHashesFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"email and attachments SHA-256."
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return TFMEmailHashesModule()

class TFMEmailHashesModule(FileIngestModule):
    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
        try:
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()
            if not content: return IngestModule.ProcessResult.OK

            # Hash email
            h_mail = core.sha256_bytes(content)
            self._hit(f, u"Email Hashes", u"Email SHA-256", h_mail)

            # Hash attachments
            msg = email.message_from_string(content)
            cnt = 0
            for part in msg.walk():
                disp  = (part.get('Content-Disposition','') or '').lower()
                fname = part.get_filename()
                if part.get_content_maintype() == 'multipart': continue
                if (not fname) and ('attachment' not in disp):  continue
                payload = part.get_payload(decode=True) or b""
                cnt += 1
                h_att = core.sha256_bytes(payload)
                label = u"Attachment SHA-256: %s" % (core.u_(fname) if fname else u"no_name_%d" % cnt)
                self._hit(f, u"Attachment Hashes", label, h_att)

            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                                            u"%s | Attachments=%d" % (core.u_(name), cnt))
            )
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
