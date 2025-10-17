# -*- coding: utf-8 -*-
# EmailHeadersHashTFM (Headers + Hashes + Inbox)

import jarray, re, hashlib, email
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

MODULE_NAME    = u"EmailHeadersHashTFM"
MODULE_VERSION = u"2.0"

# ---------- helpers ----------
from email.Header import decode_header
def u_(x):
    try:
        if isinstance(x, unicode): return x
        return unicode(x, "utf-8", "ignore")
    except:
        return unicode(str(x), "utf-8", "ignore")

def decode_mime_header(val):
    if not val: return u""
    parts = []
    for b, c in decode_header(val):
        if c:
            try: parts.append(unicode(b, c, "ignore"))
            except: parts.append(unicode(b, "utf-8", "ignore"))
        else:
            if isinstance(b, unicode): parts.append(b)
            else:
                try: parts.append(unicode(b, "utf-8"))
                except: parts.append(unicode(b, "latin-1", "ignore"))
    return u"".join(parts)

def date_to_epoch(date_str):
    try:
        import email.Utils as EU
        tup = EU.parsedate_tz(u_(date_str))
        if tup: return long(EU.mktime_tz(tup))
    except:
        pass
    return long(0)

def received_to_epoch(msg):
    """Return the first 'Received:' epoch with the date after ';'."""
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

def sha256_bytes(b): return hashlib.sha256(b).hexdigest()

# ---------- factory ----------
class EmailHeadersHashFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Headers to E-Mail Messages, hashes to Analysis Results, inbox summary"
    def getModuleVersionNumber(self): return MODULE_VERSION
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return EmailHeadersHashModule()

# ---------- module ----------
class EmailHeadersHashModule(FileIngestModule):
    def startUp(self, context): pass

    def process(self, f):
        name = f.getName()
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK

        try:
            # --- read bytes from .eml ---
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b')
            istream.read(buf)
            content = buf.tostring()
            if not content:
                return IngestModule.ProcessResult.OK

            # --- email hash (Analysis Results in Email Hashes) ---
            mail_hash = sha256_bytes(content)
            self._hit_hash(f, u"Email Hashes", u"Email SHA-256", mail_hash)

            # --- email parsing ---
            msg   = email.message_from_string(content)
            frm   = decode_mime_header(msg.get('From',''))
            to    = decode_mime_header(msg.get('To',''))
            subj  = decode_mime_header(msg.get('Subject',''))
            msgid = decode_mime_header(msg.get('Message-ID',''))
            date_sent = decode_mime_header(msg.get('Date',''))
            ts_sent = date_to_epoch(date_sent)
            ts_rcvd = received_to_epoch(msg)

            # --- standard artifact: columns in E-Mail Messages ---
            art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG)
            attrs = [
                BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM,    MODULE_NAME, frm),
                BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO,      MODULE_NAME, to),
                BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT,       MODULE_NAME, subj),
                BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID,        MODULE_NAME, msgid),
                BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH,          MODULE_NAME, f.getUniquePath()),
            ]
            # Sent (para contexto) + Received en columna si está disponible
            attrs.append(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT, MODULE_NAME, ts_sent))
            try:
                attrs.append(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD, MODULE_NAME, ts_rcvd if ts_rcvd > 0 else ts_sent))
            except:
                # For versionns with no RCVD, leave a comment
                if ts_rcvd > 0:
                    attrs.append(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, MODULE_NAME, u"Date Received (epoch): %d" % ts_rcvd))
            art.addAttributes(attrs)
            Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)

            # --- Attachments hashes (Analysis Results in Attachment Hashes) ---
            attach_cnt = 0
            for part in msg.walk():
                disp  = (part.get('Content-Disposition','') or '').lower()
                fname = part.get_filename()
                if part.get_content_maintype() == 'multipart':
                    continue
                if (not fname) and ('attachment' not in disp):
                    continue
                payload = part.get_payload(decode=True) or b""
                attach_cnt += 1
                ahash = sha256_bytes(payload)
                label = u"Attachment SHA-256: %s" % (u_(fname) if fname else u"no_name_%d" % attach_cnt)
                self._hit_hash(f, u"Attachment Hashes", label, ahash)

            # --- inbox summary ---
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.INFO, MODULE_NAME,
                    u"Email: %s | Attachments=%d" % (u_(name), attach_cnt)
                )
            )

            return IngestModule.ProcessResult.OK

        except Exception as e:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(IngestMessage.MessageType.ERROR, MODULE_NAME, u_(e))
            )
            return IngestModule.ProcessResult.ERROR

    def _hit_hash(self, f, set_name, desc, value):
        art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        art.addAttributes([
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, MODULE_NAME, u_(set_name)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,  MODULE_NAME, u_(desc)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE,    MODULE_NAME, u_(value)),
        ])
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)
