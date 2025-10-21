# -*- coding: utf-8 -*-
# tfm_email_dates_module.py — Date coherence inspector (Jython / Autopsy 4.22.x)

import jarray, email
from org.sleuthkit.autopsy.ingest import IngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute, ReadContentInputStream

import sys, os
import time 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_PATH = os.path.join(BASE_DIR, "..", "core")
if CORE_PATH not in sys.path:
    sys.path.append(CORE_PATH)

import tfm_email_core as core

MODULE_NAME = u"TFM Email Date Coherence"
MODULE_VER= u"1.1" 

class TFMEmailDateCoherenceFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return u"Analiza la coherencia temporal entre Date: y Received: y metadatos de archivo. (v1.1)"
    def getModuleVersionNumber(self): return MODULE_VER
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return TFMEmailDateCoherenceModule()

class TFMEmailDateCoherenceModule(FileIngestModule):
    def process(self, f):
        name = f.getName()
        # Solo procesa archivos .eml y que sean archivos reales (no carpetas, etc.)
        if (not f.isFile()) or (not name or not name.lower().endswith(".eml")):
            return IngestModule.ProcessResult.OK
            
        # Extraer metadatos de archivo EML
        f_date = f.getCrtime() or f.getMtime() or 0
        
        # Nuevo: Hora actual de la ingesta (para comprobar fechas futuras)
        ingest_time = long(time.time()) 
        
        try:
            # 1. Leer contenido del archivo
            istream = ReadContentInputStream(f)
            buf = jarray.zeros(int(f.getSize()), 'b'); istream.read(buf)
            content = buf.tostring()
            if not content: return IngestModule.ProcessResult.OK

            # 2. Parsear mensaje y Received:
            msg = email.message_from_string(content)
            hops = core.parse_received_chain(msg)
            
            # 3. Obtener cabecera Date: (incluye detección de múltiples)
            date_epoch, date_str, is_multiple_date = core.get_date_header_epoch(msg) 

            # 4. Obtener cabeceras alternativas (solo contexto)
            alt_dates = core.get_all_time_headers(msg) 

            # 5. Analizar la coherencia
            issues = core.analyze_date_coherence(date_epoch, date_str, is_multiple_date, hops, f_date, ingest_time) 
            
            # 6. Resumir hallazgos y puntuar
            summary, score = core.summarize_date_coherence_findings(date_str, f_date, issues, alt_dates) 

            # 7. Publicar resultado si hay puntuación > 0
            self._hit(f, u"Date Coherence", summary, score)
                
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
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, MODULE_NAME, core.u_(desc)),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, MODULE_NAME, core.u_(value)),
        ])
        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, MODULE_NAME)