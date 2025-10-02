# -*- coding: utf-8 -*-
from org.sleuthkit.autopsy.ingest import IngestModule, IngestMessage, IngestServices
from org.sleuthkit.autopsy.ingest import FileIngestModule, IngestModuleFactoryAdapter
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.casemodule import Case  # ← CORRECTO

MODULE_NAME = "Hello Artifact (Jython)"
ATTR_MODULE_NAME = MODULE_NAME

class HelloArtifactFactory(IngestModuleFactoryAdapter):
    moduleName = MODULE_NAME
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return "Crea un artifact de prueba por cada archivo."
    def getModuleVersionNumber(self): return "1.0"
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return HelloArtifactModule()

class HelloArtifactModule(FileIngestModule):
    def startUp(self, context): pass

    def process(self, file):
        if not file.isFile():
            return IngestModule.ProcessResult.OK

        # 1) Artifact estándar para que salga en Analysis Results/Report
        art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)

        # 2) Atributos básicos (nombre del “set”, comentario y ruta)
        attrs = [
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, ATTR_MODULE_NAME, "HelloWorld Hits"),
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,   ATTR_MODULE_NAME, "Demo artifact created by Hello Artifact"),
            # usa getUniquePath() que es estable entre versiones
            BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH,      ATTR_MODULE_NAME, file.getUniquePath())
        ]
        art.addAttributes(attrs)

        # 3) Indexar para que aparezca en búsquedas/resultados
        try:
            Case.getCurrentCase().getServices().getBlackboard().indexArtifact(art)
        except Exception as e:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(IngestMessage.MessageType.ERROR, MODULE_NAME, "Blackboard index error: {0}".format(e))
            )

        # 4) Mensaje visible en Ingest Inbox
        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Artifact created for: {0}".format(file.getName()))
        )

        return IngestModule.ProcessResult.OK
