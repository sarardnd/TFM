# -*- coding: utf-8 -*-
from org.sleuthkit.autopsy.ingest import IngestModule, IngestMessage, IngestServices
from org.sleuthkit.autopsy.ingest import FileIngestModule, IngestModuleFactoryAdapter

class HelloWorldFactory(IngestModuleFactoryAdapter):
    moduleName = "Hello World (Jython)"
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return "Minimal hello-world file ingest module."
    def getModuleVersionNumber(self): return "1.0"
    def isFileIngestModuleFactory(self): return True
    def createFileIngestModule(self, settings): return HelloWorldModule()

class HelloWorldModule(FileIngestModule):
    def startUp(self, context): pass
    def process(self, file):
        if not file.isFile():
            return IngestModule.ProcessResult.OK
        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                "Hello World (Jython)",
                "Processing: {0}".format(file.getName())
            )
        )
        return IngestModule.ProcessResult.OK
