from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory

NAME = "Pentagrid message editor"

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName(NAME)
        
        # register ourselves as an Message Editor Tab Factory
        callbacks.registerMessageEditorTabFactory(self)
        
        print("Loaded "+NAME+" successfully!")
        
    #
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        return DisplayValues(self, controller, editable)
        

class DisplayValues(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(False)
        self._extender = extender

    def getUiComponent(self):
        return self._txtInput.getComponent()
    
    def getTabCaption(self):
        return NAME
        
    def isEnabled(self, content, isRequest):
        return True
    
    def getMessage(self):
        return self._txtInput.getText()
    
    def getSelectedData(self):
        return FloydsHelpers.ps2jb("")
        
    def isModified(self):
        return False
    
    def setMessage(self, content, isRequest):
        # TODO: set self._txtInput.setText() to the decoded version
        return False


class FloydsHelpers(object):

    @staticmethod
    def ps2jb(arr):
        """
        Turns Python str into Java byte arrays
        :param arr: 'AAA'
        :return: [65, 65, 65]
        """
        return [ord(x) if ord(x) < 128 else ord(x) - 256 for x in arr]
    