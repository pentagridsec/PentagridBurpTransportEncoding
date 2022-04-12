from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks

NAME="Pentagrid early decoder"

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):

    def	registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(NAME)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)

        print("Loaded "+NAME+" successfully!")

    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY and messageIsRequest:
            # Already processed in processProxyMessage
            return
        self.filter_message(toolFlag, messageIsRequest, messageInfo)

    #
    # implement IProxyListener
    #
    def processProxyMessage(self, messageIsRequest, message):
        # Responses are handled as early as possible in processHttpMessage
        if messageIsRequest:
            self.filter_message(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, message.getMessageInfo())


    def filter_message(self, toolFlag, messageIsRequest, messageInfo):
        # TODO: implement decoding
        pass