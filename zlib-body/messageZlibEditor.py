from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory
from burp import IBurpExtenderCallbacks

from burp import IHttpRequestResponse
from burp import IHttpService

import urlparse
import zlib

NAME = "Pentagrid zlib editor"

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName(NAME)
        
        # register ourselves as an HTTP listener
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
        return "zlib body decoder"
        
    def isEnabled(self, content, isRequest):
        return True
    
    def getMessage(self):
        return self._txtInput.getText()
    
    def getSelectedData(self):
        return FloydsHelpers.ps2jb("")
        
    def isModified(self):
        return False
    
    def setMessage(self, content, isRequest):
        self._txtInput.setText(FloydsHelpers.ps2jb(""))
        if not content:
            self._txtInput.setText(None)
        else:
            if isRequest:
                req = FloydsHelpers.jb2ps(content)
                iRequestInfo = self._extender._helpers.analyzeRequest(content)
                body = req[iRequestInfo.getBodyOffset():]
                plain = None
                try:
                    plain = zlib.decompress(body)
                except Exception as e:
                    pass
                if plain:
                    self._txtInput.setText(FloydsHelpers.ps2jb(plain))
                    return True
            else:
                resp = FloydsHelpers.jb2ps(content)
                iResponseInfo = self._extender._helpers.analyzeResponse(content)
                body = resp[iResponseInfo.getBodyOffset():]
                plain = None
                try:
                    plain = zlib.decompress(body)
                except Exception as e:
                    pass
                if plain:
                    self._txtInput.setText(FloydsHelpers.ps2jb(plain))
                    return True
        return False


class FloydsHelpers(object):
    
    @staticmethod
    def jb2ps(arr):
        """
        Turns Java byte arrays into Python str
        :param arr: [65, 65, 65]
        :return: 'AAA'
        """
        return ''.join(map(lambda x: chr(x % 256), arr))

    @staticmethod
    def ps2jb(arr):
        """
        Turns Python str into Java byte arrays
        :param arr: 'AAA'
        :return: [65, 65, 65]
        """
        return [ord(x) if ord(x) < 128 else ord(x) - 256 for x in arr]

    @staticmethod
    def u2s(uni):
        """
        Turns unicode into str/bytes. Burp might pass invalid Unicode (e.g. Intruder Bit Flipper).
        This seems to be the only way to say "give me the raw bytes"
        :param uni: u'https://example.org/invalid_unicode/\xc1'
        :return: 'https://example.org/invalid_unicode/\xc1'
        """
        if isinstance(uni, unicode):
            return uni.encode("iso-8859-1", "ignore")
        else:
            return uni
    
    @staticmethod
    def fix_content_length(headers, length, newline):
        h = list(headers.split(newline))
        for index, x in enumerate(h):
            if "content-length:" == x[:len("content-length:")].lower():
                h[index] = x[:len("content-length:")] + " " + str(length)
                return newline.join(h)
        else:
            print "WARNING: Couldn't find Content-Length header in request, simply adding this header"
            h.insert(1, "Content-Length: " + str(length))
            return newline.join(h)
