from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IBurpExtenderCallbacks

from burp import IHttpRequestResponse
from burp import IHttpService

import urlparse
import zlib

NAME="Pentagrid zlib body decoder"

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
        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
            # Requests are handled as early as possible in processProxyMessage
            if messageIsRequest:
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
        iRequestInfo = self._helpers.analyzeRequest(messageInfo)
        if not iRequestInfo.getUrl():
            print "iRequestInfo.getUrl() returned None, so bailing out of analyzing this request"
            return
        if not self._callbacks.isInScope(iRequestInfo.getUrl()):
            print iRequestInfo.getUrl(), "is not in scope"
            return
        search = "content-type: application/octet-stream"
        if messageIsRequest:
            req = FloydsHelpers.jb2ps(messageInfo.getRequest())
            if search in req.lower():
                self.request_body_decode_zlib(messageInfo)
        else:
            resp = FloydsHelpers.jb2ps(messageInfo.getResponse())
            if search in resp.lower():
                self.response_body_decode_zlib(messageInfo)
    
    def request_body_decode_zlib(self, messageInfo):
        req = FloydsHelpers.jb2ps(messageInfo.getRequest())
        iRequestInfo = self._helpers.analyzeRequest(messageInfo)
        body = req[iRequestInfo.getBodyOffset():]
        plain = None
        try:
            plain = zlib.decompress(body)
        except Exception as e:
            pass
            #print "Couldn't decompress request body for URL ", iRequestInfo.getUrl(), "Error:", e
        if plain:
            newline = "\r\n"
            new_req_headers = req[:iRequestInfo.getBodyOffset()]
            new_req_headers_fixed = FloydsHelpers.fix_content_length(new_req_headers, len(plain), newline)
            new_req = new_req_headers_fixed + plain
            messageInfo.setRequest(FloydsHelpers.ps2jb(new_req))
            #print "Successfully decoded a request"
    
    def response_body_decode_zlib(self, messageInfo):
        resp = FloydsHelpers.jb2ps(messageInfo.getResponse())
        iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        body = resp[iResponseInfo.getBodyOffset():]
        plain = None
        try:
            plain = zlib.decompress(body)
        except Exception as e:
            pass
            #print "Couldn't decompress response body for URL ", self._helpers.analyzeRequest(messageInfo).getUrl(), "Error:", e
        if plain:
            newline = "\r\n"
            new_resp_headers = resp[:iResponseInfo.getBodyOffset()]
            new_resp_headers_fixed = FloydsHelpers.fix_content_length(new_resp_headers, len(plain), newline)
            new_resp = new_resp_headers_fixed + plain
            messageInfo.setResponse(FloydsHelpers.ps2jb(new_resp))
            #print "Successfully decoded a response"

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
