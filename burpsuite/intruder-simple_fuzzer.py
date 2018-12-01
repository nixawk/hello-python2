from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        """This method is invoked when the extension is loaded.
        param: callbacks - An IBurpExtenderCallbacks object.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Simple Fuzzer")
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

    def getGeneratorName(self):
        """This method is used by Burp to obtain the name of the payload generator.
        This will be displayed as an option within the intruder UI when
        the user selects to use extension-generated payloads."""
        return "Fuzzer Payload Generator"

    def createNewInstance(self, attack):
        """The method is used by Brupsuite when the user starts an intruder
        attack that uses this payload generator."""
        return Fuzzer(self, attack)


class Fuzzer(IIntruderPayloadGenerator):
    """This interface is used for custom Intruder payload generators."""

    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack

        # If prefer, please add vuln payload here.
        self.payloads = ['sqli', 'xss', 'vuln']
        self.max_payloads = len(self.payloads)
        self.num_iterators = 0

        return

    def custom_payload_function(self, payload):
        """Custom how to handle payload"""
        payload = payload + self.payloads[self.num_iterators]
        return payload

    def getNextPayload(self, payload):
        """This method is used by Burp to obtain the value of the next payload
        """
        payload = "".join(chr(x) for x in payload)
        payload = self.custom_payload_function(payload)

        self.num_iterators += 1
        return payload

    def hasMorePayloads(self):
        """This method is used by Burp to determine whether the payload
        generator is able to provide any further payloads.
        """
        if self.num_iterators == self.max_payloads:
            return False
        else:
            return True

    def reset(self):
        """This method is used by Burp to reset the state of the payload
        generator so that the next call to getNextPayload() returns the first
        payload again."""

        self.num_iterators = 0
        return

# Author: Nixawk
# Platform: Mac OS X
# Platform: Windows 7 - Exception in thread "main" java.lang.NoClassDefFoundError:

# https://portswigger.net/burp/help/extender.html
# https://portswigger.net/burp/extender/api/index.html
