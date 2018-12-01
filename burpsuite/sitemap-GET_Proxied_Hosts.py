from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        callbacks.setExtensionName("Proxied Hosts Collector")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Get Proxied Hosts", actionPerformed=self.custom_menu))

        return menu_list

    def custom_menu(self, event):
        hosts = set([_.host for _ in self._callbacks.getProxyHistory()])
        for _ in hosts: self._callbacks.printOutput(_)
        return

# Platform:           Mac OS X / Windows 7
# Brupsuite Version:  1.7.11
# https://portswigger.net/burp/help/extender.html
# https://portswigger.net/burp/extender/api/index.html
# https://www.foote.pub/2015/04/08/burp-extender-python.html
