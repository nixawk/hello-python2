from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import threading


class BurpExtender(IBurpExtender, IContextMenuFactory):
    """This is a burp extension that will get the responses of empty requests
       in Burp's Sitemap. When spidering a host, it happens that some requests
       are queued but never get actually requested by the spider. These usually
       show up as grey nodes in the sitemap. This extension takes care of those
       by requesting each of them and adding its response to the sitemap.
       No more gray nodes in Burp's sitemap!
    """
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("SiteMap Bulk Requests")
        self.callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, IContextMenuInvocation):
        self.selectedRequest = IContextMenuInvocation.getSelectedMessages()
        menulist = ArrayList()
        menulist.add(JMenuItem("Bulk Requests", actionPerformed=self.send_requests))
        return menulist

    def makeRequest(self, r):
        self.callbacks.addToSiteMap(self.callbacks.makeHttpRequest(r.getHttpService(), r.getRequest()))

    def send_requests(self, event):
        # http://target.net:80/code/newarticle.html
        # http://target.net/code/newarticle.html

        # https://target.net:443/code/newarticle.html
        # https://target.net/code/newarticle.html

        burp_IHttpRequestResponse = self.selectedRequest[0]
        url = burp_IHttpRequestResponse.url
        if url.port in (80, 443):
            url = '{}://{}{}'.format(url.protocol, url.host, url.path)
        else:
            url = url.toString()

        for sitemap_item in self.callbacks.getSiteMap(url):
            t = threading.Thread(target=self.makeRequest, args=[sitemap_item])
            t.daemon = True
            t.start()

# Platform:           Mac OS X / Windows 7
# Brupsuite Version:  1.7.11
# Author: Nixawk
# Fork from Site_Map_Fetcher, But it's different.
# https://portswigger.net/burp/help/extender.html
# https://portswigger.net/burp/extender/api/index.html
# https://www.foote.pub/2015/04/08/burp-extender-python.html
