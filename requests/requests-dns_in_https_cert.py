#!/usr/bin/python
# -*- coding: utf-8 -*-

# author: Nixawk

"""
$ python2.7 https.py

{'algorithm': 'sha256WithRSAEncryption',
 'dns': [('DNS', '*.www.yahoo.com'),
         ('DNS', 'www.yahoo.com'),
         ('DNS', 'add.my.yahoo.com'),
         ('DNS', 'au.yahoo.com'),
         ('DNS', 'be.yahoo.com'),
         ('DNS', 'br.yahoo.com'),
         ('DNS', 'ca.my.yahoo.com'),
         ('DNS', 'ca.rogers.yahoo.com'),
         ('DNS', 'ca.yahoo.com'),
         ('DNS', 'ddl.fp.yahoo.com'),
         ('DNS', 'de.yahoo.com'),
         ('DNS', 'en-maktoob.yahoo.com'),
         ('DNS', 'espanol.yahoo.com'),
         ('DNS', 'es.yahoo.com'),
         ('DNS', 'fr-be.yahoo.com'),
         ('DNS', 'fr-ca.rogers.yahoo.com'),
         ('DNS', 'frontier.yahoo.com'),
         ('DNS', 'fr.yahoo.com'),
         ('DNS', 'gr.yahoo.com'),
         ('DNS', 'hk.yahoo.com'),
         ('DNS', 'hsrd.yahoo.com'),
         ('DNS', 'ideanetsetter.yahoo.com'),
         ('DNS', 'id.yahoo.com'),
         ('DNS', 'ie.yahoo.com'),
         ('DNS', 'in.yahoo.com'),
         ('DNS', 'it.yahoo.com'),
         ('DNS', 'maktoob.yahoo.com'),
         ('DNS', 'malaysia.yahoo.com'),
         ('DNS', 'my.yahoo.com'),
         ('DNS', 'nz.yahoo.com'),
         ('DNS', 'ph.yahoo.com'),
         ('DNS', 'qc.yahoo.com'),
         ('DNS', 'ro.yahoo.com'),
         ('DNS', 'se.yahoo.com'),
         ('DNS', 'sg.yahoo.com'),
         ('DNS', 'tw.yahoo.com'),
         ('DNS', 'uk.yahoo.com'),
         ('DNS', 'us.yahoo.com'),
         ('DNS', 'verizon.yahoo.com'),
         ('DNS', 'vn.yahoo.com'),
         ('DNS', 'yahoo.com'),
         ('DNS', 'za.yahoo.com'),
         ('DNS', '*.amp.yimg.com'),
         ('DNS', 'mbp.yimg.com')],
 'issuer': [('C', 'US'),
            ('O', 'DigiCert Inc'),
            ('OU', 'www.digicert.com'),
            ('CN', 'DigiCert SHA2 High Assurance Server CA')],
 'notAfter': '20180319120000Z',
 'notBefore': '20170920000000Z',
 'serialnumber': 16672385189819202335591988329175294739L,
 'subject': [('C', 'US'),
             ('ST', 'CA'),
             ('L', 'Sunnyvale'),
             ('O', 'Yahoo! Inc.'),
             ('CN', '*.www.yahoo.com')]}
"""

from requests.packages.urllib3.contrib import pyopenssl as reqs


class HTTPS(object):

    def __init__(self):
        pass

    def load_remote_certificate(self, host, port):
        return reqs.OpenSSL.crypto.load_certificate(
            reqs.OpenSSL.crypto.FILETYPE_PEM,
            reqs.ssl.get_server_certificate((host, port))
        )

    def parse_remote_certificate(self, host, port):
        cert = self.load_remote_certificate(host, port)
        dns = reqs.get_subj_alt_name(cert)

        # [('C', 'US'), 
        #  ('O', 'DigiCert Inc'), 
        #  ('OU', 'www.digicert.com'), 
        #  ('CN', 'DigiCert SHA2 High Assurance Server CA')]
        issuer = cert.get_issuer().get_components()

        # [('C', 'US'), 
        #  ('ST', 'CA'), 
        #  ('L', 'Sunnyvale'), 
        #  ('O', 'Yahoo! Inc.'), 
        #  ('CN', '*.www.yahoo.com')]
        subject = cert.get_subject().get_components()

        notBefore = cert.get_notBefore() # '20170920000000Z'
        notAfter = cert.get_notAfter() # '20180319120000Z'

        # pubkey = cert.get_pubkey()
        # pubkey.bits()
        # pubkey.type()

        serialnumber = cert.get_serial_number()
        algorithm = cert.get_signature_algorithm()
        # cert.get_version()

        record = {
            "issuer": issuer,
            "subject": subject,
            "notBefore": notBefore,
            "notAfter": notAfter,
            "serialnumber": serialnumber,
            "algorithm": algorithm,
            "dns": dns
        }

        return record


if __name__ == '__main__':
    from pprint import pprint

    https = HTTPS()
    dns = https.parse_remote_certificate("www.yahoo.com", 443)

    pprint(dns)


# https://sourceforge.net/p/pyasn1/mailman/message/35772844/
# https://github.com/pyca/pyopenssl/issues/280
# https://github.com/requests/requests-docs-it/blob/master/requests/packages/urllib3/contrib/pyopenssl.py