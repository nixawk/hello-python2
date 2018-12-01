#!/usr/bin/python
# -*- coding: utf-8 -*-


from searchengine import searchengine
import requests


class censys(searchengine):
    def __init__(self):
        super(censys, self).__init__()

    def censys_dork_search(self, uid, secret, dork, dorktype, page=1):
        """query information form censys with api.
        uid:      censys API ID.
        secret:   censys API secret.
        dork:     censys dork syntax.
        dorktype: [certificates, ipv4, websites].
        page:     The page of the result set to be returned.
                  The number of pages in the result set is available under
                  metadata in any request. By default, the API will return
                  the first page of results. One indexed.

        api doc: https://censys.io/api/v1/docs/search
        """
        censys_api = 'https://www.censys.io/api/v1/search/{}'.format(dorktype)
        query = {'query': dork, 'page': page}
        return requests.post(censys_api, auth=(uid, secret), json=query)

    def parse_results(self, response):
        """parse censys results
        """
        assert response and response.json()
        assert response.json()['status'] == 'ok'

        # {u'status': u'error',
        #  u'error_type': u'malformed_request',
        #  u'error': u'request is missing the required field query'}
        json_response = response.json()
        status = json_response['status']
        results = json_response['results']

        # demo return value: {u'count': 12948,
        #                     u'query': u'apache',
        #                     u'backend_time': 510,
        #                     u'page': 1,
        #                     u'pages': 130}
        metadata = json_response['metadata']
        return (status, results, metadata)


if __name__ == '__main__':
    uid = raw_input('censys API ID: ')
    secret = raw_input('censys secret: ')
    dork = raw_input('censys dork: ')
    dorktype = raw_input('censys dork type, [certificates, ipv4, websites]: ')

    cs = censys()
    response = cs.censys_dork_search(uid, secret, dork, dorktype)
    status, results, metadata = cs.parse_results(response)
    for _ in results:
        print(_)

    # Certificates Search:
    # {u'parsed.fingerprint_sha256': [
    #      u'632aa7af6fed88218fbef0983823032093ef662b96c14574bb43da5bdb046f7e'
    #  ],
    #  u'parsed.subject_dn': [
    #      u'OU=Domain Control Validated, '
    #       'OU=PositiveSSL Multi-Domain, '
    #       'CN=sni191653.cloudflaressl.com'
    #  ],
    #  u'parsed.issuer_dn': [
    #      u'C=GB, ST=Greater Manchester, '
    #       'L=Salford, '
    #       'O=COMODO CA Limited, '
    #       'CN=COMODO ECC Domain Validation Secure Server CA 2'
    #  ]}

    # IPv4 Search
    # {u'ip': u'xxx.xxx.xxx.xxx', u'protocols': [u'443/https']}

    # Websites Search:
    # {u'domain': u'demo.com', u'alexa_rank': [622]}
