#!/usr/bin/python
# -*- coding: utf-8 -*-

# sudo apt-get install phantomjs
# sudo pip install selenium

# selenium (3.4.3)
# phantomjs (2.1.1)

from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver

import logging
import signal
import random
import hashlib


logging.basicConfig(level=logging.INFO)


def screenshot(driver, url, outfile, timeout=30):
    logging.info(outfile)
    # driver = webdriver.PhantomJS()
    driver.get(url)
    driver.implicitly_wait(timeout)
    driver.set_page_load_timeout(timeout)
    driver.save_screenshot(outfile)
    # driver.service.process.send_signal(signal.SIGTERM)
    # driver.quit()


def clean_up(driver):
    driver.service.process.send_signal(signal.SIGTERM)
    driver.quit()


def md5(text):
    return hashlib.new('md5', text).hexdigest()


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("[*] python {} <urlfile>".format(sys.argv[0]))
        sys.exit(0)

    urlfile = sys.argv[1]
    drivers = []
    threads = 10

    pool = ThreadPoolExecutor(threads)

    for _ in range(threads):
        driver = webdriver.PhantomJS()
        drivers.append(driver)

    for url in open(urlfile):
        outfile = "screenshot-%s.png" % md5(url)
        n = random.randint(0, (threads - 1))
        future = pool.submit(screenshot, drivers[n], url, outfile)
        future.done()

    for i in range(threads):
        future = pool.submit(clean_up, drivers[n])
        future.done()

## References
# https://moshimon.wordpress.com/2016/10/02/how-to-render-a-html-page-with-selenium-webdriver-phantomjs-in-python/