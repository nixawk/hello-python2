#!/usr/bin/python

from selenium import webdriver


def browser(url):
    ff = webdriver.Firefox()
    # ff.add_cookie(cookies)
    ff.get(url)
    ff.close()


if __name__ == '__main__':
    url = 'https://search.yahoo.com/'
    browser(url)
