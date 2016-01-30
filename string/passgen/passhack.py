# https://digi.ninja/projects/pipal.php
# http://thesprawl.org/projects/pack/

# 1. how to get base words
#    File Import
#    HTTP Response
#
#    word
#    word -> w0rd
#
#    word length
#    word rules
#

#
#
#
#    -------------
#    | base word |
#    -------------
#
#
#                       ------------------------------
#    | Feature |  ----> | similar words (dictoinary) |
#                       ------------------------------
#
#                       ------------------------------
#    | Featuer |  ----> | leets words                |
#                       ------------------------------

#                       ------------------------------
#    | Feature |  ----> | repeat                     |
#                       ------------------------------

#                       ------------------------------
#    | Feature |  ----> | reverse sort               |
#                       ------------------------------

#                       ------------------------------
#    | Feature |  ----> | wordlist rules (custom)    |
#                       ------------------------------
#                       ------------------------------
#                 ----> | Length rules (custom)      |
#                       ------------------------------
#
#                       ------------------------------
#    | Feature |  ----> | Random                     |
#                       ------------------------------
#
#
#
#                       ------------
#    | Feature |  ----> | Analysis |
#                       ------------
#
#                       ------------
#    | Feature |  ----> | Filter   |
#                       ------------
#
#

from leet import leet_char, leet_num
from rules import rules
from random_generator import random_generator


class PassHack(object):
    def __init__(self):
        self.pwds = []

    def baseword_http(self, url):
        return url

    def baseword_file(self, _file):
        pass

    def feature_leet_char(self, word):
        return leet_char(word)

    def feature_leet_num(self, word):
        return leet_num(word)

    def feature_random_generator(self, word, minLen, maxLen):
        return list(set([w for w in random_generator(word, minLen, maxLen)]))

    def feature_repeat(self, word, num):
        return [word * num]

    def feature_reverse(self, word):
        _word = [i for i in word]
        _word.reverse()
        return ["".join(_word)]

    def feature_rules(self, word):
        return rules(word)

    def feature_similar_dict(self, words):
        return words

    def feature_filter(self, words):
        pass

    def feature_analysis(self, words):
        pass


if __name__ == "__main__":
    ph = PassHack()
    words = 'Hello'
    r = []
    r += ph.feature_leet_char(words)
    r += ph.feature_leet_num(words)
    r += ph.feature_reverse(words)
    r += ph.feature_rules(words)
    r += ph.feature_random_generator(words, 1, len(words))
    r += ph.feature_repeat(words, 2)

    print(r)
