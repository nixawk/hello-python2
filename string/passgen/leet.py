
# https://simple.wikipedia.org/wiki/Leet

# Leet (sometimes written as "1337" or "l33t"), also known as eleet
# or leetspeak, is another alphabet for the English language that is
# used mostly on the internet. It uses various combinations of ASCII
# characters to replace Latinate letters. For example, leet spellings
# of the word leet include 1337 and l33t; eleet may be spelled 31337
# or 3l33t. It is used a lot on the internet in forums,
# chat rooms and online games.


def leet(word, leets={}):
    return [word.replace(char, nchar)
            for char in word
            if char.upper() in leets
            for nchar in leets[char.upper()]]


def leet_char(word):
    leets = {
        'A': ['4', '/-\\', '/_\\', '@', '/\\'],
        'B': ['8', '|3', '13', '|}', '|:', '|8', '18', '6', '|B'],
        'C': ['<', '{', '[', '('],
        'D': ['|)', '|}', '|]'],
        'E': ['3'],
        'F': ['|=', 'ph', '|#', '|"'],
        'G': ['[', '-', '[+', '6'],
        'H': ['4', '|-|', '[-]', '{-}', '|=|', '[=]', '{=}'],
        'I': ['1', '|'],
        'J': ['_|', '_/', '_7', '_)'],
        'K': ['|<', '1<'],
        'L': ['|_', '|', '1'],
        'O': ['0', '()', '[]', '{}'],
        'P': ['|O', '|>', '|*', '|D'],
        'Q': ['O_', '9', '(,),'],
        'R': ['|2', '12', '.-', '|^'],
        'S': ['5', '$'],
        'T': ['7', '+', '7`', "'|'"],
        'U': ['|_|', '\_\\', '/_/', '\_/', '(_)'],
        'V': ['\/'],
        'W': ['\/\/', '(/\)', '\^/', '|/\|', '\X/', '\\\\', '//'],
        'X': ['%', '*', '><', '}{', ')('],
        'Y': ['`/']

    }

    return leet(word, leets)


def leet_num(word):
    leets = {
        '1': ['L', 'l'],
        '2': ['R', 'Z'],
        '3': ['E'],
        '4': ['A', 'H'],
        '5': ['S'],
        '6': ['b', 'G'],
        '7': ['T', 'L'],
        '8': ['B'],
        '9': ['g', 'q'],
        '0': ['O']
    }

    return leet(word, leets)
