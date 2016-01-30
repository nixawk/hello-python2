
import itertools


def generator(word, length):
    chars = [i for i in word]

    for char in itertools.product(chars, repeat=length):
        yield "".join(char)


def random_generator(word, minLen, maxLen):
    chars = [i for i in word]
    wlen = len(word)

    _min = min(minLen, maxLen, wlen)
    _max = max(minLen, maxLen, wlen)

    for length in range(_min, _max+1):
        for char in itertools.product(chars, repeat=length):
            yield "".join(char)
