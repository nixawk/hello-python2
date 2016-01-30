
def years():
    return [year for year in range(1975, 2021)]


def months():
    return ["%02d" % month for month in range(1, 13)]


def days():
    return ["%02d" % month for month in range(1, 32)]


def pass_add_suffix(word, rules):
    _r = ["%s%s" % (word, r) for r in rules]
    _r += ["%s@%s" % (word, r) for r in rules]
    _r += ["%s#%s" % (word, r) for r in rules]
    _r += ["%s_%s" % (word, r) for r in rules]

    return _r


def pass_add_prefix(word, rules):
    _r = ["%s%s" % (r, word) for r in rules]
    _r += ["%s@%s" % (r, word) for r in rules]
    _r += ["%s#%s" % (r, word) for r in rules]
    _r += ["%s_%s" % (r, word) for r in rules]

    return _r


def rules(word):
    rules = [
        '!', '!!', '!!!',
        '!@#', '!@#$', '!QAZ',
        '#', '##', '###',
        '$', '$$', '$$$',
        '%', '%%', '%%%',
        '&', '&&', '&&&',
        '@', '@@', '@@@', '@123', '@abc',
        '*', '**', '***',
        '.', '..', '...',
        ':',
        '000', '000.', '01', '001', '002', '007',
        '1', '1.', '110', '101',
        '110.', '11', '111', '111.', '1122', '1122.',
        '119', '119.', '12', '12.', '222', '123',
        '123123', '1234', '1234.', '12345', '123456', '123456789',
        '123!@#', '1234!@#$',
        '1314', '1314.', '1qaz',
        '2', '222', '23', '234',
        '321', '333', '333.',
        '438', '444', '444.',
        '520', '520.', '5201314', '521', '521.', '555', '555.',
        '666', '777', '777.',
        '888', '888.', '8888', '88888', '888888', '88888888',
        '99', '999', '999.',
        'Ab', 'Abc', 'ASD', 'Aa', 'x', 'xx', 'xxx', 'zxc', 'ZXC',
        'a', 'aa', 'aaa', 'ab', 'abc', 'abcd', 'asd',
        'admin', 'admin123', 'admin888',
        'bb',
        'cc',
        'qaz', 'qaz123', 'QWE', 'qwe', 'qazwsx',
        'pass',
        'root',
        'sb'
    ]

    _r = []
    _r += pass_add_suffix(word, rules)
    _r += pass_add_suffix(word, years())
    _r += pass_add_prefix(word, rules)
    _r += pass_add_prefix(word, years())

    return _r
