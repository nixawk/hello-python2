
"""
Getitem and Getattr

New style formatting allows even greater flexibility in accessing nested datas
tructures.
"""

person = {'first': 'Jean-Luc', 'last': 'Picard'}
print '{p[first]} {p[last]}'.format(p=person)
print '{first} {last}'.format(**person)

data = [4, 8, 15, 16, 23, 42]
print '{d[4]} {d[5]}'.format(d=data)  # format dict
print '{4} {5}'.format(*data)         # format list


# As well as accessing attributes on objects via getattr():


class Plant(object):
    type = 'tree'
    kinds = [{'name': 'oak'}, {'name': 'maple'}]

print '{p.type}'.format(p=Plant())
print '{p.type}: {p.kinds[0][name]}'.format(p=Plant())
