
## Groups

# A group calls a list of tasks in parallel, and it returns a special resutl instance that lets
# you inspect the results as a group, and retrieve the return values in order.

# >>> from celery import group
# >>> from proj.tasks import add

# >>> group(add.s(i, i) for i in xrange(10))().get()
# [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]

# Partial group

# >>> g = group(add.s(i) for i in xrange(10))
# >>> g(10).get()
# [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
