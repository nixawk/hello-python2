
## Chains

# Tasks can be linked together so that after one task returns the other is called.

# >>> from celery import chain
# >>> from proj.tasks import add, mul

# (4 + 4) * 8
# >>> chain(add.s(4, 4) | mul.s(8))().get()
# 64

# or a partial chain:

# >>> # (? + 4) * 8
# >>> g = chain(add.s(4) | mul.s(8))
# >>> g(4).get()
# 64

# Chains can also be written like this:

# >>> (add.s(4, 4) | mul.s(8))().get()
# 64