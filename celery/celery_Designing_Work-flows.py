
## Canvas: Designing Work-flows

# You just learned how to call a task using the tasks delay method, and this is often
# all you need, but sometimes you may want to pass the signature of a task invocation
# to another process or as an argument to another function, for this Celery uses something
# called signatures.

# A signature wraps the arguments and execution options of a single task invocation in a way such that
# it can be passed to functions or even serialized and sent across the wire.

# You can create a signature for the add task using the arguments (2, 2), and a countdown of 10 seconds
# like this:

# >>> add.signature((2, 2), countdown=10)
# tasks.add(2, 2)

# There’s also a shortcut using star arguments:

# >>> add.s(2, 2)
# tasks.add(2, 2)

# Signature instances also supports the calling API: meaning they have the delay and apply_async methods.

# But there’s a difference in that the signature may already have an argument signature specified. The add
# task takes two arguments, so a signature specifying two arguments would make a complete signature:

# >>> s1 = add.s(2, 2)
# >>> res = s1.delay()
# >>> res.get()
# 4

# But, you can also make incomplete signatures to create what we call partials:

# incomplete partial: add(?, 2)
# >>> s2 = add.s(2)

# s2 is now a partial signature that needs another argument to be complete, and this can be resolved when calling the signature:

# resolves the partial: add(8, 2)
# >>> res = s2.delay(8)
# >>> res.get()
# 10

# Keyword arguments can also be added later, these are then merged with any existing keyword arguments, but with new arguments taking precedence:

# >>> s3 = add.s(2, 2, debug=True)
# >>> s3.delay(debug=False)   # debug is now False.