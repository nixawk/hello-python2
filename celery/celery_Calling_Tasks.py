
## Calling Tasks

# You can call a task using the delay() method:
# >>> add.delay(2, 2)

# The method is actually a star-argument shortcut to another method called apply_async()

# >>> add.apply_async((2, 2))

# The latter enables you to specify execution options like the time to run (countdown), 
# the queue is should be sent to, and so on:

# >>> add.apply_async((2, 2), queue='lopri', countdown=10)

# In the above example the task will be sent to a queue named lopri and the task will execute,
# at the earliest, 10 seconds after the message was sent.

# Applying the task directly will execute the task in the current process,
# so that no message is sent:

# >>> add(2, 2)

# The delay and apply_async methods return an AsyncResult instance, that can be used to
# keep track of the tasks execution state. But for this you need ti enable a result backend
# so that the state can be stored somewhere.

# Results are disabled by default because of the fact that there’s no result backend that
# suits every application, so to choose one you need to consider the drawbacks of each
# individual backend. For many tasks keeping the return value isn’t even very useful,
# so it’s a sensible default to have. Also note that result backends aren’t used for
# monitoring tasks and workers, for that Celery uses dedicated event messages
# (see Monitoring and Management Guide).

# If you have a result backend configured you can retrieve the return value of a task:

# >>> res = add.delay(2, 2)
# >>> res.get(timeout=1)

# You can also inspect the exception and traceback if the task raised an exception,
# in fact result.get() will propagate any errors by default:

# >>> res = add.delay(2)
# >>> res.get(timeout=1)

# If you don't wish for the errors to propagate then you can disable that by passing the
# propagate argument.

# >>> res.get(propagate=False)

# In this case it'll return the exception instance raised instead, and so to check whether
# the task succeeded or failed you'll have to use the corresponding methods on the result instance.

# >>> res.failed()
# >>> res.successful()

# So how does it know if the task has failed or not ? It can find out by looking at the tasks state:
# >>> res.state

