
## Chords

# A chord is a group with a callback

# >>> from celery import chord
# >>> from proj.tasks import add, xsum

# >>> chord((add.s(i, i) for i in xrange(10)), xsum.s())().get()
# 90

# A group chained to another task will be automatically converted to a chord:

# >>> (group(add.s(i, i) for i in xrange(10)) | xsum.s())().get()
# 90

# Since these primitives are all of the signature type they can be combined almost however you want, for example:
# >>> upload_document.s(file) | group(apply_filter.s() for filter in filters)


# http://docs.celeryproject.org/en/latest/userguide/canvas.html#guide-canvas