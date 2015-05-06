#!/usr/bin/env python
# -*- coding: utf8 -*-

import os
import time


# ***************************************************************************
# The “l” and “v” variants of the exec* functions differ in how command-line
# arguments are passed.
#
#  The “l” variants are perhaps the easiest to work with if the number of
#  parameters is fixed when the code is written; the individual parameters
#  simply become additional parameters to the execl*() functions.
#
#  The “v” variants are good when the number of parameters is variable, with
#  the arguments being passed in a list or tuple as the args parameter. In
#  either case, the arguments to the child process should start with the name
#  of the command being run, but this is not enforced.
#
#  The variants which include a “p” near the end (execlp(), execlpe(),
#  execvp(), and execvpe()) will use the PATH environment variable to locate
#  the program file.
# ****************************************************************************

# os.system
# os.fork
# os.execl(path, arg0, arg1, ...)
# os.execle(path, arg0, arg1, ..., env)
# os.execlp(file, arg0, arg1, ...)
# os.execlpe(file, arg0, arg1, ..., env)
# os.execv(path, args)
# os.execve(path, args, env)
# os.execvp(file, args)
# os.execvpe(file, args, env)


# process - ipc communication
r, w = os.pipe()
r, w = os.fdopen(r, 'r', 0), os.fdopen(w, 'w', 0)


# demo fork
def child():
    print "parent pid: %d" % os.getppid()
    print "child pid: %d" % os.getpid()

    r.close()

    for i in range(10):
        # w.write("child - %d" % i)
        print >>w, "child - %d" % i
        w.flush()
        time.sleep(1)


def parent():
    newpid = os.fork()

    if newpid == 0:
        print "child process: %s" % hex(id(child))
        child()

    else:
        print "parent process: %s" % hex(id(parent))

        w.close()

        while True:
            data = r.readline()

            if not data:
                break

            print ("parent - [%s]" % data.strip())


# demo system
def _system():
    os.system('/bin/echo helloworld')


# demo execl
def _execl():
    os.execl('/bin/ls', '-l')
    # execute a new program, replacing the current process;
    # do not return


# demo execv
def _execv():
    os.execv('/bin/echo', ['1', '2', '3'])
    # execute a new program, replacing the current process;
    # do not return

# main
parent()
_system()
_execl()
_execv()


# references
# https://docs.python.org/2/library/os.html#os.fork
# http://stackoverflow.com/questions/871447/python-program-using-os-pipe-and-os-fork-issue
