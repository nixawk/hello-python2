
# https://github.com/nvie/new_workers/

from __future__ import absolute_import
from gevent import monkey
monkey.patch_all()

import signal
import gevent
import gevent.pool
from gevent.event import Event
import time
import os
import errno


def install_signal_handlers():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)


def disable_interrupts():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


class Interruptable(object):
    def __enter__(self):
        install_signal_handlers()

    def __exit__(self, type, value, traceback):
        disable_interrupts()


def waitpid(pid):
    """
    Safe version of `os.waitpid(pid, 0)` that catches OSError in case of an
    already-gone child pid.
    """
    try:
        os.waitpid(pid, 0)
    except OSError as e:
        if e.errno != errno.ECHILD:
            # Allow "No such process", since that means process is
            # already gone---no need to wait for it to finish
            raise


def kill(pid, signum=signal.SIGKILL):
    """
    Safe version of `os.kill(pid, signum)` that catches OSError in case of an
    already-dead pid.
    """
    try:
        os.kill(pid, signum)
    except OSError as e:
        if e.errno != errno.ESRCH:
            # Allow "No such process", since that means process is
            # already gone---no need to kill what's already dead
            raise


class FakeWorkMethodMixin(object):
    """
    This is just a dummy place to hold the logic that can be replaced by RQ's
    job popping and execution.
    """

    def fake_url_get(self, url='http://nvie.com/about'):
        """This is a fake IO-bound method that has network access."""
        import requests
        word_count = len(requests.get(url).text.split())
        print '{} contains {} words.'.format(url, word_count)

    def fake_job(self):
        """This is a fake job"""
        self.fake_url_get(url='https://github.com/nvie/')


class BaseWorker(FakeWorkMethodMixin):
    def install_signal_handlers(self):
        install_signal_handlers()

    def get_ident(self):
        raise NotImplementedError('Implement this in a subclass.')

    def spawn_child(self):
        raise NotImplementedError('Implement this in a subclass.')

    def terminate_idle_children(self):
        raise NotImplementedError('Implement this in a subclass.')

    def wait_for_children(self):
        raise NotImplementedError('Implement this in a subclass.')

    def kill_children(self):
        raise NotImplementedError('Implement this in a subclass.')

    def work(self):
        self.install_signal_handlers()

        while True:
            try:
                self.spawn_child()
            except KeyboardInterrupt:
                self.terminate_idle_children()
                break

        try:
            self.wait_for_children()
        except KeyboardInterrupt:
            print 'Cold shutdown entered'
            self.kill_children()
            print 'Children killed. You murderer.'

        print 'Shut down'

    def main_child(self, mark_busy):
        """The main entry point within a spawned child.  When this method is
        invoked, any forking or spawning is already done by the main worker,
        and this method is invoked to do the actual blocking wait and the
        execution of the job.
        """
        #busy_flag.clear()  # Not really necessary, but explicit
        # job = self.fake_blpop()
        #busy_flag.set()
        mark_busy()
        # job()  # fake perform job
        self.fake_job()


class GeventWorker(BaseWorker):

    ##
    # Overridden from BaseWorker
    def __init__(self, num_processes=1):
        self._pool = gevent.pool.Pool(num_processes)

        # In this dictionary, we keep a greenlet -> Event mapping to indicate
        # whether that greenlet is in idle or busy state.  Greenlets that are
        # in busy state will not be terminated, since that might lead to loss
        # of work.  The Event is a gevent synchronisation primitive that can
        # be used to let the child set a flag that the main worker acts on.
        self._busy = {}

    def install_signal_handlers(self):
        # Enabling the following line to explicitly set SIGINT yields very
        # weird behaviour: can anybody explain?
        # gevent.signal(signal.SIGINT, signal.default_int_handler)
        gevent.signal(signal.SIGTERM, signal.default_int_handler)

    def get_ident(self):
        return id(gevent.getcurrent())

    def spawn_child(self):
        """Forks and executes the job."""
        busy_flag = Event()

        def _mark_busy(flag):
            def _inner():
                time.sleep(0)  # TODO: Required to avoid "blocking" by CPU-bound jobs in gevented worker
                flag.set()
            return _inner

        child_greenlet = self._pool.spawn(self.main_child, _mark_busy(busy_flag))
        self._busy[child_greenlet] = busy_flag
        child_greenlet.link(self._cleanup_busy_flag)

    def terminate_idle_children(self):
        print 'Find all children that are in idle state (waiting for work)...'
        for child_greenlet, busy_flag in self._busy.items():
            if not busy_flag.is_set():
                print '==> Killing {}'.format(id(child_greenlet))
                child_greenlet.kill()
            else:
                print '==> Waiting for {} (still busy)'.format(id(child_greenlet))

    def wait_for_children(self):
        print 'Waiting for children to finish gracefully...'
        self._pool.join()
        print 'YIPPY!'

    def kill_children(self):
        print 'Killing all children...'
        self._pool.kill()
        print 'MWHUAHAHAHAHA!'
        self.wait_for_children()


    ##
    # Helper methods (specific to gevent workers)
    def _cleanup_busy_flag(self, child):  # noqa
        """Callback that's called when a child greenlet finishes.  Since the
        greenlet is gone, we can clean up our busy administration.
        """
        # print 'del self._busy[{}]'.format(id(child))
        del self._busy[child]


if __name__ == "__main__":
    worker = GeventWorker(num_processes=2)
    worker.work()
