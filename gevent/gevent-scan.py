#!/usr/bin/python
# -*- coding: utf-8 -*-

'''

## Command Line

Downloads python scan.py -h
Usage: python scan.py [options]

Options:
  -h, --help            show this help message and exit

  DEMO:
    --demo              just for demo

  CONFIG:
    -c CONFIGFILE, --config=CONFIGFILE
                        a valid config file

  SETTINGS:
    --hosts=FILENAME    Input from list of hosts
    --script=SCRIPT     a script used for a special purpose
    --proc=PROCESSNUM   num of concurrent process
    --pool=POOLSIZE     gevent poolsize (default: 500)
    --timeout=TIMEOUT   gevent worker timeout

## script file

A script file can be used to finish a special file, ex:

---- poc.py --------

def test(x):
    print(x.strip())
    return x


## Scan with a config file

---- config.cfg ----

[SETTINGS]
FILENAME=hosts.ip
SCRIPT=poc.py
PROCESSNUM=6
POOLSIZE=50
TIMEOUT=300

$ python scan.py -c config.cfg


## Scan with options parameters

$ python scan.py --hosts hosts.ip --script poc.py --proc 6 --pool 50
'''

import os
import sys
import tempfile
import ConfigParser
import traceback
import multiprocessing

from optparse import OptionParser
from optparse import OptionGroup
from optparse import OptionError

try:
    import gevent
    from gevent import monkey as curious_george
    from gevent.pool import Pool
    from gevent import timeout
except ImportError:
    raise RuntimeError('Gevent is required.')

curious_george.patch_all(thread=False, select=False)


class ConfError(Exception):
    '''Config File Exceptions'''
    pass


def count_textfile(filename):
    '''count total lines number of a file'''
    with open(filename) as f:
        return sum(1 for _ in f)

def split_textfile(input_filename, linenum):
    '''split a file into serval temp files'''
    filenames = []
    for i, line in enumerate(open(input_filename)):
        if i % linenum == 0:
            output_file = open(tempfile.mktemp(), 'w')
            if output_file not in filenames:
                filenames.append(output_file.name)
        output_file.write(line)
    return filenames


class Cmdline(object):
    def getArgs(self):
        '''
        This function parses the command line parameters and arguments
        '''
        usage = "python %prog [options]"
        parser = OptionParser(usage=usage)
        try:
            demo = OptionGroup(parser, "DEMO", "")
            demo.add_option('--demo', dest='demo', action='store_true',
                            help='just for demo')
            parser.add_option_group(demo)

            config = OptionGroup(parser, "CONFIG", "")
            config.add_option('-c', '--config', dest='configfile', type='str',
                              help='a valid config file')
            parser.add_option_group(config)

            settings = OptionGroup(parser, "SETTINGS", "")
            settings.add_option('--hosts', dest='filename', type='str',
                                help='Input from list of hosts')
            settings.add_option('--script', dest='script', type='str',
                                help='a script used for a special purpose')
            settings.add_option('--proc', dest='processnum', type='int',
                                default=multiprocessing.cpu_count(),
                                help='num of concurrent process')
            settings.add_option('--pool', dest='poolsize', type='int',
                                default=500,
                                help='gevent poolsize (default: 500)')
            settings.add_option('--timeout', dest='timeout', type='float',
                                help='gevent worker timeout')
            parser.add_option_group(settings)
            (args, _) = parser.parse_args()
        except (OptionError, TypeError) as e:
            parser.error(e)
            # traceback.print_exc(e)
        else:
            return args

    def parseArgs(self, options):
        if options.demo:
            test_a_worker()
            test_workers()
            test_multiprocessing_workers()

        if options.configfile:
            options = self.initConfigfile(options)
        else:
            options = self.initOptions(options)

        VVV(options).scan()
        return options

    def initOptions(self, options):
        return vars(options)

    def initConfigfile(self, options):
        config = options.configfile
        conf = ConfigParser.ConfigParser()
        conf.read(config)
        return dict(conf.items("SETTINGS"))


class VVV(object):
    def __init__(self, options):
        self.options = options

        self.filename = options.get('filename')
        self.script = options.get('script')
        self.processnum = options.get('processnum')
        self.poolsize = options.get('poolsize')
        self.timeout = options.get('timeout')
        self.worker_func = None

    def init_script(self, script):
        func = None
        if script and os.path.exists(script):  # '"poc.py"'
            sys.path.append(os.path.abspath(os.path.dirname(script)))
            mod = __import__(os.path.splitext(os.path.basename(script))[0])
            func = self.worker_func = getattr(mod, 'test')
        return func

    def scan(self):
        if not self.filename:
            return

        if not os.path.exists(self.filename):
            raise ConfError("Targets File can not be found.")

        if not self.script:
            return

        if not os.path.exists(self.script):
            raise ConfError("Script File can not be found.")

        self.worker_func = self.init_script(self.script)
        if not self.worker_func:
            raise ConfError("Script File can not be loaded.")

        if not self.processnum:
            raise ConfError("processnum not found.")

        if not (isinstance(self.processnum, int) or self.processnum.isdigit()):
            raise ConfError("processnum must be a number.")

        processes = []
        proc_num = int(self.processnum)
        if proc_num >= multiprocessing.cpu_count():
            proc_num = multiprocessing.cpu_count()

        filecount = count_textfile(self.filename)
        filenames = split_textfile(self.filename, (filecount / proc_num) + 1)

        for _ in filenames:
            proc = multiprocessing.Process(
                target=map_workers,
                args=(open(_), 100, self.worker_func),
                kwargs={
                    'callback': None,
                    'exception_handler': None
                })
            processes.append(proc)

        for process in processes:
            process.start()

        for process in processes:
            process.join()


class Worker(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

        self.response = None

    def start(self, **kwargs):
        '''Prepares worker based on parameter passed on constructor and
        optional ``kwargs``
        '''
        merged_kwargs = {}
        merged_kwargs.update(self.kwargs)
        merged_kwargs.update(kwargs)
        worker_timeout = merged_kwargs.pop('timeout', 6.0)
        worker_callback = merged_kwargs.pop('callback', None)
        worker_exception = merged_kwargs.pop('exception_handler', None)

        try:
            self.response = timeout.with_timeout(
                worker_timeout, self.func, *self.args, **merged_kwargs)

            if worker_callback:
                self.respnose = worker_callback(self.response)
        except Exception as e:
            self.exception = e

            if worker_exception:
                self.exception = worker_exception(self.exception)
            self.traceback = traceback.format_exc()

        return self


def new_worker(func, *args, **kwargs):
    '''Create a new job worker

    :param func: special function
    :param args: function args
    :param kwargs: function kwargs

    kwargs can include the following parameters:
        callback=callback,
        exception_handler=exception_handler
    '''

    return Worker(func, *args, **kwargs)


def map_workers(iterator, poolsize, func, *args, **kwargs):
    '''Concurrently get iterator response

    :param iterator: fileobject, set, list, ...
    :param poolsize: Specifies the number of workers to make at a time.
    '''

    pool = Pool(poolsize)

    for _ in iterator:
        current_worker = new_worker(func, _, *args, **kwargs)
        pool.add(pool.apply_async(func=current_worker.start))

    pool.join()


# ### Demo Part ### #
def a_worker_callback(data):
    print("[+] callback data: {}".format(data))
    return data


def a_worker(data, *args, **kwargs):
    print("[*] original data: {}".format(data))
    # Just for [exception_handler] test
    # data = data + ' '  # Integer + String
    return data


def a_worker_exception(excep_info):
    print(excep_info)
    return excep_info


def test_a_worker():
    demo_worker = new_worker(a_worker, 2, callback=a_worker_callback)
    # demo_worker = new_worker(a_worker, 2)
    demo_worker.start()
    # print(demo_worker.response)


def test_workers():
    iterator = [i for i in range(10000)]
    map_workers(iterator, 100, a_worker, callback=a_worker_callback)


def test_multiprocessing_workers():
    iterator = [i for i in range(10000)]

    proc = multiprocessing.Process(
        target=map_workers,
        args=(iterator, 100, a_worker),
        kwargs={
            'callback': a_worker_callback,
            'exception_handler': a_worker_exception
        })

    proc.start()
    proc.join()


if __name__ == "__main__":
    print("Hello python")
    c = Cmdline()
    c.parseArgs(c.getArgs())
