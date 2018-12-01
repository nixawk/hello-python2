#!/usr/bin/python
# -*- coding: utf-8 -*-

##
# Current source: https://github.com/open-security/vulnpwn/
##

import io
import os
import cmd
import subprocess


class Colors(object):
    N = '\033[m'    # native
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue


class Framework(cmd.Cmd):
    """Core Framework"""
    ruler = '='
    lastcmd = ''
    intro = None
    doc_leader = ''
    doc_header = 'Core Commands Menu (help <command> for details)'
    misc_header = 'Miscellaneous help topics:'
    undoc_header = "No help on follwoing command(s):"

    # ======================
    #  cmd.Cmd
    # ======================
    # Code: https://hg.python.org/cpython/file/tip/Lib/cmd.py

    def __init__(self, verbose=False):
        """init core framework"""
        cmd.Cmd.__init__(self)
        self.do_help.__func__.__doc__ = """Show help menu"""

        self.path_sep = os.path.sep
        self.verbose = verbose

    def emptyline(self):
        """Called when an empty line is entered in response to the prompt."""
        if self.lastcmd:
            return self.onecmd(self.lastcmd)

    def default(self, line):
        """Called on an input line when the cmd prefix is not recognized."""
        self.do_shell(line)

    def precmd(self, line):
        """Hook method executed just before the command line is interpreted,
        but after the input prompt is generated and issued"""
        return line

    def postcmd(self, stop, line):
        """Hook method executed just after a command dispatch is finished."""
        return stop

    def preloop(self):
        """Hook method executed once when the cmdloop() method is called."""
        pass

    def postloop(self):
        """Hook method executed once when the cmdloop() method is
        about to return"""
        pass

    def print_topics(self, header, cmds, cmdlen, maxcol):
        """make help menu more readable"""
        if cmds:
            self.stdout.write(header)
            self.stdout.write("\n")
            if self.ruler:
                self.stdout.write(self.ruler * len(header))
                self.stdout.write("\n")

            for cmd in cmds:
                help_msg = getattr(self, "do_{}".format(cmd)).__doc__
                self.stdout.write("{:<16}".format(cmd))
                self.stdout.write(help_msg)
                self.stdout.write("\n")
            self.stdout.write("\n")

    def shell_will_go(self):
        """Enter a interactive shell"""
        try:
            self.cmdloop()
        except KeyboardInterrupt:
            print

    # ======================
    #  STRING METHODS
    # ======================

    def getUnicode(self, line, encoding=None):
        """translate a string to unicode"""
        if isinstance(line, unicode):
            return line
        else:
            try:
                return unicode(line, encoding or "utf-8")
            except (UnicodeDecodeError, TypeError):
                return unicode(str(line), errors="ignore")

    def error(self, line):
        """output error message"""
        print('{}[!] {}{}'.format(Colors.R, self.getUnicode(line), Colors.N))

    def warn(self, line):
        """output warnings message"""
        print('{}[*] {}{}'.format(Colors.G, Colors.N, self.getUnicode(line)))

    def output(self, line):
        """output text message"""
        print('{}[*] {}{}'.format(Colors.B, Colors.N, self.getUnicode(line)))

    def debug(self, line):
        """output debug text message"""
        if self.verbose:
            self.output(line)

    # ======================
    #  FRAMEWORK COMMANDS
    # ======================

    def is_file(self, filename):
        """if file is a normal file or not"""
        return os.path.isfile(filename)

    def is_dir(self, filename):
        """if file is an directory or not"""
        return os.path.isdir(filename)

    def is_executable(self, filename):
        """if file is executable or not"""
        return os.access(filename, os.X_OK)

    def is_readable(self, filename):
        """if file is readable or not"""
        return os.access(filename, os.R_OK)

    def is_writable(self, filename):
        """if file is writeable or not"""
        return os.access(filename, os.W_OK)

    def is_exists(self, filename):
        """if file exists or not"""
        return os.path.exists(filename)

    def openfile(self, filename, mode='r', encoding='utf-8'):
        """open file, and return a file handle"""
        try:
            f = io.open(filename, mode, encoding=encoding)
        except Exception as e:
            self.error(e)
            f = None

        return f

    def readfile(self, filename, mode='r', encoding='utf-8'):
        """read contents from file"""
        d = ''  # file data
        f = self.openfile(filename, mode, encoding=encoding)
        if hasattr(f, 'read'):
            d = f.read()
        return d

    def writefile(self, filename, data, mode='w', encoding='utf-8'):
        """write contents to file. file must be a unicode format"""
        f = self.openfile(filename, mode, encoding=encoding)
        if hasattr(f, 'write'):
            f.write(self.getUnicode(data))
            return True

        return False

    def editfile(self, filename):
        """Edit file with the default text editor"""
        self.output("EDIT FILE > {}".format(filename))
        editor = os.getenv('EDITOR', 'vim')
        os.system('{} {}'.format(editor, filename))

    def dirpath(self, filepath):
        """return directory path"""
        return os.path.dirname(filepath)

    def filename(self, filepath):
        """return filename"""
        return os.path.basename(filepath)

    def dirwalk(self, dirpath):
        """return filepaths list from dirpath"""
        dirs = []
        for (dirpath, dirnames, filenames) in os.walk(dirpath):
            if dirpath[-1] == self.path_sep:
                filepaths = ["{}{}".format(dirpath, fname)
                             for fname in filenames if fname]
            else:
                filepaths = ["{}{}{}".format(dirpath, self.path_sep, fname)
                             for fname in filenames if fname]
            dirs.extend(filepaths)

        return list(set(dirs))

    # ======================
    #  FRAMEWORK COMMANDS
    # ======================

    def do_exit(self, line):
        """Exit framework interactive shell"""

        return True

    def do_debug(self, line):
        """Enter into python debugger"""
        import pdb
        pdb.set_trace()

    def do_shell(self, cmd):
        """Execute system command"""
        process = subprocess.Popen(cmd,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   shell=True)

        stdout = process.stdout.read()
        stderr = process.stderr.read()

        if stdout:
            self.output(self.getUnicode(stdout))

        if stderr:
            self.error(self.getUnicode(stderr))

        # return (stdout, stderr)

    # ======================
    #  FRAMEWORK HELP
    # ======================

    def help_exit(self):
        self.output('')
        self.output('  Usage : exit')
        self.output('  Desp  : {}'.format(getattr(self, 'do_exit').__doc__))
        self.output('  Demo  : exit')
        self.output('')

    def help_help(self):
        self.output('')
        self.output('  Usage : help')
        self.output('  Desp  : {}'.format(getattr(self, 'do_help').__doc__))
        self.output('  Demo  : help')
        self.output('')

    def help_debug(self):
        self.output('')
        self.output('  Usage : debug')
        self.output('  Desp  : {}'.format(getattr(self, 'do_debug').__doc__))
        self.output('  Demo  : debug')
        self.output('')

    def help_shell(self):
        self.output('')
        self.output('  Usage : shell <command>')
        self.output('  Desp  : {}'.format(getattr(self, 'do_shell').__doc__))
        self.output('  Demo  : shell whoami')
        self.output('')


if __name__ == '__main__':
    fw = Framework()
    fw.shell_will_go()
