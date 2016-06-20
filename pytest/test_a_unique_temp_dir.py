
# Going functional: requesting a unique temporary directory

# For functional tests one often needs to create some files and pass them to
# application objects. pytest provides Builtin fixtures/function arguments which
# allow to request arbitrary resources, for example a unique temp directory


def test_needsfiles(tmpdir):
    print(tmpdir)
    assert 0

# We list the name `tmpdir` in the test function signature and `pytest` will
# lookup and call a fixture factory to create the resource before performing the
# test function call. Let's just run it:

"""
$ py.test -q test_tmpdir.py
F
======= FAILURES ========
_______ test_needsfiles ________

tmpdir = local('PYTEST_TMPDIR/test_needsfiles0')

    def test_needsfiles(tmpdir):
        print (tmpdir)
>       assert 0
E       assert 0

test_tmpdir.py:3: AssertionError
--------------------------- Captured stdout call ---------------------------
PYTEST_TMPDIR/test_needsfiles0
1 failed in 0.12 seconds
"""

# Before the test runs, a unique-per-test-invocation temporary directory was
# created. More info at Temporary directories and files.

# You can find out what kind of builtin pytest fixtures: explicit, modular,
# scalable exist by typing:

# $ py.test --fixtures   # shows builtin and custom fixtures

"""
cache
    Return a cache object that can persist state between testing sessions.

    cache.get(key, default)
    cache.set(key, value)

    Keys must be a ``/`` separated value, where the first part is usually the
    name of your plugin or application to avoid clashes with other cache users.

    Values can be any object handled by the json stdlib module.
capsys
    enables capturing of writes to sys.stdout/sys.stderr and makes
    captured output available via ``capsys.readouterr()`` method calls
    which return a ``(out, err)`` tuple.
capfd
    enables capturing of writes to file descriptors 1 and 2 and makes
    captured output available via ``capfd.readouterr()`` method calls
    which return a ``(out, err)`` tuple.
record_xml_property
    Fixture that adds extra xml properties to the tag for the calling test.
    The fixture is callable with (name, value), with value being automatically
    xml-encoded.
monkeypatch
    The returned ``monkeypatch`` funcarg provides these
    helper methods to modify objects, dictionaries or os.environ::

    monkeypatch.setattr(obj, name, value, raising=True)
    monkeypatch.delattr(obj, name, raising=True)
    monkeypatch.setitem(mapping, name, value)
    monkeypatch.delitem(obj, name, raising=True)
    monkeypatch.setenv(name, value, prepend=False)
    monkeypatch.delenv(name, value, raising=True)
    monkeypatch.syspath_prepend(path)
    monkeypatch.chdir(path)

    All modifications will be undone after the requesting
    test function has finished. The ``raising``
    parameter determines if a KeyError or AttributeError
    will be raised if the set/deletion operation has no target.
pytestconfig
    the pytest config object with access to command line opts.
recwarn
    Return a WarningsRecorder instance that provides these methods:

    * ``pop(category=None)``: return last warning matching the category.
    * ``clear()``: clear list of warnings

    See http://docs.python.org/library/warnings.html for information
    on warning categories.
tmpdir_factory
    Return a TempdirFactory instance for the test session.
tmpdir
    return a temporary directory path object
    which is unique to each test function invocation,
    created as a sub directory of the base temporary
    directory.  The returned object is a `py.path.local`_
    path object.
"""
