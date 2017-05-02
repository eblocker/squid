#!/usr/bin/python
#
#    test-squid.py quality assurance test script
#    Copyright (C) 2008-2017 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Author: Christian Ehrhardt <christian.ehrhardt@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import os.path
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest


class HttpdCommon(unittest.TestCase):
    '''Common functions'''
    def __init__(self, *args):
        '''This is called for each TestCase test instance, which isn't much better
           than SetUp.'''
        unittest.TestCase.__init__(self, *args)

    def _setUp(self):
        '''Setup'''
        if not hasattr(self, 'initscript'):
            self._set_initscript("/etc/init.d/apache2")

        self._stop()
        self._start()

    def _set_initscript(self, initscript):
        self.initscript = initscript

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self._stop()

    def _start(self):
        '''Start httpd'''
        expected = 0
        ret, report = cmd([self.initscript, 'start'])
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(expected, ret, result + report)
        time.sleep(2)

    def _stop(self):
        '''Stop httpd'''
        expected = 0
        ret, report = cmd([self.initscript, 'stop'])
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(expected, ret, result + report)

    def _word_find(self, report, content, invert=False):
        '''Check for a specific string'''
        if invert:
            warning = 'Found "%s"\n' % content
            self.assertTrue(content not in report, warning + report)
        else:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(content in report, warning + report)

    def _test_url_proxy(self, url="http://localhost/", content="",
                        proxy="localhost:3128"):
        '''Test the given url'''
        ret, rep = cmd(['elinks', '-verbose', '2', '-no-home', '1',
                        '-eval',
                        'set protocol.ftp.proxy.host = "%s"' % (proxy),
                        '-eval',
                        'set protocol.http.proxy.host = "%s"' % (proxy),
                        '-eval',
                        'set protocol.https.proxy.host = "%s"' % (proxy),
                        '-dump', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(expected, ret, result + rep)

        if content != "":
            self._word_find(rep, content)


class BasicTest(HttpdCommon):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''

        self._set_initscript("/etc/init.d/squid")
        HttpdCommon._setUp(self)

        self.gophermap = "/var/gopher/gophermap"

        self.aa_profile = "usr.sbin.squid3"
        self.aa_abs_profile = "/etc/apparmor.d/%s" % self.aa_profile

    def tearDown(self):
        '''Shutdown methods'''
        HttpdCommon._tearDown(self)
        config_restore(self.gophermap)

    def test_daemons(self):
        '''Test daemon'''

        pidfile = "/run/squid.pid"
        exe = "(squid-1)"

        self.assertTrue(check_pidfile(exe, pidfile))

    def test_http_proxy(self):
        '''Test http'''
        self._test_url_proxy("http://localhost/",
                             "It works!",
                             "http://localhost:3128/")

    def test_https_proxy(self):
        '''Test https'''
        self._test_url_proxy("https://localhost/",
                             "It works!",
                             "http://localhost:3128/")

    def test_ftp_proxy(self):
        '''Test ftp'''
        self._test_url_proxy("ftp://anonymous@localhost:21", "irectory",
                             "http://localhost:3128/")

    def test_squidclient(self):
        '''Test squidclient'''
        urls = ['ftp://anonymous@localhost:21', 'gopher://127.0.0.1']
        for url in urls:
            ret, report = cmd(['squidclient', '-h', '127.0.0.1', '-p',
                               '3128', '-r', url])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (ret, expected)
            self.assertEquals(expected, ret, result + report)

    def test_CVE_2011_3205(self):
        '''Test parsing lines > 4096 in length (CVE-2011-3205)'''

        longline = "ABCDEF" * 4096

        config_replace(self.gophermap,
                       """Welcome to Pygopherd!  You can place your documents
in /var/gopher for future use.  You can remove the gophermap
file there to get rid of this message, or you can edit it to
use other things.  (You'll need to do at least one of these
two things in order to get your own data to show up!)

%s

Some links to get you started:

1Pygopherd Home /devel/gopher/pygopherd gopher.quux.org 70
1Quux.Org Mega Server   /   gopher.quux.org 70
1The Gopher Project /Software/Gopher    gopher.quux.org 70
1Traditional UMN Home Gopher    /   gopher.tc.umn.edu   70

Welcome to the world of Gopher and enjoy!
""" % (longline), append=False)

        ret, report = cmd(['squidclient', '-h', '127.0.0.1', '-p',
                           '3128', '-r', "gopher://127.0.0.1"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(expected, ret, result + report)

    # Run this last so if we enable the profile then we don't unload it
    def test_zz_apparmor(self):
        '''Test apparmor'''

        # Currently while we have a profile, it is shipped disabled by default.
        # Verify that.
        ret, report = check_apparmor(self.aa_abs_profile, is_running=False)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(ret, expected, result + report)

        # Verify it is syntactically correct
        ret, report = cmd(['apparmor_parser', '-p', self.aa_abs_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(ret, expected, result + report)

        # Verify it loads ok
        ret, report = cmd(['aa-enforce', self.aa_abs_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(ret, expected, result + report)

        self._stop()
        self._start()

        ret, report = check_apparmor(self.aa_abs_profile, is_running=True)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (ret, expected)
        self.assertEquals(ret, expected, result + report)


# http://www.chiark.greenend.org.uk/ucgi/~cjwatson/blosxom/2009-07-02-python-sigpipe.html
# This is needed so that the subprocesses that produce endless output
# actually quit when the reader goes away.
def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def _restore_backup(path):
    pathbackup = path + '.autotest'
    if os.path.exists(pathbackup):
        shutil.move(pathbackup, path)


def _save_backup(path):
    pathbackup = path + '.autotest'
    if os.path.exists(path) and not os.path.exists(pathbackup):
        shutil.copy2(path, pathbackup)
        # copy2 does not copy ownership, so do it here.
        # Reference: http://docs.python.org/library/shutil.html
        stat = os.stat(path)
        os.chown(pathbackup, stat[4], stat[5])


def config_replace(path, contents, append=False):
    '''Replace (or append) to a config file'''
    _restore_backup(path)
    if os.path.exists(path):
        _save_backup(path)
        if append:
            with open(path) as fileh:
                contents = fileh.read() + contents
    with open(path, 'w') as fileh:
        fileh.write(contents)


def config_restore(path):
    '''Rename a replaced config file back to its initial state'''
    _restore_backup(path)


def recursive_rm(dir_path, contents_only=False):
    '''recursively remove directory'''
    names = os.listdir(dir_path)
    for name in names:
        path = os.path.join(dir_path, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    if not contents_only:
        os.rmdir(dir_path)


def check_pidfile(exe, pidfile):
    '''Checks if pid in pidfile is running'''
    if not os.path.exists(pidfile):
        return False

    # get the pid
    try:
        with open(pidfile, 'r') as filed:
            pid = filed.readline().rstrip('\n')
    except:
        return False

    return check_pid(exe, pid)


def check_pid(exe, pid):
    '''Checks if pid is running'''
    cmdline = "/proc/%s/cmdline" % (str(pid))
    if not os.path.exists(cmdline):
        return False

    # get the command line
    try:
        with open(cmdline, 'r') as filed:
            tmp = filed.readline().split('\0')
    except:
        return False

    # this allows us to match absolute paths or just the executable name
    if re.match(r'^' + exe + r'$', tmp[0]) or \
       re.match(r'.*/' + exe + r'$', tmp[0]) or \
       re.match(r'^' + exe + r': ', tmp[0]) or \
       re.match(r'^\(' + exe + r'\)', tmp[0]):
        return True

    return False


def cmd(command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
        stdin=None):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
        subp = subprocess.Popen(command, stdin=stdin, stdout=stdout,
                                stderr=stderr, close_fds=True,
                                preexec_fn=subprocess_setup,
                                universal_newlines=True)
    except OSError as err:
        return [127, str(err)]

    out, outerr = subp.communicate(None)
    # Handle redirection of stdout
    if out is None:
        out = ''
    # Handle redirection of stderr
    if outerr is None:
        outerr = ''
    return [subp.returncode, out + outerr]


def _aa_status():
    '''Get aa-status output'''
    exe = "/usr/sbin/aa-status"
    assert os.path.exists(exe)
    if os.geteuid() == 0:
        return cmd([exe])
    return cmd(['sudo', exe])


def is_apparmor_loaded(path):
    '''Check if profile is loaded'''
    ret, report = _aa_status()
    if ret != 0:
        return False

    for line in report.splitlines():
        if line.endswith(path):
            return True
    return False


def is_apparmor_confined(path):
    '''Check if application is confined'''
    ret, report = _aa_status()
    if ret != 0:
        return False

    for line in report.splitlines():
        if re.search(r'%s \(' % path, line):
            return True
    return False


def check_apparmor(path, is_running=True):
    '''Check if path is loaded and confined'''
    ret = -1

    if not os.path.exists('/sbin/apparmor_parser'):
        return (ret, "Skipped (couldn't find apparmor_parser)")

    ret = 0
    msg = ""
    if not is_apparmor_loaded(path):
        ret = 1
        msg = "Profile not loaded for '%s'" % path

    # this check only makes sense it the 'path' is currently executing
    if is_running and ret == 0 and not is_apparmor_confined(path):
        ret = 1
        msg = "'%s' is not running in enforce mode" % path

    return (ret, msg)


if __name__ == '__main__':
    SUITE = unittest.TestSuite()
    SUITE.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    RC = unittest.TextTestRunner(verbosity=2).run(SUITE)
    if not RC.wasSuccessful():
        sys.exit(1)
