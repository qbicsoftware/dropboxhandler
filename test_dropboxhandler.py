# coding: utf8

from __future__ import print_function
from dropboxhandler import (
    extract_barcode, init_logging, is_valid_barcode,
    write_checksum, recursive_link, generate_openbis_name
)
from nose.tools import raises
import tempfile
import subprocess
import os
import shutil
import signal
import time
from os.path import join as pjoin
from os.path import exists as pexists

init_logging({'loglevel': 'DEBUG', 'use_conf_file_logging': False,
              'paths': {'incoming': '/path/to/incoming'}})


@raises(ValueError)
def test_barcode_no_barcode():
    extract_barcode("/exports/blubb/netair.raw")


def test_barcode_bad_chars():
    path = "/exports/blubb/aörQJFDC010EUä()_<{.räW"
    assert extract_barcode(path) == "QJFDC010EU"


@raises(ValueError)
def test_barcode_two_barcodes():
    path = "/exports/blubb/QJFDC010EU_QJFDC066BI"
    extract_barcode(path)


def test_barcode_two_barcodes_eq():
    path = "/exports/blubb/QJFDC010EU_QJFDC010EU.raw"
    assert extract_barcode(path) == 'QJFDC010EU'


def test_generate_openbis_name():
    path = "uiaenrtd_{()=> \tQJFDC010EU_gtä.raw"
    assert (generate_openbis_name(path) ==
            "QJFDC010EU_uiaenrtd_QJFDC010EU_gt.raw")


def test_is_valid_barcode():
    assert is_valid_barcode("QJFDC010EU")
    assert not is_valid_barcode("QJFDC010EX")
    assert is_valid_barcode("QJFDC066BI")
    assert not is_valid_barcode("QJFDC066B1")


def test_write_checksum():
    dir = tempfile.mkdtemp()
    data = os.path.join(dir, 'data.txt')
    with open(data, 'w') as f:
        f.write("hi")
    write_checksum(data)
    with open(data + '.sha256') as f:
        print(f.read())
    subprocess.check_call('sha256sum -c --status %s.sha256' % data,
                          shell=True,
                          cwd=dir)

    with open(data, 'w') as f:
        f.write("blubb")

    try:
        subprocess.check_call(
            'sha256sum -c --status --strict %s.sha256' % data,
            shell=True, cwd=dir
        )
        assert False
    except subprocess.CalledProcessError:
        pass

    datadir = os.path.join(dir, 'testdir')
    os.mkdir(datadir)
    data = os.path.join(datadir, 'filename')

    with open(data, 'w') as f:
        f.write('bä')

    write_checksum(datadir)

    subprocess.check_call('sha256sum -c --status %s.sha256' % datadir,
                          cwd=dir,
                          shell=True)

    shutil.rmtree(dir)


def test_recursive_link():
    base = tempfile.mkdtemp()

    source = os.path.join(base, 'data')
    os.mkdir(source)
    data = os.path.join(source, 'data.txt')
    os.symlink('/usr/bin/', os.path.join(source, 'link'))
    with open(data, 'w'):
        pass

    dest = os.path.join(base, 'dest')
    try:
        recursive_link(source, dest)
    except ValueError:
        pass
    else:
        assert False
    shutil.rmtree(base)


class TestIntegration:

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.names = ['incoming', 'tmpdir', 'storage', 'manual', 'openbis']
        self.paths = {}
        for name in self.names:
            self.paths[name] = os.path.join(self.base, name)
            os.mkdir(self.paths[name])

        self.pidfile = pjoin(self.base, 'pidfile')
        self.conf = os.path.join(self.base, 'dropbox.conf')
        self.umask = '0o077'
        with open(self.conf, 'w') as f:
            f.write("[paths]\n")
            for name in self.names:
                f.write("%s = %s\n" % (name, self.paths[name]))
            f.write('pidfile = %s\n' % self.pidfile)

            f.write('[options]\n')
            f.write('interval = 1\n')
            f.write('filemode = 0o644\n')
            f.write('dirmode = 0o755\n')
            f.write('umask = %s\n' % self.umask)

        self.logfile = pjoin(self.base, 'log')
        subprocess.check_call(
            'dropboxhandler -c %s -d' % (self.conf),
            shell=True
        )
        time.sleep(0.2)

    def tearDown(self):
        with open(self.pidfile) as f:
            pid = int(f.read())

        os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)
        assert not os.path.exists(self.pidfile)
        shutil.rmtree(self.base)

    def _send_file(self, name):
        fdata = os.path.join(self.paths['incoming'], name)
        with open(fdata, 'w') as f:
            f.write('hi')

        marker = os.path.join(self.paths['incoming'],
                              ".MARKER_is_finished_" + name)
        with open(marker, 'w'):
            pass

        time.sleep(1.2)

    def _send_dir(self, name, *files):
        dir = os.path.join(self.paths['incoming'], name)
        os.mkdir(dir)
        for file in files:
            with open(pjoin(dir, file), 'w') as f:
                f.write('blubb')

        marker = os.path.join(self.paths['incoming'],
                              ".MARKER_is_finished_" + name)
        with open(marker, 'w'):
            pass

        time.sleep(1.2)

    def test_manual(self):
        self._send_file('dataaä .txt')
        assert pexists(pjoin(self.paths['manual'], 'dataa.txt'))
        assert pexists(pjoin(self.paths['manual'], 'dataa.txt.sha256'))
        with open(pjoin(self.paths['manual'], 'dataa.txt.sha256')) as f:
            assert 'dataa.txt' in f.read()

    def test_empty(self):
        self._send_file(' ä')
        assert pexists(pjoin(self.paths['incoming'], 'MARKER_error_ ä'))

    def test_tab(self):
        self._send_file('baää\t\n')
        assert pexists(pjoin(self.paths['manual'], 'ba'))

    def test_conflict(self):
        self._send_file('blubb.txt')
        self._send_file('blubb.txt')
        assert pexists(pjoin(self.paths['incoming'], 'MARKER_error_blubb.txt'))

    def test_start_marker(self):
        self._send_file('.MARKER_is_finished_foo')
        marker_name = 'MARKER_error_.MARKER_is_finished_foo'
        error_marker = pjoin(self.paths['incoming'], marker_name)
        assert pexists(error_marker)

    def test_umask(self):
        self._send_dir('testdir', 'file1')
        outpath = pjoin(self.paths['manual'], 'testdir')
        assert pexists(outpath)
        assert os.path.isdir(outpath)
        assert pexists(pjoin(outpath, 'file1'))
        assert os.stat(outpath).st_mode & int(self.umask, 8) == 0

    def test_openbis(self):
        self._send_file("äää  \t({QJFDC066BI.RAw")
        expected_name = 'QJFDC066BI_QJFDC066BI.raw'
        assert pexists(pjoin(self.paths['openbis'], expected_name))
        marker = '.MARKER_is_finished_' + expected_name
        assert pexists(pjoin(self.paths['openbis'], marker))
