# coding: utf8

from handle_incoming import (
    extract_barcode, init_logging, is_valid_barcode,
    write_checksum, recursive_link, generate_openbis_name
)
from nose.tools import istest, raises
import tempfile
import subprocess
import os
import shutil
from collections import namedtuple
try:
    from unittest import mock
except ImportError:
    mock = namedtuple('mock', ['patch'])(lambda s: lambda f: lambda: f(s))

init_logging({'loglevel': 'DEBUG'})


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
        subprocess.check_call('sha256sum -c --status %s.sha256' % data,
                              shell=True)
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


@istest
@mock.patch('handle_incoming.logger')
def test_recursive_link(mock_logger):
    base = tempfile.mkdtemp()

    source = os.path.join(base, 'data')
    os.mkdir(source)
    data = os.path.join(source, 'data.txt')
    os.symlink('/usr/bin/', os.path.join(source, 'link'))
    with open(data, 'w'):
        pass

    dest = os.path.join(base, 'dest')
    recursive_link(source, dest)
    assert os.path.exists(os.path.join(dest, 'data.txt'))
    assert not os.path.exists(os.path.join(dest, 'link'))
    assert "Removing..." in mock_logger.error.call_args[0][0]
    shutil.rmtree(base)
