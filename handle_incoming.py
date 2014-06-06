#!/usr/bin/env python
# coding: utf8

from __future__ import print_function

import re
import string
import os
import pwd
import grp
import subprocess
import argparse
import time
import sys
import shutil
import ast
import logging
import atexit
import signal
import glob


logger = None


BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
MARKER_NAME = ".MARKER_is_finished_"
IGNORED_FILES = [MARKER_NAME, 'to_openbis', 'manual_intervention',
                 'checksums.txt']


def init_logging(logfile, loglevel, name):
    global logger
    logger = logging.getLogger(name)

    if logfile is not None:
        logging.basicConfig(
            level=getattr(logging, loglevel),
            filename=logfile,
        )
    else:
        logging.basicConfig(
            level=getattr(logging, loglevel),
            stream=sys.stdout,
        )


def read_checksums(string, basedir):
    csums = {}
    for line in string.splitlines():
        csum, name = line.split(maxsplit=1)
        name = ast.literal_eval('"""' + line + '"""')
        csums[basedir / name] = csum
    return csums


def checksums(files, checksums_file, write_checksums=False, force_check=False):
    """ Compute sha256 checksums of all files in ``files``. """
    if not files:
        return

    basedir = os.path.dirname(os.path.abspath(checksums_file))
    files_abs = [os.path.abspath(p) for p in files]
    files_rel = [os.path.relpath(file, basedir) for file in files_abs]

    # read old checksums from checksums_file
    try:
        with open(checksums_file) as f:
            known_sums = read_checksums(f.read(), basedir)
    except OSError:
        known_sums = {}

    # compute real checksums
    real_sums = {}
    csums = subprocess.check_output(
        ['sha256sum'] + files_rel, shell=False, cwd=str(basedir),
        universal_newlines=True,
    )
    real_sums = read_checksums(csums, basedir)

    # check if identical
    for file in files_abs:
        if force_check and file not in known_sums:
            logger.error("Checksum for file {} not known".format(file))
            raise ValueError("Checksum for file {} not known".format(file))
        if file in known_sums and known_sums[file] != real_sums[file]:
            logger.warn("Incorrect checksum for file " + str(file))
            raise ValueError("Invalid checksum for file " + str(file))

    # write all real checksums to file
    if write_checksums:
        with open(checksums_file, 'w') as f:
            f.write(csums)


def is_valid_barcode(barcode):
    if re.fullmatch(BARCODE_REGEX, barcode) is None:
        return False
    csum = sum(ord(c) * (i + 1) for i, c in enumerate(barcode[:-1]))
    csum = csum % 34 + 48
    if csum > 57:
        csum += 7
    return barcode[-1] == chr(csum)


def extract_barcode(path):
    """ Extract a OpenBis barcode from the file name.

    If a barcode is found, return it. Raise ValueError if no barcode,
    or more that one barcode has been found.

    Barcodes must match this regular expression: [A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]
    """
    barcodes = re.findall(BARCODE_REGEX, path.stem)
    barcodes = [b for b in barcodes if is_valid_barcode(b)]
    if not barcodes:
        raise ValueError("no barcodes found")
    if len(barcodes) > 1 and any(b != barcodes[0] for b in barcodes):
        logger.error("More than one barcode in filename")
        raise ValueError("more than one barcode in filename")

    return barcodes[0]


def generate_name(path):
    """ Generate a sane file name from the input file

    Copy the barcode to the front and remove invalid characters.

    Raise ValueError if the filename does not contain a barcode.

    Example
    -------
    >>> path = "stüpid\tname(<QJFDC010EU.).>ä.raw"
    >>> generate_name(path)
    'QJFDC010EU_stpidnameQJFDC010EU.raw'
    """
    barcode = extract_barcode(path)

    allowed_chars = string.ascii_letters + string.digits + '_'

    stem, suffix = os.path.splitext(os.path.basename(path))

    cleaned_stem = ''.join(i for i in stem if i in allowed_chars)
    if not cleaned_stem:
        logger.error("Very strange file name: " + str(path))
        raise ValueError("Invalid file name")

    if not all(i in allowed_chars + '.' for i in suffix):
        logger.error("Got file with invalid chars in suffix: " + str(path))
        raise ValueError("Bad file suffix: " + suffix)

    return barcode + '_' + cleaned_stem + suffix


def get_correct_user_group():
    """ Return userid and groupid that all new files should belong to."""
    user = pwd.getpwuid(os.getuid()).pw_name
    group = user + 'grp'

    userid = os.getuid()
    try:
        groupid = grp.getgrnam(group)
    except KeyError:
        raise ValueError("group {} does not exist".format(group))
    return userid, groupid


def check_input_permissions(path):
    """ Basic sanity check for permissions of incoming files

    This is not a security check, but it should find configuration
    issues of upstream tools.
    """
    userid, groupid = get_correct_user_group()
    error = "invalid file permissions"

    if not os.stat(path).st_uid == userid:
        logger.critical(error)
        raise ValueError("Invalid file owner: " + path)
    if os.stat(path).st_mode % 0o1000 != 0o600:
        logger.critical(error)
        raise ValueError("Invalid file permissions: " + path)


def check_output_permissions(path):
    """ Basic sanity check for permissions of file written by this daemon

    This is not a security check, but it should find configuration
    issues of this tool.
    """
    userid, groupid = get_correct_user_group()
    error = "invalid file permissions"

    if not os.stat(path).st_uid == userid:
        logger.critical(error)
        raise ValueError("Invalid file owner: " + path)
    if not os.stat(path).st_gid == groupid:
        logger.critical(error)
        raise ValueError("Invalid group: " + path)
    if os.path.isdir(path):
        if os.stat(path).st_mode % 0o1000 != 0o770:
            logger.critical(error)
            raise ValueError("Invalid permissions for directory: " + path)
    else:
        if os.stat(path).st_mode % 0o1000 != 0o660:
            logger.critical(error)
            raise ValueError("Invalid file permissions: " + path)


def copy(file, dest, checksums_file=None):
    """ TODO add call to checksums """
    logger.debug("copying file {} to {}".format(file, dest))
    file = os.path.abs(file)
    if os.path.isfile(file):
        copy = shutil.copyfile
    elif os.path.isdir(file):
        copy = shutil.copytree  # TODO uses shutil.copy2, copies mode
    copy(file, dest)
    check_output_permissions(dest)


def to_openbis(file, new_name, checksums_file=None):
    """ Copy this file or directory to the openbis export directory """
    logger.debug("Export {} to OpenBis".format(file))
    file = os.path.abspath(file)
    copy(file, file.parent / 'to_openbis' / new_name,
         checksums_file=checksums_file)


def to_storage(file, new_name, checksums_file=None):
    pass


def to_manual(file, checksums_file=None):
    """ Copy this file or directory to the directory for manual intervention"""
    file = os.path.abspath(file)
    dest = os.path.join(os.path.split(file)[0],
                        'manual_intervention',
                        os.path.basename(file))
    copy(file, dest, checksums_file=None)


def handle_file(basedir, file):
    basedir = os.path.abspath(basedir)
    assert os.path.isdir(basedir)
    checksums_file = os.path.join(basedir, 'checksums.txt')

    try:
        manual_file = False
        logger.debug("processing file " + str(file))
        file = os.path.abspath(file)

        if os.path.isdir(file):
            to_manual(file, checksums_file=checksums_file)
            manual_file = True

        else:
            try:
                new_name = generate_name(file)
            except ValueError:
                to_manual(file, checksums_file=checksums_file)
                manual_file = True
            else:
                to_storage(file, new_name, checksums_file=checksums_file)
                to_openbis(file, new_name, checksums_file=checksums_file)

        if manual_file:
            logger.critical("manual intervention is required for a file")
    except Exception:
        logger.exception("An error occured while moving files: ")
        (basedir / 'ERROR').touch()
        raise
    else:
        logger.debug("Removing file " + str(file))
        if os.path.isfile(file):
            os.remove(file)
        elif os.path.isfile(file):
            shutil.rmtree(str(file))
        else:
            logger.error("Could not remove file " + file)


def listen(path, interval):
    """ Listen for tasks in ``path``.

    Check for a marker file in ``path`` every ``interval`` seconds. If new
    files are found, check their permissions, write their checksums to
    ``checksums.txt`` and sort them into apropriate subdirs.
    """
    logger.info("Starting to listen in " + str(path))
    os.chdir(str(path))
    ignored_files = [os.path.join(path, file) for file in IGNORED_FILES]
    while True:
        for marker in glob.glob(MARKER_NAME + '*'):
            file = marker[len(MARKER_NAME):]
            if not os.path.exists(file):
                logger.error("Marker {} exists, but {} does not"
                             .format(marker, file))
            if file in ignored_files:
                continue
            try:
                logger.info("New file arrived: " + file)
                check_input_permissions(file)
                """
                try:
                    checksums(
                        [file],
                        checksums_file=os.path.join(path, 'checksums.txt'),
                        write_checksums=True
                    )
                except ValueError:
                    with open('CHECKSUMS_DO_NOT_MATCH', 'w'):
                        pass
                    raise ValueError("Invalid checksums")
                """

                handle_file(path, file)
                logger.info("Finished processing file. Cleaning up")
                try:
                    os.remove(marker)
                except OSError:
                    logger.error("Marker file vanished: " + marker)
            except Exception:
                logger.exception("An unexpected error:")
        time.sleep(interval)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Watch for new files in " +
                    "dropbox and move to ObenBis/storage"
    )
    parser.add_argument(
        'dropboxdir',
        help='the dropbox directory in which new files appear'
    )
    parser.add_argument(
        '-t', help="interval [s] between checks for " +
                   "new files (may be removed in the future)",
        default=600, type=int)
    parser.add_argument(
        '--no-check-permissions',
        help="do not check permissions of input and output files",
        dest='check_permissions', action='store_false', default=True
    )
    parser.add_argument('--logfile', default=None)
    parser.add_argument('--loglevel', default='INFO')
    parser.add_argument('-d', '--daemon', default=False, action='store_true')
    parser.add_argument('--pid-file', default='~/.handle_incoming.pid')
    return parser.parse_args()


def daemonize(func, pidfile, *args, **kwargs):
    """ Run ``func`` in new process independent from this one.

    Write the pid of the new daemon to pidfile.
    """
    logger.info("Starting new daemon")
    os.chdir('/')
    try:
        pid = os.fork()
    except OSError:
        print("Fork failed.", file=sys.stderr)
        sys.exit(1)
    if pid:
        os._exit(0)

    # new process group
    os.setsid()

    try:
        pid = os.fork()
    except OSError:
        print("Fork failed.", file=sys.stderr)
        sys.exit(1)

    if pid:
        os._exit(0)

    def handler(signal, frame):
        raise SystemExit()

    logger.info("PID of new daemon: " + str(os.getpid()))

    signal.signal(signal.SIGTERM, handler)

    pidfile = os.path.expanduser(str(pidfile))

    # open(file, 'x') not available in python 2.6
    if os.path.exists(pidfile):
        print("Pidfile exists. Is another daemon running?")
        sys.exit(1)

    try:
        with open(pidfile, 'w') as f:
            f.write(str(os.getpid()) + '\n')
    except OSError:
        print("Could not write pidfile. Is another daemon running?",
              file=sys.stderr)
        sys.exit(1)

    atexit.register(lambda: os.remove(pidfile))

    func(*args, **kwargs)


def main():
    args = parse_args()
    path = os.path.abspath(args.dropboxdir)
    if not os.path.exists(path):
        print("Could not find dropboxdir", file=sys.stderr)
    init_logging(args.logfile, args.loglevel, os.path.basename(path))

    # overwrite permission checking by stubs
    if not args.check_permissions:
        global check_input_permissions, check_output_permissions
        global get_correct_user_group
        check_output_permissions = lambda x: None
        check_input_permissions = lambda x: None
        get_correct_user_group = lambda: (0, 0)

    # sanity checks for dropboxdir
    if not os.path.isdir(path):
        print(args.dropboxdir + " is not a directory", file=sys.stderr)
        sys.exit(1)
    try:
        check_output_permissions(path)
    except ValueError:
        print("dropboxdir has invalid permissions", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(os.path.join(path, 'to_openbis')):
        print("dropboxdir must contain dir 'to_openbis'", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(os.path.join(path, 'manual_intervention')):
        print("dropboxdir must contain dir 'manual_intervention'",
              file=sys.stderr)
        sys.exit(1)

    # set group and permissions for new files
    userid, groupid = get_correct_user_group()
    try:
        if args.check_permissions:
            os.setgid(groupid)
        os.umask(0o117)
    except Exception:
        print("Could not change to group " + str(groupid))
        sys.exit(1)

    # start checking for new files
    if args.daemon:
        daemonize(listen, args.pid_file, path, args.t)
    else:
        listen(path, args.t)


if __name__ == '__main__':
    main()
