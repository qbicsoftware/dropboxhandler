#!/usr/bin/env python
# coding: utf8

from __future__ import print_function

import re
import pathlib
import string
import os
import pwd
import grp
import stat
import subprocess
import argparse
import time
import sys
import shutil
import ast
import logging
import atexit
import signal


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
            level=loglevel,
            filename=logfile,
        )
    else:
        logging.basicConfig(
            level=loglevel,
            stream=sys.stdout,
        )


def read_checksums(string, basedir):
    basedir = pathlib.Path(basedir)
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

    checksums_file = pathlib.Path(checksums_file)
    basedir = checksums_file.parent.resolve()
    files = [str(p) for p in files]
    files_abs = [pathlib.Path(p).resolve() for p in files]
    files_rel = [str(file.relative_to(basedir)) for file in files_abs]

    # read old checksums from checksums_file
    try:
        with checksums_file.open() as f:
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
        with checksums_file.open('w') as f:
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
    path = pathlib.Path(path)
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
    path = pathlib.Path(path)
    barcode = extract_barcode(path)

    allowed_chars = string.ascii_letters + string.digits + '_'

    cleaned_stem = ''.join(i for i in path.stem if i in allowed_chars)
    if not cleaned_stem:
        logger.error("Very strange file name: " + str(path))
        raise ValueError("Invalid file name")

    if not all(i in allowed_chars + '.' for i in path.suffix):
        logger.error("Got file with invalid chars in suffix: " + str(path))
        raise ValueError("Bad file suffix: " + path.suffix)

    return barcode + '_' + cleaned_stem + path.suffix


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
    path = pathlib.Path(path)
    userid, groupid = get_correct_user_group()
    error = "invalid file permissions"

    if not path.stat().st_uid == userid:
        logger.critical(error)
        raise ValueError("Invalid file owner: " + str(path))
    if path.stat().st_mode % 0o1000 != 0o600:
        logger.critical(error)
        raise ValueError("Invalid file permissions: " + str(path))


def check_output_permissions(path):
    """ Basic sanity check for permissions of file written by this daemon

    This is not a security check, but it should find configuration
    issues of this tool.
    """
    path = pathlib.Path(path)
    userid, groupid = get_correct_user_group()
    error = "invalid file permissions"

    if not path.stat().st_uid == userid:
        logger.critical(error)
        raise ValueError("Invalid file owner: " + str(path))
    if not path.stat().stat.st_gid == groupid:
        logger.critical(error)
        raise ValueError("Invalid group: " + str(path))
    if path.stat().st_mode % 0o1000 != 0o660:
        logger.critical(error)
        raise ValueError("Invalid file permissions: " + str(path))


def copy(file, dest, checksums_file=None):
    """ TODO add call to checksums """
    logger.debug("copying file {} to {}".format(file, dest))
    file = pathlib.Path(file).resolve()
    if file.is_file():
        copy = shutil.copyfile
    elif file.is_dir():
        copy = shutil.copytree  # TODO uses shutil.copy2, copies mode
    copy(str(file), str(dest))
    check_output_permissions(dest)


def to_openbis(file, new_name, checksums_file=None):
    """ Copy this file or directory to the openbis export directory """
    logger.debug("Export {} to OpenBis".format(file))
    file = pathlib.Path(file).resolve()
    copy(file, file.parent / 'to_openbis' / new_name,
         checksums_file=checksums_file)


def to_storage(file, new_name, checksums_file=None):
    pass


def to_manual(file, checksums_file=None):
    """ Copy this file or directory to the directory for manual intervention"""
    file = pathlib.Path(file).resolve()
    copy(file, file.parent / 'manual_intervention' / file.name,
         checksums_file=None)


def call_openbis(basedir):
    """ Tell OpenBis that new files in 'to_openbis' are ready"""
    (pathlib.Path(basedir) / 'to_openbis' / MARKER_NAME).touch()


def handle_files(basedir, files):
    basedir = pathlib.Path(basedir).resolve()
    checksums_file = basedir / 'checksums.txt'
    assert basedir.is_dir()

    try:
        openbis_files = False
        manual_files = False
        for file in files:
            logger.debug("processing file " + str(file))
            file = file.resolve()

            if file.is_dir():
                to_manual(file, checksums_file=checksums_file)
                manual_files = True
                continue

            try:
                new_name = generate_name(file)
            except ValueError:
                to_manual(file, checksums_file=checksums_file)
                manual_files = True
            else:
                to_storage(file, new_name, checksums_file=checksums_file)
                to_openbis(file, new_name, checksums_file=checksums_file)
                openbis_files = True

        if openbis_files:
            call_openbis(basedir)
        if manual_files:
            logger.critical("manual intervention is required for some files")
    except Exception:
        logger.exception("An error occured while moving files: ")
        (basedir / 'ERROR').touch()
        raise
    else:
        for file in files:
            logger.debug("Removing file " + str(file))
            if file.is_file():
                file.unlink()
            elif file.is_dir():
                shutil.rmtree(str(file))


def listen(path, interval):
    """ Listen for tasks in ``path``.

    Check for a marker file in ``path`` every ``interval`` seconds. If new
    files are found, check their permissions, write their checksums to
    ``checksums.txt`` and sort them into apropriate subdirs.
    """
    logger.info("Starting to listen in " + str(path))
    os.chdir(str(path))
    ignored_files = [path / file for file in IGNORED_FILES]
    while True:
        if (path / MARKER_NAME).exists():
            files = [f for f in path.iterdir() if f not in ignored_files]
            try:
                logger.info("New set of files arrived")
                for file in files:
                    check_input_permissions(file)
                try:
                    checksums(files, checksums_file=path / 'checksums.txt',
                              write_checksums=True)
                except ValueError:
                    (path / 'CHECKSUMS_DO_NOT_MATCH').touch()
                    raise ValueError("Invalid checksums")

                handle_files(path, files)
                logger.info("Finished processing files. Cleaning up")
                if (path / MARKER_NAME).exists():
                    (path / MARKER_NAME).unlink()
                if (path / 'checksums.txt').exists():
                    (path / 'checksums.txt').unlink()
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

    try:
        with open(pidfile, 'x') as f:
            f.write(str(os.getpid()) + '\n')
    except OSError:
        print("Could not write pidfile. Is another daemon running?",
              file=sys.stderr)
        sys.exit(1)

    atexit.register(lambda: os.remove(pidfile))

    func(*args, **kwargs)


def main():
    args = parse_args()
    try:
        path = pathlib.Path(args.dropboxdir).resolve()
    except OSError:
        print("Could not find dropboxdir", file=sys.stderr)
    init_logging(args.logfile, args.loglevel, path.stem)

    # overwrite permission checking by stubs
    if not args.check_permissions:
        global check_input_permissions, check_output_permissions
        global get_correct_user_group
        check_output_permissions = lambda x: None
        check_input_permissions = lambda x: None
        get_correct_user_group = lambda: (0, 0)

    # sanity checks for dropboxdir
    if not path.is_dir():
        print(args.dropboxdir + " is not a directory", file=sys.stderr)
        sys.exit(1)
    try:
        check_output_permissions(path)
    except ValueError:
        print("dropboxdir has invalid permissions", file=sys.stderr)
        sys.exit(1)

    if not (path / 'to_openbis').is_dir():
        print("dropboxdir must contain dir 'to_openbis'", file=sys.stderr)
        sys.exit(1)
    if not (path / 'manual_intervention').is_dir():
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
