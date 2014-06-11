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
import logging
import atexit
import signal
import glob


logger = None

BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
MARKER_NAME = ".MARKER_is_finished_"
IGNORED_FILES = ['to_openbis', 'manual_intervention']


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


def checksum(file, write_checksum=True):
    """ Check ckecksums if available and write new checksums if not.

    Checksums will be written to <inputfile>.sha256 in the
    format of the sha256sum tool.

    If file is a directory, the checksum file will include the
    checksums of all files in that dir.
    """

    basedir = os.path.split(file)[0]
    checksum_file = str(file) + '.sha256'
    if os.path.exists(checksum_file):
        subprocess.check_call(
            ['sha256sum', '-c', '--', checksum_file],
            cwd=basedir,
        )
    if not write_checksum:
        return

    files = subprocess.check_output(
        [
            'find',
            str(file),
            '-type', 'f',
            '-print0'
        ],
        cwd=basedir,
    ).split(b'\0')[:-1]

    with open(checksum_file, 'wb') as f:
        for file in files:
            csum_line = subprocess.check_output(
                ['sha256sum', '-b', '--', file],
                cwd=basedir,
            )
            csum, _ = csum_line.split(maxsplit=1)
            base, ext = os.path.splitext(file)

            if not len(csum) == 64:
                raise TypeError('Could not parse sha256sum output')

            f.write(csum_line)


def is_valid_barcode(barcode):
    """ Check if barcode is a valid OpenBis barcode """
    if re.match('^' + BARCODE_REGEX + '$', barcode) is None:
        return False
    csum = sum(ord(c) * (i + 1) for i, c in enumerate(barcode[:-1]))
    csum = csum % 34 + 48
    if csum > 57:
        csum += 7
    if barcode[-1] == chr(csum):
        return True
    logging.error("got invalid barcode: %s", barcode)
    return False


def extract_barcode(path):
    """ Extract a OpenBis barcode from the file name.

    If a barcode is found, return it. Raise ValueError if no barcode,
    or more that one barcode has been found.

    Barcodes must match this regular expression: [A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]
    """
    stem, suffix = os.path.splitext(os.path.basename(path))
    barcodes = re.findall(BARCODE_REGEX, stem)
    barcodes = [b for b in barcodes if is_valid_barcode(b)]
    if not barcodes:
        raise ValueError("no barcodes found")
    if len(barcodes) > 1 and any(b != barcodes[0] for b in barcodes):
        logger.error("More than one barcode in filename")
        raise ValueError("more than one barcode in filename")

    return barcodes[0]


def clean_filename(path):
    """ Generate a sane filename for path. """
    allowed_chars = string.ascii_letters + string.digits + '_'
    stem, suffix = os.path.splitext(os.path.basename(path))
    cleaned_stem = ''.join(i for i in stem if i in allowed_chars)
    if not cleaned_stem:
        logger.error("Can not clean names without legal chars")
        raise ValueError("Invalid file name: %s", stem + suffix)

    if not all(i in allowed_chars + '.' for i in suffix):
        logger.error("Got file with invalid chars in suffix: " + str(path))
        raise ValueError("Bad file suffix: " + suffix)

    return cleaned_stem + suffix


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
    cleaned_name = clean_filename(path)
    return barcode + '_' + cleaned_name


def get_output_user_group():
    """ Return userid and groupid that all new files should belong to."""
    user = pwd.getpwuid(os.getuid()).pw_name
    group = user + 'grp'

    userid = os.getuid()
    try:
        groupid = grp.getgrnam(group).gr_gid
    except KeyError:
        raise ValueError("group %s does not exist" % group)
    return userid, groupid


def _check_perms(path, userid, groupid, dirmode, filemode):
    if not os.stat(path).st_uid == userid:
        logger.critical("userid of file %s should be %s but is %s",
                        path, userid, os.stat(path).st_uid)
    if not os.stat(path).st_gid == groupid:
        logger.critical("groupid of file %s should be %s but is %s",
                        path, groupid, os.stat(path).st_gid)
    if os.path.isdir(path):
        if os.stat(path).st_mode % 0o1000 != dirmode:
            logger.critical("mode of dir %s should be %s but is %s",
                            path, dirmode, os.stat(path).st_mode)
    elif os.path.islink(path):
        logging.critical("symbolic links are not allowed: %s", path)
    elif os.path.isfile(path):
        if os.stat(path).st_mode % 0o1000 != filemode:
            logger.critical("mode of file %s should be %s but is %s",
                            path, filemode, os.stat(path).st_mode)
    else:
        logger.critical("should be a regular file or dir: %s", path)


def check_input_permissions(path):
    """ Basic sanity check for permissions of incoming files

    This exists to find configuration issues only.

    Will not raise errors, but write them to logger.
    """
    userid, groupid = get_output_user_group()

    if os.path.isdir(path):
        for path, dirnames, filenames in os.walk(path):
            _check_perms(path, userid, groupid, 0o700, 0o600)
            for name in filenames:
                _check_perms(os.path.join(path, name),
                             userid, groupid, 0o700, 0o600)


def check_output_permissions(path):
    """ Basic sanity check for permissions of file written by this daemon

    This exists to find configuration issues only.

    Will not raise errors, but write them to logger.
    """
    userid, groupid = get_output_user_group()

    if os.path.isdir(path):
        for path, dirnames, filenames in os.walk(path):
            _check_perms(path, userid, groupid, 0o770, 0o660)
            for name in filenames:
                _check_perms(os.path.join(path, name),
                             userid, groupid, 0o770, 0o660)


def init_signal_handler():
    def handler(sig, frame):
        if sig == signal.SIGTERM:
            logging.info("Daemon got SIGTERM. Shutting down.")
            sys.exit(1)
        elif sig == signal.SIGCONT:
            logging.info("Daemon got SIGCONT. Continuing.")
        else:
            logging.error("Signal handler did not expect to get %s", sig)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGCONT, handler)


def run_rsync(source, dest):
    if os.path.isdir(source) and source[-1] != '/':
        source = source + '/'

    userid, groupid = get_output_user_group()
    rsync = subprocess.Popen(
        [
            'rsync',
            '--timeout=500',  # timeout if no IO for 500 s
            '--safe-links',  # symlinks outside tree are a security issue
            '--checksum',
            '--recursive',
            '--itemize-changes',  # return list of changed files
            '--no-group',  # set by chown
            '--perms',  # or else chmod does not get applied
            '--chmod=Dug+rwx,Do-rwx,Fug+rw,Fo-rwx',
            #'--numeric-ids',
            #'--chown=%s:%s' % (userid, groupid),
            '--link-dest=%s' % source,  # Should be removed if dest on other fs
            '--',  # end options, in case files start with '-'
            str(source),
            str(dest),
        ],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=False,
    )
    out, err = rsync.communicate()
    changed = out.decode()
    if err != b'':
        logging.error("Stderr of rsync: %s", err.decode())
    if rsync.returncode:
        raise subprocess.IOError(
            "Error executing rsync. error code %s" % rsync.returncode
        )

    return changed


def copy(file, dest, checksums=True, maxtries=2):
    """ Copy dir or file ``file`` to dest.

    shutil has a couple of security issues in its copy functions:
    http://bugs.python.org/issue15100
    Using ``/usr/bin/rsync`` instead.
    """
    file = os.path.abspath(file)
    dest = os.path.abspath(dest)
    logger.debug("copying file %s to %s", file, dest)

    if os.path.exists(dest):
        logger.critical("Destination file exists: %s", dest)
        raise ValueError("Destination file exists: %s", dest)

    # just for better error message. Real check in rsync
    if os.path.islink(file):
        logger.critical('Symbolic links in "incoming" are not allowed')
        raise ValueError('Not allowed to copy links')
    if not (os.path.isdir(file) or os.path.isfile(file)):
        logger.critical('Can only copy files or directories')
        raise ValueError("Invalid file to copy: %s", file)

    check_input_permissions(file)
    changed = True
    for i in range(maxtries + 1):
        if not changed:
            break

        changed = run_rsync(file, dest)

        if i != 0 and changed:
            logging.info("Bit errors while copying the following files: \n%s",
                         changed)
    else:
        logging.error("Retried copying and checksums still differ " +
                      "for files:\n%s", changed.decode())
        raise OSError("Bit errors while copying")
    check_output_permissions(dest)


def to_openbis(file, new_name, checksums=True):
    """ Copy this file or directory to the openbis export directory """
    logger.debug("Export %s to OpenBis", file)
    file = os.path.abspath(file)
    dest = os.path.join(os.path.split(file)[0],
                        'to_openbis',
                        new_name)
    copy(file, dest, checksums=checksums)

    # tell openbis that we are finished copying
    base, name = os.path.split(dest)
    with open(os.path.join(base, MARKER_NAME + name), 'w'):
        pass


def to_storage(file, new_name, checksums=True):
    pass


def to_manual(file, checksums=True):
    """ Copy this file or directory to the directory for manual intervention"""
    file = os.path.abspath(file)
    dest = os.path.join(os.path.split(file)[0],
                        'manual_intervention',
                        os.path.basename(file))
    copy(file, dest, checksums=checksums)
    checksum(dest)


def handle_file(basedir, file):
    basedir = os.path.abspath(basedir)
    assert os.path.isdir(basedir)

    try:
        manual_file = False
        logger.debug("processing file " + str(file))
        file = os.path.abspath(file)

        if os.path.isdir(file):
            to_manual(file, checksums=True)
            manual_file = True

        else:
            try:
                new_name = generate_name(file)
            except ValueError:
                to_manual(file, checksums=True)
                manual_file = True
            else:
                to_storage(file, new_name, checksums=True)
                to_openbis(file, new_name, checksums=True)

        if manual_file:
            logger.info("manual intervention is required for %s", file)
    except Exception:
        logger.exception("An error occured while moving files: ")
        with open(os.path.join(basedir, 'ERROR'), 'w'):
            pass
        raise
    else:
        logger.debug("Removing file " + str(file))
        if os.path.isfile(file):
            os.unlink(file)
        elif os.path.isdir(file):
            shutil.rmtree(str(file))
        else:
            logger.error("Could not remove file " + file)


def listen(path, interval):
    """ Listen for tasks in ``path``.

    Check for a marker file in ``path`` every ``interval`` seconds. If new
    files are found, check their permissions, write their checksums to
    ``checksums.txt`` and sort them into apropriate subdirs.
    """
    init_signal_handler()
    logger.info("Starting to listen in " + str(path))
    os.chdir(str(path))
    ignored_files = [os.path.join(path, file) for file in IGNORED_FILES]
    while True:
        for marker in glob.glob(MARKER_NAME + '*'):
            try:
                logging.debug("Found new marker file: %s", marker)
                file = marker[len(MARKER_NAME):]
                if not os.path.exists(file):
                    logger.critical("Marker %s exists, but %s does not",
                                    marker, file)
                    raise ValueError("Marker %s without file" % marker)
                if file in ignored_files:
                    logging.debug("ignoring file: %s", file)
                    continue
                logger.info("New file arrived: %s", file)
                handle_file(path, file)
                logger.info("Finished processing file. Cleaning up")
                try:
                    os.remove(marker)
                except OSError:
                    logger.error("Could not remove marker file " + marker)
            except Exception:
                logger.critical(
                    "An unexpected error occured during handeling of file %s",
                    file
                )
                logger.exception("Error was:")
                logger.critical("This daemon will now suspend itself and " +
                                " wait for human intervention. To restart, " +
                                "please execute `kill -CONT %s`. To exit, " +
                                "execute `kill %s`", os.getpid(), os.getpid())

                # Should use signal.sigwaitinfo, but this is not available
                # for py < 3.3
                signal.pause()
        time.sleep(interval)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Watch for new files in " +
                    "dropboxdir and move to ObenBis/storage"
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
        '--no-permissions',
        help="do not set and check permissions of input and output files",
        dest='permissions', action='store_false', default=True
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

    logger.info("PID of new daemon: " + str(os.getpid()))
    pidfile = os.path.expanduser(str(pidfile))

    # open(file, 'x') not available in python 2.6
    if os.path.exists(pidfile):
        print("Pidfile %s exists. Is another daemon running?" % pidfile,
              file=sys.stderr)
        sys.exit(1)

    try:
        with open(pidfile, 'w') as f:
            f.write(str(os.getpid()) + '\n')
    except OSError:
        print("Could not write pidfile %s. Is another " +
              "daemon running?" % pidfile,
              file=sys.stderr)
        sys.exit(1)

    atexit.register(lambda: os.remove(pidfile))

    func(*args, **kwargs)


def set_write_permissions():
    # set group and permissions for new files
    userid, groupid = get_output_user_group()
    try:
        os.setgid(groupid)
        os.umask(0o007)
    except Exception:
        print("Could not change to group " + str(groupid))
        sys.exit(1)


def check_dropboxdir(path):
    """ sanity checks for dropboxdir. """
    if not os.path.isdir(path):
        print(str(path) + " is not a directory", file=sys.stderr)
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


def main():
    args = parse_args()
    path = os.path.abspath(args.dropboxdir)
    if not os.path.exists(path):
        print("Could not find dropboxdir", file=sys.stderr)
        sys.exit(1)

    if args.permissions:
        set_write_permissions()
    else:
        # overwrite permission checking by stubs
        global check_input_permissions, check_output_permissions
        global get_output_user_group
        check_output_permissions = lambda x: None
        check_input_permissions = lambda x: None
        get_output_user_group = lambda: (1000, 1000)

    check_dropboxdir(path)

    init_logging(args.logfile, args.loglevel, "handle_incoming %s" % path)

    try:
        # start checking for new files
        if args.daemon:
            daemonize(listen, args.pid_file, path, args.t)
        else:
            listen(path, args.t)
    except Exception:
        logging.critical("Daemon is shutting down for unknown reasons")
        logging.exception('Error was:')
        sys.exit(1)


if __name__ == '__main__':
    main()
