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
import sys
import time
import shutil
import logging
import logging.config
import atexit
import signal
import glob
import traceback
import stat
import tempfile
import concurrent.futures
from . import fscall
from os.path import join as pjoin
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

if not hasattr(__builtins__, 'FileExistsError'):
    FileExistsError = OSError

logger = None

BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
FINISHED_MARKER = ".MARKER_is_finished_"
ERROR_MARKER = "MARKER_error_"
STARTED_MARKER = "MARKER_started_"


# python 2.6 compat
if not hasattr(subprocess, 'check_output'):
    def check_output(*args, **kwargs):
        kwargs['stdout'] = subprocess.PIPE
        try:
            proc = subprocess.Popen(*args, **kwargs)
            stdout, stderr = proc.communicate()
        except:
            proc.kill()
            proc.wait()
            raise
        retcode = proc.poll()
        if retcode:
            raise subprocess.CalledProcessError(
                retcode, list(args[0])
            )
        return stdout

    subprocess.check_output = check_output


# python2 does not allow open(..., mode='x')
def create_open(path):
    if sys.version_info < (3, 3):
        fd = os.open(path, os.O_CREAT | os.O_NOFOLLOW | os.O_WRONLY)
        try:
            file = os.fdopen(fd, 'w')
        except OSError:
            os.close(fd)
            raise
        else:
            return file
    else:
        return open(path, mode='x')


def touch(path):
    with create_open(path):
        pass


def is_old(path):
    """ Test if path has been modified during the last 5 days. """
    modified = os.stat(path).st_mtime
    age_seconds = time.time() - modified
    if age_seconds > 60 * 60 * 24 * 5:  # 5 days
        return True


def init_logging(options):
    global logger

    if 'logfile' in options:
        logging.basicConfig(
            level=getattr(logging, options['loglevel']),
            filename=options['logfile'],
        )
    else:
        logging.basicConfig(
            level=getattr(logging, options['loglevel']),
            stream=sys.stdout,
        )

    if options['use_conf_file_logging']:
        try:
            logging.config.fileConfig(options['conf_file'],
                                      disable_existing_loggers=True)
        except Exception as e:
            print("Could not load logging information from config file", e,
                  file=sys.stderr)

    logger = logging.getLogger('dropboxhandler')


def message_to_admin(message):
    pass


def write_checksum(file):
    """ Compute checksums of file or of contents if it is a dir.

    Checksums will be written to <inputfile>.sha256 in the
    format of the sha256sum tool.

    If file is a directory, the checksum file will include the
    checksums of all files in that dir.
    """
    file = os.path.abspath(file)
    basedir = os.path.split(file)[0]
    checksum_file = str(file) + '.sha256'

    files = subprocess.check_output(
        [
            'find',
            os.path.basename(file),
            '-type', 'f',
            '-print0'
        ],
        cwd=basedir,
    ).split(b'\0')[:-1]

    if not files:
        raise ValueError("%s has no files to checksum" % file)

    try:
        with open(checksum_file, 'wb') as f:
            for file in files:
                csum_line = subprocess.check_output(
                    ['sha256sum', '-b', '--', file],
                    cwd=basedir,
                )
                csum = csum_line.split()[0]
                base, ext = os.path.splitext(file)

                if not len(csum) == 64:
                    raise ValueError('Could not parse sha256sum output')

                f.write(csum_line)
    except OSError:
        logging.exception('Could not write checksum file. Does it exist?')
        raise


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
    return False


def extract_barcode(path):
    """ Extract an OpenBis barcode from the file name.

    If a barcode is found, return it. Raise ValueError if no barcode,
    or more that one barcode has been found.

    Barcodes must match this regular expression: [A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]
    """
    stem, suffix = os.path.splitext(os.path.basename(path))
    barcodes = re.findall(BARCODE_REGEX, stem)
    barcodes = [b for b in barcodes if is_valid_barcode(b)]
    if not barcodes:
        raise ValueError("no barcodes found")
    if len(set(barcodes)) > 1:
        raise ValueError("more than one barcode in filename")
    return barcodes[0]


def clean_filename(path):
    """ Generate a sane (alphanumeric) filename for path. """
    allowed_chars = string.ascii_letters + string.digits + '_'
    stem, suffix = os.path.splitext(os.path.basename(path))
    cleaned_stem = ''.join(i for i in stem if i in allowed_chars)
    if not cleaned_stem:
        raise ValueError("Invalid file name: %s", stem + suffix)

    if not all(i in allowed_chars + '.' for i in suffix):
        raise ValueError("Bad file suffix: " + suffix)

    return cleaned_stem + suffix.lower()


def generate_openbis_name(path):
    """ Generate a sane file name from the input file

    Copy the barcode to the front and remove invalid characters.

    Raise ValueError if the filename does not contain a barcode.

    Example
    -------
    >>> path = "stüpid\tname(<QJFDC010EU.).>ä.raW"
    >>> generate_openbis_name(path)
    'QJFDC010EU_stpidname.raw'
    """
    barcode = extract_barcode(path)
    path = path.replace(barcode, "")
    cleaned_name = clean_filename(path)
    return barcode + '_' + cleaned_name


def _check_perms(path, userid, groupid, dirmode, filemode):
    if userid and os.stat(path).st_uid != userid:
        raise ValueError("userid of file %s should be %s but is %s" %
                         (path, userid, os.stat(path).st_uid))
    if groupid and os.stat(path).st_gid != groupid:
        raise ValueError("groupid of file %s should be %s but is %s" %
                         (path, groupid, os.stat(path).st_gid))

    if os.path.isdir(path):
        if os.stat(path).st_mode % 0o1000 != dirmode:
            raise ValueError("mode of dir %s should be %o but is %o" %
                             (path, dirmode, os.stat(path).st_mode % 0o1000))
    elif os.path.islink(path):
        raise ValueError("symbolic links are not allowed: %s" % path)
    elif os.path.isfile(path):
        if os.stat(path).st_mode % 0o1000 != filemode:
            raise ValueError("mode of file %s should be %o but is %o" %
                             (path, filemode, os.stat(path).st_mode % 0o1000))
    else:
        raise ValueError("should be a regular file or dir: %s" % path)


def check_permissions(path, userid, groupid, dirmode, filemode):
    """ Basic sanity check for permissions of file written by this daemon.

    Raises ValueError, if permissions are not as specified, or for files
    that are not regular files or directories.
    """
    _check_perms(path, userid, groupid, dirmode, filemode)
    for path, dirnames, filenames in os.walk(path):
        _check_perms(path, userid, groupid, dirmode, filemode)
        for name in filenames:
            _check_perms(os.path.join(path, name),
                         userid, groupid, dirmode, filemode)


def init_signal_handler():
    def handler(sig, frame):
        if sig == signal.SIGTERM:
            logger.info("Daemon got SIGTERM. Shutting down.")
            sys.exit(0)
        elif sig == signal.SIGCONT:
            logger.info("Daemon got SIGCONT. Continuing.")
        elif sig == signal.SIGINT:
            logger.info("Daemon got SIGINT. Shutting down.")
            sys.exit(0)
        else:
            logger.error("Signal handler did not expect to get %s", sig)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGCONT, handler)
    signal.signal(signal.SIGINT, handler)


def recursive_link(source, dest, tmpdir=None, perms=None):
    source = os.path.abspath(source)
    dest = os.path.abspath(dest)
    if os.path.exists(dest):
        raise ValueError("File exists: %s" % dest)
    destbase, destname = os.path.split(dest)
    if destname.startswith(FINISHED_MARKER):
        logger.error("Can not copy to destination that looks like a marker")
        raise ValueError("Illegal destination file: %s", dest)

    tmpdir = tempfile.mkdtemp(dir=tmpdir)
    workdest = os.path.join(tmpdir, destname)

    logger.debug("Linking files in %s to workdir %s", source, workdest)

    command = [
        'cp',
        '--link',
        '--no-dereference',  # symbolic links could point anywhere
        '--recursive',
        '--no-clobber',
        '--',
        str(source),
        str(workdest),
    ]

    try:
        subprocess.check_call(command, shell=False)

        # remove symlinks from output
        # os.fwalk would be better, but not for py<3.3
        for root, dirs, files in os.walk(workdest):
            for file in dirs + files:
                path = os.path.join(root, file)
                stats = os.lstat(path)
                if stat.S_IFMT(stats.st_mode) == stat.S_IFLNK:
                    raise ValueError(
                        "Symbolic links are not allowed. %s is a link to %s" %
                        (path, os.readlink(path))
                    )

        if perms is not None:
            logger.debug("Checking permissions: %s", perms)
            check_permissions(workdest, **perms)

        logger.debug("Created links in workdir. Moving to destination")
        # TODO race condition
        if os.path.exists((dest)):
            raise ValueError("Destination exists: %s", dest)
        os.rename(workdest, dest)
    except:  # even for SystemExit
        logger.error("Got exception before we finished copying files. " +
                     "Rolling back changes")
        if os.path.exists(dest):
            shutil.rmtree(dest)
        raise
    finally:
        shutil.rmtree(tmpdir)


class FileHandler(concurrent.futures.ThreadPoolExecutor):

    """ Handle incoming files.

    Parameters
    ----------
    target_dirs: dict
        A dictionary containing the paths to output directories. Must
        have the keys `storage`, `manual` and optionally `msconvert`.
    openbis_dropboxes: list
        A list of pairs (regexp, path). Incoming files that contain
        a valid QBiC barcode will be stored in the path with the first
        matching regexp. If no regexp matches, throw an error.
    tmpdir: path, optional
        A basepath for temporary files. Must be on the same filesystem
        as the source and target directories. Default is system
        default temp directory.
    perms: dict, optional
        A dict with keys `userid`, `groupid`, `filemode` and `dirmode`.
        Input files that do not match these will throw an error.
    """

    def __init__(self, openbis_dropboxes, storage, manual,
                 msconvert=None, tmpdir=None, perms=None, max_workers=5):
        super(FileHandler, self).__init__(max_workers)
        self._openbis_dropboxes = openbis_dropboxes
        self._storage_dir = storage
        self._manual_dir = manual
        self._msconvert_dir = msconvert
        self._tmpdir = tmpdir
        self._perms = perms

    def _find_openbis_dest(self, name):
        for regexp in self._openbis_dropboxes:
            path = self._openbis_dropboxes[regexp]
            if re.match(regexp, name):
                logger.debug("file %s matches regex %s", name, regexp)
                return os.path.join(path, name)
        logger.error("File with barcode, but does not match " +
                     "an openbis dropbox: %s", name)
        raise ValueError('No known openbis dropbox for file %s' % name)

    def to_openbis(self, file):
        """ Sort this file or directory to the openbis dropboxes.

        If the filename does not include an openbis barcode, raise ValueError.
        file, openbis_dir and tmpdir must all be on the same file system.
        Two additional files will be created: `{name}.origlabfilename`,
        that contains the original name of the file; and `{}.sha256sum`, that
        contains a checksum of the new file or directory.
        """
        file = os.path.abspath(file)

        base, orig_name = os.path.split(file)

        openbis_name = generate_openbis_name(file)
        logger.info("Exporting %s to OpenBis as %s", file, openbis_name)

        dest = self._find_openbis_dest(openbis_name)
        dest_dir = os.path.split(dest)[0]
        logger.info("Write file to openbis dropbox %s" % dest_dir)

        recursive_link(file, dest, tmpdir=self._tmpdir, perms=self._perms)

        labname_file = "%s.origlabfilename" % openbis_name
        with create_open(os.path.join(dest_dir, labname_file)) as f:
            f.write(orig_name)

        write_checksum(dest)

        # tell openbis that we are finished copying
        for name in [openbis_name]:
            marker = os.path.join(dest_dir, FINISHED_MARKER + name)
            with create_open(marker):
                pass

    def to_storage(self, file):
        """Store file in a subdir of storage_dir with the name of the project.

        The first 4 letters of the barcode are the project name. If no barcode
        is found, it will use the name 'other'.
        """
        file = os.path.abspath(file)

        try:
            project = extract_barcode(file)[:5]
            name = generate_openbis_name(file)
        except ValueError:
            project = 'other'
            name = clean_filename(file)

        dest = os.path.join(self._storage_dir, project, name)

        try:
            os.mkdir(os.path.join(self._storage_dir, project))
        except FileExistsError:
            pass

        recursive_link(file, dest, tmpdir=self._tmpdir, perms=self._perms)
        write_checksum(dest)

    def to_manual(self, file):
        """ Copy this file to the directory for manual intervention"""
        file = os.path.abspath(file)
        base, name = os.path.split(file)
        cleaned_name = clean_filename(file)
        dest = os.path.join(self._manual_dir, cleaned_name)
        recursive_link(file, dest, tmpdir=self._tmpdir, perms=self._perms)
        logger.info("manual intervention is required for %s", dest)

        # store the original file name
        orig_file = os.path.join(self._manual_dir,
                                 cleaned_name + '.origlabfilename')
        with create_open(orig_file) as f:
            f.write(name)

        write_checksum(dest)

    def to_msconvert(self, file, beat_timeout=30):
        future = fscall.submit(self._msconvert_dir, [file],
                               beat_timeout=beat_timeout)
        try:
            res = future.result()  # TODO add timeout
        except BaseException:
            message_to_admin('hi')
            # future.cancel()
            raise
        else:
            try:
                basepath, filename = os.path.split(res)
                touch(os.path.join(basepath, STARTED_MARKER + filename))
                self.submit(res, os.path.split(res)[0]).result()
                # future.clean()
            except BaseException:
                message_to_admin('blubb')
                raise

    def _handle_file(self, file):
        """ Figure out to which dirs file should be linked. """
        try:
            file = os.path.abspath(file)

            logger.debug("processing file " + str(file))

            if self._perms is not None:
                check_permissions(file, **self._perms)

            try:
                self.to_openbis(file)
                self.to_storage(file)
            except ValueError:
                self.to_manual(file)

            logger.debug("Removing original file %s", file)
            try:
                if os.path.isfile(file):
                    os.unlink(file)
                elif os.path.isdir(file):
                    shutil.rmtree(str(file))
                else:
                    logger.error("Could not remove file, it is not a " +
                                 "regular file: %s", file)
            except Exception:
                logger.error("Could not remove original file %s after " +
                             "handeling the file correctly", file)
                raise
        except BaseException:
            incoming, filename = os.path.split(file)
            error_marker = os.path.join(
                incoming,
                ERROR_MARKER + filename
            )
            logger.exception("An error occured while handeling file. " +
                             "Creating error marker file %s, remove if " +
                             "you fixed the error. Error was:",
                             error_marker)
            with open(error_marker, 'w') as f:
                traceback.print_exc(file=f)

    def submit(self, path, basedir):
        filename = os.path.split(path)[1]
        future = super(FileHandler, self).submit(self._handle_file, path)

        def remove_start_marker(future):
            error_marker = os.path.join(basedir, STARTED_MARKER + filename)
            try:
                os.unlink(error_marker)
            except OSError:
                logger.warn("Could not find start marker for file %s", path)
        future.add_done_callback(remove_start_marker)
        return future


def process_marker(marker, basedir, incoming_name, handler):
    """ Check if there are new files in `incoming` and handle them if so.

    Check for a marker file in `incoming`. If new files are found, check
    their permissions, write their checksums to ``checksums.txt`` and sort them
    into apropriate subdirs.
    """
    logging.debug("Found new marker file: %s", marker)

    filename = os.path.basename(marker)[len(FINISHED_MARKER):]
    file = pjoin(basedir, filename)

    # error_marker is created if we can't process the file
    error_marker = pjoin(basedir, ERROR_MARKER + filename)

    # start marker tells us that a background process is looking at it
    start_marker = pjoin(basedir, STARTED_MARKER + filename)

    # finish marker is created by the datamover when the file
    # has been copied completely
    finish_marker = pjoin(basedir, FINISHED_MARKER + filename)

    if os.path.exists(error_marker):
        logger.debug("Ignoring file %s because of error marker", file)
        return

    if os.path.exists(start_marker):
        logger.debug("Ignoring file %s because of started marker", file)
        if is_old(start_marker):
            logger.warning("Found an old start marker: %s.", start_marker)
        return

    try:
        if not filename:
            raise ValueError("Got invalid marker file: %s" % finish_marker)

        logger.info("New file arrived for dropbox %s: %s" %
                    (incoming_name, file))

        if (filename.startswith(FINISHED_MARKER) or
                filename.startswith(ERROR_MARKER) or
                filename.startswith(STARTED_MARKER)):
            raise ValueError("Filename starts with marker name")

        if not os.path.exists(file):
            raise ValueError("Got marker %s, but %s does not exist" %
                             (finish_marker, file))

        touch(start_marker)
        handler.submit(file, basedir)
        # handler will remove start_marker
        os.unlink(finish_marker)
    except BaseException:
        logger.exception("An error occured while submitting a job. " +
                         "Creating error marker file %s, remove if " +
                         "you fixed the error.",
                         error_marker)
        with open(error_marker, 'w') as f:
            traceback.print_exc(file=f)


def listen(incoming_dirs, interval, handler):
    """ Watch directories `incomings` for new files and call FileHandler."""
    while True:
        for name in incoming_dirs:
            basedir = incoming_dirs[name]

            logger.debug("Check for new files in %s at %s" % (name, basedir))
            for marker in glob.glob(pjoin(basedir, FINISHED_MARKER + '*')):
                process_marker(marker, basedir, name, handler)
        time.sleep(interval)


def error_exit(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_args():
    """ Read arguments from config file and command line args."""
    defaults = {
        'permissions': True,
        'checksum': True,
        'interval': 60,
        'pidfile': '~/.dropboxhandler.pid',
        'daemon': False,
        'user': None,
        'group': None,
        'filemode': 0o660,
        'dirmode': 0o770,
        'umask': 0o077,
    }

    parser = argparse.ArgumentParser(
        description="Watch for new files in " +
                    "dropboxdir and move to ObenBis/storage",
    )

    parser.add_argument("-c", "--conf-file",
                        help="Specify config file", metavar="FILE",
                        default="~/.dropboxhandler.conf")
    parser.add_argument("--print-example-config",
                        help="Print a example config file to stdout.",
                        action="store_true", default=False)
    parser.add_argument('-t', help="interval [s] between checks for " +
                        "new files", type=float, dest='interval')
    parser.add_argument('--no-permissions', dest='permissions',
                        help="do not set and check permissions of input " +
                        "and output files", action='store_false')
    parser.add_argument('--logfile', default=None)
    parser.add_argument('--loglevel', default='INFO')
    parser.add_argument('-d', '--daemon', action='store_true')
    parser.add_argument('--pidfile', default=None)
    parser.add_argument('--no-checksum', dest='checksum',
                        help="Do not compute checksums for incoming files",
                        action="store_false")
    parser.add_argument('--user', default=None,
                        help="Owner of incoming and outgoing files")
    parser.add_argument('--group', default=None,
                        help="Group owner of incoming and outgoing files ")
    parser.add_argument('--filemode', default=None,
                        help="permissions of all incoming and outgoing file " +
                        "(e.g. '0o660')")
    parser.add_argument('--dirmode', default=None,
                        help="permissons of all incoming and outgoing dirs")
    parser.add_argument('--umask', default=None,
                        help="Set umask in the same format at filemode")

    args = parser.parse_args()

    if args.print_example_config:
        print_example_config()
        sys.exit(0)

    # read config file
    if not os.path.exists(args.conf_file):
        print("Could not find config file (default location: " +
              "~/.dropboxhandler.conf", file=sys.stderr)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read([args.conf_file])

    if not config.has_section('incoming'):
        error_exit("Config file must include section 'incoming'")
    if not config.has_section('outgoing'):
        error_exit("Config file must include section 'outgoing'")
    if not config.has_section('openbis'):
        error_exit("Config file must include section 'openbis'")
    if not config.has_section('options'):
        error_exit("Config file must include section 'options'")

    return merge_configuration(vars(args), config, defaults)


def merge_configuration(args, config, defaults):
    cleaned_args = {}
    for key in args:
        if args[key] is not None:
            cleaned_args[key] = args[key]

    cleaned_config = {}
    cleaned_config['outgoing'] = {}
    for name in ["storage", "manual", "tmpdir"]:
        if not config.has_option("outgoing", name):
            error_exit("Section 'outgoing' must contain '%s'" % name)
        cleaned_config['outgoing'][name] = os.path.expanduser(
            config.get('outgoing', name)
        )

    for name in ['permissions', 'checksum', 'daemon']:
        if config.has_option('options', name):
            cleaned_config[name] = config.getboolean('options', name)

    for name in ['interval']:
        if config.has_option('options', name):
            cleaned_config[name] = config.getfloat('options', name)

    for name in ['filemode', 'dirmode', 'umask']:
        if config.has_option('options', name):
            cleaned_config[name] = int(config.get('options', name), base=8)

    for name in ['user', 'group', 'pidfile']:
        if config.has_option('options', name):
            cleaned_config[name] = config.get('options', name)

    cleaned_config['incoming'] = dict(config.items('incoming'))
    cleaned_config['openbis'] = {}
    for regexp, path in config.items('openbis'):
        cleaned_config['openbis'][regexp.strip("'" + '"')] = path

    cleaned_config['use_conf_file_logging'] = config.has_section('logging')

    defaults.update(cleaned_config)
    defaults.update(cleaned_args)
    defaults['pidfile'] = os.path.expanduser(defaults['pidfile'])
    defaults['pidfile'] = os.path.abspath(defaults['pidfile'])
    return defaults


def check_configuration(options):
    """ Sanity checks for directories. """
    for section in ['outgoing', 'incoming', 'openbis']:
        for name in options[section]:
            path = options[section][name]
            if not os.path.isdir(path):
                error_exit("%s is not a directory: %s" % (name, path))

    if options['interval'] <= 0:
        error_exit("Invalid interval: " + options['interval'])

    if options['daemon'] and os.path.exists(options['pidfile']):
        error_exit("Pidfile %s exists. Is another daemon unning?" %
                   options['pidfile'])

    if options['permissions']:
        perms = {}
        if options['user'] is None:
            perms['userid'] = os.geteuid()
        else:
            try:
                perms['userid'] = pwd.getpwnam(options['user']).pw_uid
            except KeyError:
                error_exit("User '%s' does not exist." % options['user'])

        if options['group'] is None:
            perms['groupid'] = os.getegid()
        else:
            try:
                perms['groupid'] = grp.getgrnam(options['group']).gr_gid
            except KeyError:
                error_exit("Group '%s' does not exist." % options['group'])

        perms['filemode'] = options['filemode']
        perms['dirmode'] = options['dirmode']
        options['perms'] = perms
    else:
        options['perms'] = None


def print_example_config():
    config_path = os.path.join(os.path.dirname(__file__), 'example.conf')
    with open(config_path) as f:
        print(f.read())


def daemonize(func, pidfile, umask, *args, **kwargs):
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

    logger.info("PID of new daemon: %s", os.getpid())

    os.umask(umask)
    write_pidfile(pidfile)
    close_open_fds()
    init_signal_handler()
    try:
        func(*args, **kwargs)
    except Exception:
        logger.critical("Unexpected error. Daemon is stopping")
        logger.exception("Error was:")


def write_pidfile(pidfile):
    pidfile = os.path.expanduser(str(pidfile))

    try:
        with create_open(pidfile) as f:
            f.write(str(os.getpid()) + '\n')
    except FileExistsError:
        error_exit("Could not write pidfile %s. Is the daemon running?" %
                   pidfile)
        sys.exit(1)

    atexit.register(lambda: os.remove(pidfile))


def close_open_fds():
    # use devnull for std file descriptors
    devnull = os.open('/dev/null', os.O_RDWR)
    for i in range(3):
        os.dup2(devnull, 0)


def main():
    args = parse_args()
    check_configuration(args)
    init_logging(args)
    try:
        handler_args = {
            'perms': args['perms'],
            'openbis_dropboxes': args['openbis'],
        }
        handler_args.update(args['outgoing'])
        with FileHandler(**handler_args) as handler:
            listen_args = {
                'incoming_dirs': args['incoming'],
                'interval': args['interval'],
                'handler': handler,
            }
            if args['daemon']:
                daemonize(
                    listen, args['pidfile'], args['umask'], **listen_args)
            else:
                init_signal_handler()
                os.umask(args['umask'])
                listen(**listen_args)

    except Exception:
        logging.critical("Daemon is shutting down for unknown reasons")
        logging.exception('Error was:')
        sys.exit(1)


if __name__ == '__main__':
    main()
