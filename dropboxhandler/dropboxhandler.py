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
import logging.config
import atexit
import signal
import glob
import traceback
import stat
import tempfile
import resource
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


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


logger = None

BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
FINISHED_MARKER = ".MARKER_is_finished_"
ERROR_MARKER = "MARKER_error_"


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

    if 'conf_file' in options and options['conf_file']:
        try:
            logging.config.fileConfig(options['conf_file'],
                                      disable_existing_loggers=True)
        except Exception as e:
            print("Could not load logging information from config file", e)

    logger = logging.getLogger()


def write_checksum(file):
    """ Compute checksums of file or of contents, if file is dir.

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
        raise ValueError("%s has no files to checksum", file)

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
    logging.warn("got invalid barcode: %s", barcode)
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

    return cleaned_stem + suffix.lower()


def generate_openbis_name(path):
    """ Generate a sane file name from the input file

    Copy the barcode to the front and remove invalid characters.

    Raise ValueError if the filename does not contain a barcode.

    Example
    -------
    >>> path = "stüpid\tname(<QJFDC010EU.).>ä.raW"
    >>> generate_openbis_name(path)
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
    if userid and os.stat(path).st_uid != userid:
        logger.critical("userid of file %s should be %s but is %s",
                        path, userid, os.stat(path).st_uid)
    if groupid and os.stat(path).st_gid != groupid:
        logger.critical("groupid of file %s should be %s but is %s",
                        path, groupid, os.stat(path).st_gid)

    if os.path.isdir(path):
        if os.stat(path).st_mode % 0o1000 != dirmode:
            logger.critical("mode of dir %s should be %o but is %o",
                            path, dirmode, os.stat(path).st_mode % 0o1000)
    elif os.path.islink(path):
        logging.critical("symbolic links are not allowed: %s", path)
    elif os.path.isfile(path):
        if os.stat(path).st_mode % 0o1000 != filemode:
            logger.critical("mode of file %s should be %o but is %o",
                            path, filemode, os.stat(path).st_mode % 0o1000)
    else:
        logger.critical("should be a regular file or dir: %s", path)


def _check_perms_recursive(path, userid, groupid, dirmode, filemode):
    _check_perms(path, userid, groupid, dirmode, filemode)
    for path, dirnames, filenames in os.walk(path):
        _check_perms(path, userid, groupid, dirmode, filemode)
        for name in filenames:
            _check_perms(os.path.join(path, name),
                         userid, groupid, dirmode, filemode)


def check_input_permissions(path):
    """ Basic sanity check for permissions of incoming files

    This exists to find configuration issues only.

    Will not raise errors, but write them to logger.
    """
    try:
        userid, groupid = get_output_user_group()
    except ValueError:
        logger.critical("Output group does not exist. Files may be " +
                        "accessible for unauthorized users")
        return

    _check_perms_recursive(path, userid, None, 0o700, 0o600)


def check_output_permissions(path):
    """ Basic sanity check for permissions of file written by this daemon

    This exists to find configuration issues only.

    Will not raise errors, but write them to logger.
    """
    try:
        userid, groupid = get_output_user_group()
    except ValueError:
        logger.critical("Output group does not exist. Files may be " +
                        "accessible for unauthorized users")
        return

    _check_perms_recursive(path, userid, groupid, 0o770, 0o660)


def adjust_permissions(path):
    try:
        userid, groupid = get_output_user_group()
    except ValueError:
        logger.critical("Output group does not exist. Files may be " +
                        "accessible for unauthorized users")
        return

    def adjust(file):
        os.chown(file, userid, groupid)
        if os.path.isdir(file):
            os.chmod(file, 0o770)
        else:
            os.chmod(file, 0o660)

    adjust(path)
    for root, dirs, files in os.walk(path):
        for file in dirs + files:
            adjust(file)


def init_signal_handler():
    def handler(sig, frame):
        if sig == signal.SIGTERM:
            logging.info("Daemon got SIGTERM. Shutting down.")
            sys.exit(0)
        elif sig == signal.SIGCONT:
            logging.info("Daemon got SIGCONT. Continuing.")
        elif sig == signal.SIGINT:
            logging.info("Daemon got SIGINT. Shutting down.")
            sys.exit(0)
        else:
            logging.error("Signal handler did not expect to get %s", sig)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGCONT, handler)
    signal.signal(signal.SIGINT, handler)


def recursive_link(source, dest, tmpdir=None):
    source = os.path.abspath(source)
    dest = os.path.abspath(dest)
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
        '--',
        str(source),
        str(workdest),
    ]

    try:
        subprocess.check_call(command, shell=False)

        # remove symlinks from output
        for root, dirs, files, rootdf in os.fwalk(workdest):
            for file in dirs + files:

                stats = os.stat(file, dir_fd=rootdf, follow_symlinks=False)
                if stat.S_IFMT(stats.st_mode) == stat.S_IFLNK:
                    logger.error("Got symbolic link in source to %s. " +
                                 "Removing...",
                                 os.readlink(file, dir_fd=rootdf))
                    os.unlink(file, dir_fd=rootdf)

        logger.debug("Created links in workdir. Moving to destination")
        os.rename(workdest, dest)
        check_output_permissions(workdest)
    except:  # even for SystemExit
        logger.error("Got exception before we finished copying files. " +
                     "Rolling back changes")
        if os.path.exists(dest):
            shutil.rmtree(dest)
        raise
    finally:
        shutil.rmtree(tmpdir)


def to_openbis(file, openbis_dir, tmpdir=None):
    """ Copy this file or directory to the openbis export directory

    If the filename does not include an openbis barcode, raise ValueError.

    file, openbis_dir and tmpdir must all be on the same file system.
    """
    file = os.path.abspath(file)

    if os.path.isdir(file):
        logging.debug("Can not send directory %s to openbis", file)
        raise ValueError("Sending directories to openbis is not supported")

    try:
        openbis_name = generate_openbis_name(file)
    except ValueError:
        logging.debug("Can not find a barcode in %s", file)
        raise

    logger.info("Exporting %s to OpenBis as %s", file, openbis_name)
    dest = os.path.join(openbis_dir, openbis_name)
    recursive_link(file, dest, tmpdir)

    # tell openbis that we are finished copying
    base, name = os.path.split(dest)
    with open(os.path.join(base, FINISHED_MARKER + name), 'w'):
        pass


def to_storage(file, storage_dir, tmpdir=None):
    logger.debug("to_storage is not implemented, ignoring")


def to_manual(file, manual_dir, tmpdir=None):
    """ Copy this file or directory to the directory for manual intervention"""
    file = os.path.abspath(file)

    cleaned_name = clean_filename(file)
    dest = os.path.join(manual_dir, cleaned_name)
    recursive_link(file, dest, tmpdir)
    logger.info("manual intervention is required for %s", file)
    write_checksum(dest)


def make_links(file, openbis_dir, manual_dir, storage_dir, tmpdir=None):
    file = os.path.abspath(file)

    logger.debug("processing file " + str(file))

    adjust_permissions(file)

    try:
        to_openbis(file, openbis_dir, tmpdir)
    except ValueError:
        to_manual(file, manual_dir, tmpdir)
    finally:
        to_storage(file, storage_dir, tmpdir)

    logger.debug("Removing original file %s", file)
    try:
        if os.path.isfile(file):
            os.unlink(file)
        elif os.path.isdir(file):
            shutil.rmtree(str(file))
        else:
            logger.error(
                "Could not remove file, it is not a regular file: %s", file
            )
    except Exception:
        logger.error("Could not remove file %s", file)
        raise


def listen(interval, incoming, openbis, manual, storage, tmpdir=None):
    """ Listen for tasks in ``path``.

    Check for a marker file in ``path`` every ``interval`` seconds. If new
    files are found, check their permissions, write their checksums to
    ``checksums.txt`` and sort them into apropriate subdirs.
    """
    logger.info("Starting to listen in %s", incoming)
    os.chdir(str(incoming))
    while True:
        for marker in glob.glob(FINISHED_MARKER + '*'):
            logging.debug("Found new marker file: %s", marker)
            filename = marker[len(FINISHED_MARKER):]
            file = os.path.abspath(filename)

            if os.path.exists(ERROR_MARKER + filename):
                logger.debug("Ignoring file %s because of error marker",
                             file)
                continue

            try:
                if not filename:
                    raise ValueError("Got bare marker file: %s" % marker)

                logger.info("New file arrived: %s", file)

                if (filename.startswith(FINISHED_MARKER) or
                        filename.startswith(ERROR_MARKER)):
                    raise ValueError("Filename starts with marker name")

                if not os.path.exists(file):
                    raise ValueError("Marker %s, but %s does not exist" %
                                     (marker, file))

                make_links(
                    file,
                    openbis_dir=openbis,
                    manual_dir=manual,
                    storage_dir=storage,
                    tmpdir=tmpdir,
                )

                logger.debug("Finished processing file. Removing marker")
                os.unlink(marker)

                logger.info("Finished processing file %s", filename)
            except Exception:
                error_marker = os.path.join(
                    incoming,
                    ERROR_MARKER + filename
                )
                logger.exception("An error occured while moving files. " +
                                 "Creating error marker file %s, remove if " +
                                 "you fixed the error. Error was:",
                                 error_marker)
                with open(error_marker, 'w') as f:
                    traceback.print_exc(file=f)
        time.sleep(interval)


def parse_args():
    """ Read arguments from config file and command line args."""
    defaults = {
        'permissions': True,
        'checksum': True,
        'interval': 60,
        'pidfile': '~/.dropboxhandler.pid',
        'daemon': False,
    }

    parser = argparse.ArgumentParser(
        description="Watch for new files in " +
                    "dropboxdir and move to ObenBis/storage",
    )

    parser.add_argument("-c", "--conf_file",
                        help="Specify config file", metavar="FILE",
                        default="~/.dropboxhandler.conf")
    parser.add_argument("--print-example-config",
                        help="Print a example config file to stdout.",
                        action="store_true", default=False)
    parser.add_argument('-t', help="interval [s] between checks for " +
                        "new files", type=int, dest='interval')
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
    args = parser.parse_args()

    if args.print_example_config:
        print_example_config()
        sys.exit(0)

    # read config file
    if not os.path.exists(args.conf_file):
        print("Could not find config file (default location: " +
              "~/.dropboxhandler.conf", file=sys.stderr)
        sys.exit(1)
    interpolator = configparser.ExtendedInterpolation()
    config = configparser.ConfigParser(interpolation=interpolator)
    config.read([args.conf_file])

    if not "paths" in config:
        print("Config file must include section 'paths'", file=sys.stderr)
        sys.exit(1)

    return merge_configuration(args, config, defaults)


def merge_configuration(args, config, defaults):
    cleaned_args = {}
    for key in args:
        if args[key] is not None:
            cleaned_args[key] = args[key]

    cleaned_config = {}
    cleaned_config['paths'] = {}
    for name in ["incoming", "openbis", "storage", "manual", "tmpdir"]:
        if not name in config["paths"]:
            print("Section 'paths' must include '%s'" % name, file=sys.stderr)
        cleaned_args['paths'][name] = config.get('paths', name)

    args = vars(args)
    for name in ['permissions', 'checksum', 'daemon']:
        if name in config:
            cleaned_config[name] = config.getboolean('options', name)

    for name in ['interval']:
        if name in config:
            cleaned_config[name] = config.getint('options', name)

    defaults.update(cleaned_config)
    defaults.update(args)
    return defaults


def check_configuration(options):
    """ Sanity checks for directories. """
    for name in options['paths']:
        path = options['paths'][name]
        if not os.path.isdir(path):
            print(name + " is not a directory: ", path, file=sys.stderr)
            sys.exit(1)
        try:
            check_output_permissions(path)
        except ValueError:
            print(str(path) + " has invalid permissions", file=sys.stderr)
            sys.exit(1)

    if options['interval'] <= 0:
        print("Invalid interval:", options['interval'], file=sys.stderr)
        sys.exit(1)


def print_example_config():
    config_path = os.path.join(os.path.dirname(__file__), 'example.conf')
    with open(config_path) as f:
        print(f.read())


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

    logger.info("PID of new daemon: %s", os.getpid())

    write_pidfile(pidfile)
    close_open_dfs()
    init_signal_handler()

    try:
        func(*args, **kwargs)
    except Exception:
        logger.critical("Unexpected error. Daemon is stopping")
        logger.exception("Error was:")


def write_pidfile(pidfile):
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


def close_open_dfs():
    for fd in range(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
        try:
            os.close(fd)
        except OSError:
            pass

    # use devnull for std file descriptors
    devnull = os.open('/dev/null', os.O_RDWR)
    for i in range(3):
        os.dup2(devnull, 0)


def configure_permissions(args):
    global check_input_permissions, check_output_permissions
    global get_output_user_group
    if args['permissions']:
        userid, groupid = get_output_user_group()
        try:
            os.setgid(groupid)
            os.umask(0o007)
        except Exception:
            print("Could not change to group " + str(groupid))
            sys.exit(1)
    else:
        # overwrite permission checking with stubs
        check_output_permissions = lambda x: None
        check_input_permissions = lambda x: None
        get_output_user_group = lambda: (1000, 1000)


def main():
    args = parse_args()
    configure_permissions(args)
    init_logging(args)
    check_configuration(args)

    try:
        # start checking for new files
        if args['daemon']:
            daemonize(listen, args['pidfile'], args['interval'],
                      **args['paths'])
        else:
            init_signal_handler()
            listen(args['interval'], **args['paths'])

    except Exception:
        logging.critical("Daemon is shutting down for unknown reasons")
        logging.exception('Error was:')
        sys.exit(1)


if __name__ == '__main__':
    main()
