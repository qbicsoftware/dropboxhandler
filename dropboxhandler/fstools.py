import logging
import os
import sys
import time
import subprocess
import string
import tempfile
import stat
import shutil

if not hasattr(__builtins__, 'FileExistsError'):
    FileExistsError = OSError
if not hasattr(__builtins__, 'FileNotFoundError'):
    FileNotFoundError = OSError

logger = logging.getLogger('dropboxhandler.fstools')


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


def touch(path):
    with create_open(path):
        pass


def is_old(path):
    """ Test if path has been modified during the last 5 days. """
    modified = os.stat(path).st_mtime
    age_seconds = time.time() - modified
    if age_seconds > 60 * 60 * 24 * 5:  # 5 days
        return True


def write_checksum(file):
    """ Compute checksums of file or of contents if it is a dir.

    Checksums will be written to <inputfile>.sha256sum in the
    format of the sha256sum tool.

    If file is a directory, the checksum file will include the
    checksums of all files in that dir.
    """
    file = os.path.abspath(file)
    basedir = os.path.split(file)[0]
    checksum_file = str(file) + '.sha256sum'

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


def clean_filename(path):
    """ Generate a sane (alphanumeric) filename for path. """
    allowed_chars = string.ascii_letters + string.digits + '_'
    stem, suffix = os.path.splitext(os.path.basename(path))
    cleaned_stem = ''.join(i for i in stem if i in allowed_chars)
    if not cleaned_stem:
        raise ValueError("Invalid file name: %s", stem + suffix)

    if not all(i in allowed_chars + '.' for i in suffix):
        raise ValueError("Bad file suffix: " + suffix)

    return cleaned_stem + suffix


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


def recursive_link(source, dest, tmpdir=None, perms=None):
    source = os.path.abspath(source)
    dest = os.path.abspath(dest)
    if os.path.exists(dest):
        raise ValueError("File exists: %s" % dest)
    destbase, destname = os.path.split(dest)

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
