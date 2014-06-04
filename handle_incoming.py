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


BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
MARKER_NAME = ".MARKER_is_finished_"
IGNORED_FILES = [MARKER_NAME, 'to_openbis', 'manual_intervention',
                 'checksums.txt']


def checksums(files, checksums_file, write_checksums=False):
    """ Compute sha256 checksums on all files in ``files``. """
    files = [str(p) for p in files]
    files_abs = [pathlib.Path(p).resolve() for p in files]
    checksums_file = pathlib.Path(checksums_file)

    # read old checksums from checksums_file
    known_sums = {}
    if checksums_file.exists():
        basedir = checksums_file.parent
        with checksums_file.open('r') as f:
            lines = f.readlines()
        sums = dict(line.split(maxsplit=1)[::-1] for line in lines)
        for file in files_abs:
            known_sums[file] = sums[str(file.relative_to(basedir))]

    # compute real checksums
    real_sums = {}
    lines = subprocess.check_output(
        ['sha256sum'] + files, shell=False, cwd=str(checksums_file / '..')
    ).splitlines()
    sums = dict(line.split(maxsplit=1)[::-1] for line in lines)
    for file in sums:
        real_sums[pathlib.Path(file).resolve()] = sums[file]

    # check if identical
    for file in files_abs:
        if file in known_sums and known_sums[file] != real_sums[file]:
            raise ValueError("Invalid checksum for file " + str(file))

    # write all real checksums to file
    if write_checksums:
        with checksums_file.open('w') as f:
            f.writelines(lines)


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

    Barcodes must match this regular expression: [A-Z]{4}[0-9]{3}[A-Z][A-Z0-9]
    """
    path = pathlib.Path(path)
    barcodes = re.findall(BARCODE_REGEX, path.stem)
    barcodes = [b for b in barcodes if is_valid_barcode(b)]
    if not barcodes:
        raise ValueError("no barcodes found")
    if len(barcodes) > 1 and any(b != barcodes[0] for b in barcodes):
        raise ValueError("more than one barcode in filename")

    return barcodes[0]


def generate_name(path):
    """ Generate a sane file name from the input file

    Copy the barcode to the front and remove invalid characters.

    Raise ValueError the filename does not contain a barcode.

    Example
    -------
    >>> path = "stüpid\tname(<QJFDC010EU.).>ä.raw"
    >>> generate_name(path)
    'QJFDC010EU_stpidnameQJFDC010EU.raw'
    """
    path = pathlib.Path(path)
    barcode = extract_barcode(path)

    allowed_chars = string.ascii_letters + string.digits + '_-'

    cleaned_stem = ''.join(i for i in path.stem if i in allowed_chars)
    if not cleaned_stem:
        raise ValueError("Invalid file name")

    if not all(i in allowed_chars + '.' for i in path.suffix):
        raise ValueError("Bad file suffix: " + path.suffix)

    return barcode + '_' + cleaned_stem + path.suffix


def get_correct_user_group():
    user = pwd.getpwuid(os.getuid()).pw_name
    group = user + 'grp'

    userid = os.getuid()
    try:
        groupid = grp.getgrnam(group)
    except KeyError:
        raise ValueError("group {} does not exist".format(group))
    return userid, groupid


def check_permissions(path):
    """ Basic sanity check for permissions of incoming files

    This is not a security check, but it should find configuration
    issues of upstream tools.
    """
    path = pathlib.Path(path)
    userid, groupid = get_correct_user_group()

    if not path.stat().st_uid == userid:
        raise ValueError("Invalid file owner: " + str(path))
    if not path.stat().stat.st_gid == groupid:
        raise ValueError("Invalid group: " + str(path))

    if path.stat().filemode(stat) != "-rw-------":
        raise ValueError("Invalid file permissions: " + str(path))


def copy(file, dest, checksums_file=None):
    file = pathlib.Path(file).resolve()
    if file.is_file():
        copy = shutil.copy
    elif file.is_dir():
        copy = shutil.copytree
    copy(str(file), str(dest))


def to_openbis(file, new_name, checksums_file=None):
    file = pathlib.Path(file).resolve()
    copy(file, file.parent / 'to_openbis' / new_name,
         checksums_file=checksums_file)


def to_storage(file, new_name, checksums_file=None):
    pass


def to_manual(file, new_name, checksums_file=None):
    file = pathlib.Path(file).resolve()
    copy(file, file.parent / 'manual_intervention' / new_name,
         checksums_file=None)


def call_openbis(basedir):
    """ Tell OpenBis that new files in 'to_openbis' are ready"""
    (pathlib.Path(basedir) / 'to_openbis' / MARKER_NAME).touch()


def handle_files(basedir, files):
    basedir = pathlib.Path(basedir)
    checksums_file = basedir / 'checksums.txt'
    assert basedir.is_dir()
    #for file in files:
    #    check_permissions(file)
    try:
        checksums(files, checksums_file=checksums_file, write_checksums=True)
    except subprocess.CalledProcessError:
        with (basedir / 'INVALID_CHECKSUMS').open('w'):
            pass
        raise ValueError("Invalid checksums")

    try:
        for file in files:
            if file.is_dir():
                to_manual(file)
                continue

            try:
                new_name = generate_name(file)
            except ValueError:
                to_manual(file)
            else:
                to_storage(file, new_name, checksums_file=checksums_file)
                to_openbis(file, new_name, checksums_file=checksums_file)

        call_openbis(basedir)
    except Exception:
        with (basedir / 'ERROR').open('w'):
            pass
    else:
        for file in files:
            if file.is_file():
                file.unlink()
            elif file.is_dir():
                shutil.rmtree(str(file))


def parse_args():
    parser = argparse.ArgumentParser(description="Watch for new files in " +
                                     "dropbox and move to ObenBis/storage")
    parser.add_argument('dropboxdir', help='the dropbox directory in which' +
                        ' new files appear')
    parser.add_argument('-t', help="interval [s] between checks for " +
                        "new files (may be removed in the future)",
                        default=600, type=int)
    return parser.parse_args()


def main():
    args = parse_args()
    path = pathlib.Path(args.dropboxdir)
    if not path.is_dir():
        print(args.dropboxdir + " is not a directory")
        sys.exit(1)
    try:
        check_permissions(path)
    except ValueError:
        print("dropboxdir has invalid permissions")
        sys.exit(1)

    userid, groupid = get_correct_user_group()
    try:
        os.setgid(groupid)
    except Exception:
        print("Could not change to group " + str(groupid))
        sys.exit(1)

    while True:
        if (path / MARKER_NAME).exists():
            files = [f for f in path.iterdir() if f not in IGNORED_FILES]
            try:
                handle_files(path, files)
            except Exception as e:
                print(e)
        time.sleep(args.t)


if __name__ == '__main__':
    main()
