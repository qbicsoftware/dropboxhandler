import re
import pathlib
import string
import os
import pwd
import grp
import stat
import subprocess


BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"


def checksums(dirpath, checksums_file='checksums.txt'):
    """ Compute sha256 checksums on all files in dirpath.

    If ``dirpath / checksums.txt`` exists, check if all checksums in this
    file are ok.

    If it does not, compute checksums of all files in this dir and write
    them to ``checksums.txt``.
    """
    dir = pathlib.Path(dirpath)

    if not dir.is_dir():
        raise ValueError(str(dirpath) + " is not a directory")

    files = [str(p) for p in dir.iterdir()]
    checks = dir / checksums_file
    if not checks.exists():
        sums = subprocess.check_output(
            ['sha256sum'] + files, shell=False,
        )
        with checks.open('x') as f:
            f.write(sums)
    else:
        subprocess.check_call(
            ['sha256sum', '-c', '--status'] + files,
            shell=False,
        )


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
    """ Generate a sane file name a input file

    Copy the barcode to the front and remove invalid characters.

    Raise ValueError the filename does not contain a barcode.

    Example
    -------
    >>> path = "stüpid\tname(<QJFDC010EU..ä.raw"
    >>> print(generate_name(path))
    QJFDC010EU_stpidnameQJFDC010EU.raw
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


def check_permissions(path):
    """ Basic sanity check for permissions of incoming files

    This is not a security check, but it should find configuration
    issues of upstream tools.
    """
    path = pathlib.Path(path)

    user = pwd.getpwuid(os.getuid()).pw_name
    group = user + 'grp'

    userid = os.getuid()
    try:
        groupid = grp.getgrnam(group)
    except KeyError:
        raise ValueError("group {} does not exist".format(group))

    if not path.stat().st_uid == userid:
        raise ValueError("Invalid file owner: " + str(path))
    if not path.stat().stat.st_gid == groupid:
        raise ValueError("Invalid group: " + str(path))

    if path.stat().filemode(stat) != "-rw-------":
        raise ValueError("Invalid file permissions: " + str(path))
