#!/usr/bin/env python
# coding: utf8

from __future__ import print_function

import re
import os
import time
import shutil
import logging
import glob
import traceback
import concurrent.futures
from os.path import join as pjoin

from . import fstools

try:
    from . import fscall
except ImportError:
    fscall = False

if not hasattr(__builtins__, 'FileExistsError'):
    FileExistsError = OSError
if not hasattr(__builtins__, 'FileNotFoundError'):
    FileNotFoundError = OSError

logger = logging.getLogger('dropboxhandler.handler')

BARCODE_REGEX = "[A-Z]{5}[0-9]{3}[A-Z][A-Z0-9]"
FINISHED_MARKER = ".MARKER_is_finished_"
ERROR_MARKER = "MARKER_error_"
STARTED_MARKER = "MARKER_started_"


def message_to_admin(message):
    pass


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
    valid_barcodes = [b for b in barcodes if is_valid_barcode(b)]
    if len(barcodes) != len(valid_barcodes):
        logger.warn("Invalid barcode in file name: %s",
                    set(barcodes) - set(valid_barcodes))
    if not barcodes:
        raise ValueError("no barcodes found")
    if len(set(barcodes)) > 1:
        raise ValueError("more than one barcode in filename")
    return barcodes[0]


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
    cleaned_name = fstools.clean_filename(path)
    barcode = extract_barcode(cleaned_name)
    name = cleaned_name.replace(barcode, "")
    return barcode + '_' + name


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
                 msconvert=None, tmpdir=None, max_workers=5, checksum=True):
        super(FileHandler, self).__init__(max_workers)
        self._openbis_dropboxes = openbis_dropboxes
        self._storage_dir = storage
        self._manual_dir = manual
        self._msconvert_dir = msconvert
        self._tmpdir = tmpdir

    def _find_openbis_dest(self, origin, name, is_dir):
        for conf in self._openbis_dropboxes:
            regexp, path = conf['regexp'], conf['path']
            if 'origin' in conf and origin not in conf['origin']:
                continue
            if is_dir and not conf.get('match_dir', True):
                continue
            if not is_dir and not conf.get('match_file', True):
                continue
            if re.match(regexp, name):
                logger.debug("file %s matches regex %s", name, regexp)
                return os.path.join(path, name)
        logger.error("File with barcode, but does not match " +
                     "an openbis dropbox: %s", name)
        raise ValueError('No known openbis dropbox for file %s' % name)

    def to_openbis(self, origin, file, perms=None):
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

        is_dir = os.path.isdir(file)
        dest = self._find_openbis_dest(origin, openbis_name, is_dir)

        # Put all related files inside a directory, so that openbis
        # can process them together.
        dest_file = os.path.join(dest, openbis_name)
        dest_dir = os.path.split(dest)[0]
        os.mkdir(dest)

        logger.debug("Write file to openbis dropbox %s" % dest)
        fstools.recursive_link(
            file, dest_file, tmpdir=self._tmpdir, perms=perms
        )

        labname_file = "%s.origlabfilename" % openbis_name
        with fstools.create_open(os.path.join(dest, labname_file)) as f:
            f.write(orig_name)

        fstools.write_checksum(dest_file)

        with fstools.create_open(os.path.join(dest, "source_dropbox.txt")) as f:
            f.write(origin)

        # tell openbis that we are finished copying
        for name in [openbis_name]:
            marker = os.path.join(dest_dir, FINISHED_MARKER + name)
            with fstools.create_open(marker):
                pass

    def to_storage(self, origin, file, perms=None):
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
            name = fstools.clean_filename(file)

        dest = os.path.join(self._storage_dir, project, name)

        try:
            os.mkdir(os.path.join(self._storage_dir, project))
        except FileExistsError:
            pass

        fstools.recursive_link(file, dest, tmpdir=self._tmpdir, perms=perms)
        fstools.write_checksum(dest)

    def to_manual(self, origin, file, perms=None):
        """ Copy this file to the directory for manual intervention"""
        file = os.path.abspath(file)
        base, name = os.path.split(file)
        cleaned_name = fstools.clean_filename(file)
        dest_dir = os.path.join(self._manual_dir, cleaned_name)
        os.mkdir(dest_dir)

        dest = os.path.join(dest_dir, cleaned_name)
        fstools.recursive_link(file, dest, tmpdir=self._tmpdir, perms=perms)
        logger.warn("manual intervention is required for %s", dest_dir)

        # store the original file name
        orig_file = os.path.join(dest_dir,
                                 cleaned_name + '.origlabfilename')
        with fstools.create_open(orig_file) as f:
            f.write(name)

        source_file = os.path.join(dest_dir, "source_dropbox.txt")
        with fstools.create_open(source_file) as f:
            f.write(origin)

        fstools.write_checksum(dest)

    def to_msconvert(self, origin, file, beat_timeout=30, perms=None):
        if not fscall:
            raise ValueError("msconvert need pathlib, which is not installed")
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
                fstools.touch(os.path.join(basepath, STARTED_MARKER + filename))
                self.submit(origin, res, os.path.split(res)[0]).result()
                # future.clean()
            except BaseException:
                message_to_admin('blubb')
                raise

    def _handle_file(self, origin, file, perms=None):
        """ Figure out to which dirs file should be linked. """
        try:
            file = os.path.abspath(file)

            logger.debug("processing file " + str(file))

            if perms is not None:
                fstools.check_permissions(file, **perms)

            try:
                self.to_openbis(origin, file, perms=perms)
                self.to_storage(origin, file, perms=perms)
            except ValueError:
                self.to_manual(origin, file, perms=perms)

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

    def submit(self, origin, path, basedir, perms=None):
        """ Submit an incoming file or directory to the thread pool.

        Arguments
        ---------
        origin: str
            The name of the dropbox the file came from, as specified in
            the config file.
        path: str
            Path to the incoming file or directory.
        basedir: str
            Path to the dropbox that contains the incoming file.
        perms: dict
            A dictionary with arguments to `fstools.check_permissions`.
        """
        filename = os.path.split(path)[1]
        future = super(FileHandler, self).submit(
            self._handle_file, origin, path, perms
        )

        def remove_markers(future):
            started_marker = os.path.join(basedir, STARTED_MARKER + filename)
            finish_marker = os.path.join(basedir, FINISHED_MARKER + filename)
            try:
                os.unlink(finish_marker)
            except OSError:
                logger.error("Could not find finish marker for file %s", path)
            try:
                os.unlink(started_marker)
            except OSError:
                logger.error("Could not find start marker for file %s", path)
        future.add_done_callback(remove_markers)
        return future


def process_marker(marker, basedir, incoming_name, handler, perms=None):
    """ Check if there are new files in `incoming` and handle them if so.

    Marker files
    ------------
    - All incoming files are expected to write a marker file
      `FINISHED_MARKER<filename>` when copying is finished. Incoming files
      without such a marker file will be silently ignored.

    - If a file is being processed by the dropboxhandler, a
      `STARTED_MARKER<filename>` marker file is written. This will be removed
      after the incoming file itself has been moved to the correct location.

    - If the incoming file has incorrect permissions or if handling the
      file fails for another reason, a `ERROR_MARKER<filename>` marker file
      is created, that contains the error message. If this file is removed
      and a new `FINISHED_MARKER<filename>` marker file is created, the
      dropboxhandler will try again.
    """
    logger.debug("Found new marker file: %s", marker)

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
        if fstools.is_old(start_marker):
            logger.error("Found an old start marker: %s.", start_marker)
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

        fstools.touch(start_marker)
        handler.submit(incoming_name, file, basedir, perms)
        # handler will remove start_marker and finish marker
    except BaseException:
        logger.exception("An error occured while submitting a job. " +
                         "Creating error marker file %s, remove if " +
                         "you fixed the error.",
                         error_marker)
        with open(error_marker, 'w') as f:
            traceback.print_exc(file=f)


def listen(incoming, interval, handler):
    """ Watch directories `incomings` for new files and call FileHandler."""
    logger.info("Starting to listen for new files")
    while True:
        for conf in incoming:
            basedir = conf['path']
            name = conf['name']
            perms = conf.get('perms', None)

            logger.debug("Check for new files in %s at %s" % (name, basedir))
            for marker in glob.glob(pjoin(basedir, FINISHED_MARKER + '*')):
                process_marker(marker, basedir, name, handler, perms)
        time.sleep(interval)
