Dropboxhandler
=============

Listen for marker files (``.MARKER_is_finished_<filename>``) in a directory.
All of the incoming files are copied (or hard linked) to certain directories:

* storage: All incoming files are copied here. Additionally a file
  ``<filename>.sha265`` is created, that contains checksums. You
  can check the files with ``sha256sum -c <filename>.sha256``.

* openbis: If the name of the incoming file contains a valid openbis barcode,
  a copy is placed in this directory. The filename is cleand of all strange
  characters.

* manual: If the file name does not contain a valid barcode, copy it here.

Install
=======

Execute

    python setup.py install

Configure
=========

See

    dropboxhandler -h

for a small overview of the options.

Execute

    dropboxhandler --print-example-config


adjust the config to your needs and store it in a file. To start the
daemon, execute

    dropboxhandler --daemon -c config_file
