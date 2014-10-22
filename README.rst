.. image:: https://travis-ci.org/qbicsoftware/dropboxhandler.svg?branch=master
   :target: https://travis-ci.org/qbicsoftware/dropboxhandler

Dropboxhandler
==============

Listen for marker files (``.MARKER_is_finished_<filename>``) in a set of
directories. All incoming files are copied (or hard linked) to other
directories:

* storage: All incoming files are copied here. Additionally a file
  ``<filename>.sha265`` is created, that contains checksums. You
  can check the files with ``sha256sum -c <filename>.sha256``.

* manual: If the file name does not contain a valid barcode, copy it here.

* openbis: If the name of the incoming file contains a valid openbis barcode,
  the input file will be copied to openbis dropboxes. Which dropbox is
  used for which file is specified in the config file by regular expressions.

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
