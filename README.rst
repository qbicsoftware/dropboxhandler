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

At github.com/qbicsoftware/specs you can find a spec file for building
an RPM.

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

If you change the configuration check it with

    dropboxhandler -c config_file --check-config

and tell drobpoxhandler to re-read the config:

    kill -HUP pid_of_dropboxhandler

The new config will apply to all new incoming files and will not apply
to files that are being processed when the signal arrived.

System service
==============

The rpm that can be created with the spec file at qbicsoftware/specs
has an additional config file at /etc/dropboxhandler.conf which must
define the variables USER and USER_CONFIG_FILE pointing to the user
the service should be executed as and the dropboxhandler config file.
A template can be found at `service/drobpoxhandler.conf`
