from __future__ import print_function

import logging
import sys
import os
import argparse
import atexit
import pwd
import grp
import re
import traceback
import yaml
import numbers
import signal

from . import dropboxhandler
from . import fstools


logger = None


class RestartException(BaseException):
    """ Raised on SIGUSR1 to indicate that the config file changed."""
    pass


def init_logging(options):
    global logger

    try:
        logging.config.dictConfig(options)
    except AttributeError:
        import logutils.dictconfig
        logutils.dictconfig.dictConfig(options)
    except Exception as e:
        traceback.print_exc()
        error_exit("Could not load logging information from config: %s " % e)

    logger = logging.getLogger('dropboxhandler.commandline')


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


def print_example_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    with open(config_path) as f:
        print(f.read())


def write_pidfile(pidfile):
    try:
        with fstools.create_open(pidfile) as f:
            f.write(str(os.getpid()) + '\n')

        def remove_pid():
            try:
                os.remove(pidfile)
            except OSError:
                pass
        atexit.register(remove_pid)
    except fstools.FileExistsError:
        with open(pidfile) as f:
            # the pidfile is correct if the service is re-reading its config
            if os.getpid() == int(f.read()):
                return
        error_exit("Could not write pidfile %s. Is the daemon running?" %
                   pidfile)
        sys.exit(1)


def close_open_fds():
    # use devnull for std file descriptors
    devnull = os.open('/dev/null', os.O_RDWR)
    for i in range(3):
        os.dup2(devnull, 0)


def init_signal_handler():
    def handler(sig, frame):
        if sig == signal.SIGTERM:
            logger.warn("Daemon got SIGTERM. Shutting down.")
            raise SystemExit
        elif sig == signal.SIGHUP:
            logger.warn("Got SIGHUP, restart daemon with new config")
            raise RestartException
        else:
            logger.error("Signal handler did not expect to get %s", sig)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGHUP, handler)


def start(ignore_daemon=False):
    args = parse_args()
    check_configuration(args)
    if args['check_config']:
        print('Config file seems fine.')
        sys.exit(0)
    init_logging(args['logging'])
    logger.info("Starting service")
    try:
        handler_args = {
            'openbis_dropboxes': args['openbis'],
            'checksum': args['options']['checksum'],
        }
        handler_args.update(args['outgoing'])
        with dropboxhandler.FileHandler(**handler_args) as handler:
            listen_args = {
                'incoming': args['incoming'],
                'interval': args['options']['interval'],
                'handler': handler,
            }
            if not ignore_daemon and args['options']['daemon']:
                daemonize(
                    dropboxhandler.listen, args['options']['pidfile'],
                    args['options']['umask'], **listen_args
                )
            else:
                init_signal_handler()
                os.umask(args['options']['umask'])
                dropboxhandler.listen(**listen_args)

    except Exception:
        logging.critical("Daemon is shutting down for unknown reasons")
        logging.exception('Error was:')
        sys.exit(1)


def main(ignore_daemon=False):
    try:
        start(ignore_daemon)
    except RestartException:
        main(True)


def error_exit(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_args():
    """ Read arguments from config file and command line args."""
    options_default = {
        'permissions': True,
        'checksum': True,
        'interval': 60,
        'pidfile': '~/.dropboxhandler.pid',
        'daemon': False,
        'umask': 0o077,
    }

    parser = argparse.ArgumentParser(
        description="Listen for new files in " +
                    "dropboxdirs and move to ObenBis/storage",
    )

    parser.add_argument("-c", "--conf-file",
                        help="Specify config file", metavar="FILE",
                        default="~/.dropboxhandler.conf")
    parser.add_argument("--print-example-config",
                        help="Print a example config file to stdout.",
                        action="store_true", default=False)
    parser.add_argument('-d', '--daemon', action='store_true', default=None)
    parser.add_argument('--pidfile', default=None)
    parser.add_argument('--check-config', default=False, action='store_true',
                        help="Do not start the daemon, but check the " +
                        "config file")

    args = parser.parse_args()

    if args.print_example_config:
        print_example_config()
        sys.exit(0)

    try:
        with open(args.conf_file) as f:
            config = yaml.load(f)
    except dropboxhandler.FileNotFoundError:
        error_exit("Could not find config file (default location: " +
                   "~/.dropboxhandler.conf")
    except yaml.parser.ParserError as e:
        error_exit("Could not parse config file. Error was %s" % e)

    for key in ['incoming', 'outgoing', 'openbis', 'options']:
        if key not in config:
            error_exit("Config file must include section '%s'" % key)

    options_default.update(config['options'])
    config['options'] = options_default

    if args.pidfile is not None:
        config['options']['pidfile'] = args.pidfile
    if args.daemon is not None:
        config['options']['daemon'] = args.daemon
    config['check_config'] = args.check_config

    return config


def check_options(options):
    for key in options:
        if key == 'permissions' and options[key] not in [True, False]:
            error_exit("Invalid value for 'permissions' in section 'options'")
        elif key == 'checksum' and options[key] not in [True, False]:
            error_exit("Invalid value for 'checksum' in section 'options'")
        elif key == 'interval' and not isinstance(options[key], numbers.Real):
            error_exit("Invalid value for 'interval' in section 'options'")
            if options[key] <= 0:
                error_exit("'interval' in section 'options' must be positive")
        elif key == 'pidfile' and not os.path.isabs(options[key]):
            error_exit("Invalid value for 'pidfile' in section 'options'")
        elif key == 'pidfile' and os.path.exists(options[key]):
            with open(options[key]) as f:
                if os.getpid() == int(f.read()):
                    continue
            error_exit("pidfile exists. Is the daemon already running?")
        elif key == 'umask' and not isinstance(options[key], int):
            error_exit("Invalid value for 'umask' in section 'options'")
        elif key == 'daemon' and options[key] not in [True, False]:
            error_exit("Invalid value for 'daemon' in section 'options'")


def check_outgoing(conf):
    for key in conf:
        if key not in ['manual', 'storage', 'tmpdir', 'msconvert']:
            error_exit("Invalid path for key %s in section 'outgoing'" % key)
        if not os.path.isabs(conf[key]):
            error_exit("Path in config section 'outgoing' is not absolute: %s"
                       % conf[key])
        if not os.path.isdir(conf[key]):
            error_exit("Path in config is not a directory: %s" % conf[key])


def _user_to_uid(user):
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        error_exit("Invalid user name: %s" % user)


def _group_to_gid(group):
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        error_exit("Invalid group name: %s" % group)


def _check_permission_config(conf):
    for key in conf:
        if key == 'user':
            conf[key] = _user_to_uid(conf[key])
        elif key == 'group':
            conf[key] = _group_to_gid(conf[key])
        elif key in ['filemode', 'dirmode']:
            if not isinstance(conf[key], int):
                error_exit("Invalid value for key %s in section " +
                           "'incoming'" % key)
        else:
            error_exit("Unknown key '%s' in section 'incoming'" % key)


def check_incoming(conf):
    if not isinstance(conf, list):
        error_exit("Config section 'incoming' is not a list")
    for section in conf:
        if 'path' not in section:
            error_exit("Missing key 'path' in section 'incoming'")
        if 'name' not in section:
            error_exit("Missing key 'name' in section 'incoming'")
        if 'perms' in section:
            _check_permission_config(section['perms'])


def check_openbis(config):
    if not isinstance(config, list):
        error_exit("Config section 'openbis' is not a list")
    for conf in config:
        for key in conf:
            if key == 'regexp':
                try:
                    re.compile(conf[key])
                except re.error:
                    error_exit("Invalid regular expression: %s" % conf[key])
            elif key == 'path':
                if not os.path.isdir(conf[key]):
                    error_exit("Not a directory: %s" % conf[key])
                if not os.path.isabs(conf[key]):
                    error_exit("Not an absolute path: %s" % conf[key])
            elif key == 'origin':
                if not isinstance(conf[key], list):
                    error_exit("'origin' in 'openbis' section must be a list")
            elif key == 'match_dir':
                pass
            elif key == 'match_file':
                pass
            else:
                error_exit("Unexpected option %s in section 'openbis'" % key)


def check_configuration(config):
    """ Sanity checks for configuration. """
    check_options(config['options'])
    check_outgoing(config['outgoing'])
    check_incoming(config['incoming'])
    check_openbis(config['openbis'])


if __name__ == '__main__':
    main()
