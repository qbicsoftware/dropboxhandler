#!/bin/sh
#
# dropboxhandler sort files from incoming dropboxes to openbis dropboxes
#
# chkconfig:   - 30 70
# description: Sort files from incoming dropboxes to openbis dropboxes

# Source function library.
. /etc/rc.d/init.d/functions

exec="/usr/bin/dropboxhandler"
prog="dropboxhandler"
config="/etc/dropboxhandler.conf"

[ -e /etc/sysconfig/$prog ] && . /etc/sysconfig/$prog

lockfile=/var/lock/subsys/$prog
pidfile=/var/run/${prog}.pid

start() {
    [ -x $exec ] || exit 5
    [ -f $config ] || exit 6
    [ -f $lockfile ] || exit 0
    echo -n $"Starting $prog: "
    # USER and USER_CONFIG_FILE must be defined in config
    . $config
    [ -n "$USER" ] || exit 6
    [ -n "$USER_CONFIG_FILE" ] || exit 6
    [ -f $USER_CONFIG_FILE ] || exit 6
    su $USER -c "dropboxhandler -c ${USER_CONFIG_FILE} -d --pidfile $pidfile"
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $?
}

stop() {
    echo -n $"Stopping $prog: "
    [ -f $pidfile ] || exit 0

    kill -TERM $(cat $lockfile)
    counter=0
    while [ $counter -lt 500 ]; do
	    [ -z $pidfile ] || break
	    sleep 1
	    let counter=counter+1
    done
    if [ -z $pidfile ] ; then
	    kill -KILL $(cat $pidfile)
	    rm -f $pidfile
    fi
    rm -f $lockfile
    return 0
}

restart() {
    stop
    start
}

reload() {
    restart
}

force_reload() {
    restart
}

rh_status() {
    # run checks to determine if the service is running or use generic status
    status $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}


case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    force-reload)
        force_reload
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
        restart
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart|reload|force-reload}"
        exit 2
esac
exit $?
