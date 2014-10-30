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
    echo -n $"Starting $prog: "
    [ -x $exec ] || return 5
    [ -f $config ] || return 6
    [ -f $lockfile ] && return 0
    # USER and USER_CONFIG_FILE must be defined in config
    . $config
    if [ ! -n "$USER" ] ; then
	    echo "missing value USER in config file $config"
	    return 6
    fi
    if [ ! -n "${USER_CONFIG_FILE}" ] ; then
	    echo "missing value USER_CONFIG_FILE in config file $config"
	    return 6
    fi
    if [ ! -f ${USER_CONFIG_FILE} ] ; then
	    echo "user config file not found"
	    return 6
    fi
    su $USER -c "dropboxhandler -c ${USER_CONFIG_FILE} -d --pidfile $pidfile"
    retval=$?
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}

stop() {
    echo -n $"Stopping $prog: "
    [ -f $pidfile ] || return 1
    read pid < $pidfile
    [ -n "$pid" ] || return 1

    kill -TERM $pid
    counter=0
    while [ $counter -lt 500 ]; do
	    [ -z $pidfile ] || break
	    sleep 1
	    let counter=counter+1
    done
    if [ -z $pidfile ] ; then
	    kill -KILL $pid
	    sleep 1
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
retcode=$?
[ $retcode -eq 0 ] && success || failure
echo
exit $retcode
