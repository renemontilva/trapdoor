#! /bin/sh
#
# trapdoor2	HTTPS Trapdoor start/stop script
#
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian GNU/Linux
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
#		by Philipp Richter <philipp.richter@linbit.com>


PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/td2
NAME=trapdoor2
DESC=trapdoor2
CHROOT_DIR=/var/run/trapdoor2

test -f $DAEMON || exit 0

set -e

check_chroot_dir() {
    if [ ! -d $CHROOT_DIR ]; then
        mkdir $CHROOT_DIR
        chmod 0755 $CHROOT_DIR
    fi
    if [ ! -d $CHROOT_DIR/dev ]; then
        mkdir $CHROOT_DIR/dev
        chmod 0755 $CHROOT_DIR/dev
    fi
    if [ ! -c $CHROOT_DIR/dev/urandom ]; then
        mknod $CHROOT_DIR/dev/urandom c 1 9
        chmod 0444 $CHROOT_DIR/dev/urandom
    fi
}

case "$1" in
  start)
	echo -n "Starting $DESC: "
	check_chroot_dir
	start-stop-daemon --start --quiet --exec $DAEMON
	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
	start-stop-daemon --oknodo --stop --quiet --exec $DAEMON
	echo "$NAME."
	;;
  reload)
	echo -n "Reloading $DESC configuration..."
	if start-stop-daemon --stop --quiet --exec $DAEMON --signal HUP ; then
		echo "done."
	else
		echo "$DESC not running."
	fi
	;;
  restart|force-reload)
	$0 stop
	$0 start
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
