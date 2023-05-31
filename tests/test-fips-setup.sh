#!/bin/sh

current_policy="$(update-crypto-policies --show)"

if [ -z "$current_policy" ]; then
	exit 1
fi

action1=--enable
action2=--disable

check_fips_enabled () {
	if ! fips-mode-setup --is-enabled;then
		echo "FIPS --is-enabled did not detect FIPS mode!"
		# do not bother checking in containers that are not
		# running in FIPS enabled kernels.
		if test -e /proc/sys/crypto/fips_enabled;then
			exit 1
		fi
	fi
}

check_fips_disabled () {
	if fips-mode-setup --is-enabled;then
		echo "FIPS --is-enabled detected FIPS mode when it shouldn't!"
		exit 1
	fi
}

if fips-mode-setup --is-enabled; then
	action1=--disable
	action2=--enable
fi

fips-mode-setup --no-bootcfg $action1 || exit $?

if [ $action1 = --enable ] ; then
	[ ! -d /etc/dracut.conf.d ] || [ -f /etc/dracut.conf.d/40-fips.conf ] || exit 3
	grep -q FIPS ${CONFDIR}/config || exit $?

	check_fips_enabled
else
	check_fips_disabled
fi

fips-mode-setup --no-bootcfg $action2 || exit $?

if [ $action2 = --enable ]; then
	[ ! -d /etc/dracut.conf.d ] || [ -f /etc/dracut.conf.d/40-fips.conf ] || exit 3
	grep -q FIPS ${CONFDIR}/config || exit $?

	check_fips_enabled
else
	check_fips_disabled
fi

if [ $current_policy != FIPS ] ; then
	update-crypto-policies --set $current_policy || exit $?
fi

exit 0
