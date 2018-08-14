#!/bin/bash

if [ "$(id -u)" !=  "0" ]  ; then
        echo "Run as root user"
        exit 1
fi

log_file="`pwd`/tests.log"
tarball="nftables-0.8.1.tar.bz2"
dir=../..
cmd=./configure
argument=( --without-cli --enable-debug --with-mini-gmp --enable-man-doc
	    --with-xtables --with-json)
ok=0
failed=0

[ -f $log_file ] && rm -rf $log_file
cd $dir

echo  "Testing build with distcheck"
make distcheck >/dev/null 2>>$log_file
rt=$?

rm -rf $tarball

if [ $rt != 0 ] ; then
	echo "Something went wrong. Check the log for details."
	exit 1
fi

echo -en "\033[1A\033[K"
echo "Build works. Now, testing compile options"

for var in "${argument[@]}" ; do
	echo "[EXECUTING] Testing compile option $var"
	$cmd $var >/dev/null 2>>$log_file
	rt=$?
	echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line

	if [ $rt -eq 0 ] ; then
		echo "[OK] Compile option $var works."
		((ok++))
	else
		echo "[FAILED] Compile option $var does not work. Check log for details."
		((failed++))
	fi
done

echo "results: [OK] $ok [FAILED] $failed [TOTAL] $((ok+failed))"
exit 0
