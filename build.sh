#!/bin/bash

#git clone https://github.com/frank-w/nftables-bpi.git nftables

echo "installing depencies"

function check_dep()
{
    PACKAGE_Error=0

    grep -i 'ubuntu\|debian' /etc/issue &>/dev/null
    if [[ $? -ne 0 ]];then
        echo "depency-check currently only on debian/ubuntu..."
        return 0;
    fi
    PACKAGES=$(dpkg -l | awk '{print $2}')

    NEEDED_PKGS="git make gcc dh-autoreconf bison flex asciidoc pkg-config docbook-xsl xsltproc libxml2-utils"

    #echo "needed: $NEEDED_PKGS"

#    if [[ $# -ge 1 ]];
#    then
        if [[ $board == "bpi-r64" ]];then
            NEEDED_PKGS+="gcc-aarch64-linux-gnu"
        elif [[ $board == "bpi-r2" ]];then
            NEEDED_PKGS+="gcc-arm-linux-gnueabihf"
        fi
#    fi

    echo "needed: $NEEDED_PKGS"
    for package in $NEEDED_PKGS; do
        #TESTPKG=$(dpkg -l |grep "\s${package}")
        TESTPKG=$(echo "$PACKAGES" |grep "^${package}")
        if [[ -z "${TESTPKG}" ]];then echo "please install ${package}";PACKAGE_Error=1;fi
    done
    if [ ${PACKAGE_Error} == 1 ]; then return 1; fi
    return 0;
}

check_dep
#sudo apt-get install --no-install-recommends git make gcc dh-autoreconf bison flex asciidoc pkg-config docbook-xsl xsltproc libxml2-utils

git clone https://git.netfilter.org/libmnl
git clone git://git.netfilter.org/libnftnl
#git clone git://git.netfilter.org/nftables

board="bpi-r2"
#board="bpi-r64"

if [[ "$board" == "bpi-r64" ]];then
	hostcc=aarch64-linux-gnu
else
	hostcc=arm-linux-gnueabihf
fi

BASE="$(pwd)";

#build libmnl for armhf
cd libmnl
mkdir -p install
sh autogen.sh
sh configure --host=$hostcc --prefix=$(pwd)/install
if [[ $? -eq 0 ]];then
	make clean
	make
	if [[ $? -eq 0 ]];then
		make install
	fi
fi
if [[ $? -ne 0 ]];then
	echo "building libmnl failed"
	exit 1
fi

#build libnftnl
cd ../libnftnl/
mkdir -p install
sh autogen.sh
./configure --host=$hostcc --prefix=$(pwd)/install LIBMNL_LIBS=$BASE/libmnl/install/lib LIBMNL_CFLAGS=$BASE/libmnl/include/
if [[ $? -eq 0 ]];then
	make clean
	make
	if [[ $? -eq 0 ]];then
		make install
	fi
fi
if [[ $? -ne 0 ]];then
	echo "building libnftnl failed"
	exit 1
fi

#build nft
cd $BASE
mkdir -p install
sh autogen.sh
./configure --host=$hostcc --prefix=$(pwd)/install PKG_CONFIG_PATH="$BASE/libnftnl/install/lib/pkgconfig:$BASE/libmnl/install/lib/pkgconfig" --with-mini-gmp --without-cli --disable-debug --disable-man-doc --disable-python
if [[ $? -eq 0 ]];then
	make clean
	make
	if [[ $? -eq 0 ]];then
		make install
	fi
fi
if [[ $? -ne 0 ]];then
	echo "building nftables failed"
	exit 1
else
	echo "building nftables done :)"
	tar -cvf nftables_$board.tar.gz install/* libnftnl/install/* libmnl/install/*
fi
