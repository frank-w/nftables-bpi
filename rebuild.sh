#!/bin/bash
#
# Recompile both libnftnl and nftables so that nft does not use the host
# libnftnl anymore.

LIBNFTNL_PATH=/home/$USER/libnftnl
NFT_PATH=/home/$USER/nftables

#cd "$(dirname $0)"

# first libnftnl build
#cd $LIBNFTNL_PATH
#rm -rf install
#./autogen.sh
#./configure --enable-static --prefix="$PWD/install" || {
#	echo "libnftnl: configure failed"
#	exit 1
#}
#make clean
#make || { echo "libnftnl: make failed"; exit 2; }
#make install || { echo "libnftnl: make install failed"; exit 3; }
cd $NFT_PATH

if false; then
# now build nftables and link against static libnftnl
./autogen.sh
./configure --enable-static \
	--prefix="$PWD/install" \
	PKG_CONFIG_PATH="${LIBNFTNL_PATH}/install/lib/pkgconfig" \
        LDFLAGS="-L${LIBNFTNL_PATH}/install/lib/"

#	CFLAGS="-fprofile-arcs -ftest-coverage"
#--enable-shared\
#--with-json \
#--with-xtables \

[[ $? -eq 0 ]] || { echo "nftables: configure failed"; exit 4; }
make clean
fi
make V=1 || { echo "nftables: make failed"; exit 5; }
make install || { echo "nftables: make install failed"; exit 6; }
