# NFTABLES userspace tool

this version has support for offload flags in flowtable

fork from git://git.netfilter.org/nftables

## native compilation

apt-get install --no-install-recommends git make gcc dh-autoreconf bison flex asciidoc libmnl-dev pkg-config libgmp-dev libreadline-dev libreadline-dev docbook-xsl xsltproc libxml2-utils

run rebuild.sh

(taken from https://www.spinics.net/lists/netfilter-devel/msg66323.html and slightly modified)

## crosscompile (binary not yet tested)

just for documenting my steps :)

```
apt-get install --no-install-recommends git make gcc dh-autoreconf bison flex asciidoc pkg-config docbook-xsl xsltproc libxml2-utils

git clone https://git.netfilter.org/libmnl
git clone git://git.netfilter.org/libnftnl
#git clone git://git.netfilter.org/nftables
git clone https://github.com/frank-w/nftables-bpi.git nftables

#build libmnl for armhf
cd libmnl
mkdir -p install
sh autogen.sh
sh configure --host=arm-linux-gnueabihf --prefix=$(pwd)/install
make
make install

#build libnftnl
cd ../libnftnl/
mkdir -p install
sh autogen.sh
BASE="$(pwd)/..";
./configure --host=arm-linux-gnueabihf --prefix=$(pwd)/install LIBMNL_LIBS=$BASE/libmnl/install/lib LIBMNL_CFLAGS=$BASE/libmnl/include/
make clean
make
make install

#build nft
cd ../nftables/
mkdir -p install
sh autogen.sh
./configure --host=arm-linux-gnueabihf --prefix=$(pwd)/install PKG_CONFIG_PATH="$BASE/libnftnl/install/lib/pkgconfig:$BASE/libmnl/install/lib/pkgconfig" --with-mini-gmp --without-cli
make clean
make
make install
```
