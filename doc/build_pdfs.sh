#!/bin/sh
for i in *.adoc nft.txt; do a2x --doctype manpage --format pdf $i; done
exit

# (This script needs dblatex in addition to the man page build requirements).
# This script builds PDF versions of the man pages.
# Distributors may like to place these in e.g. $DOCDIR/pdf.
# As an example, these are the changes for the Slackware build script:

8<--------------------8<--------------------8<--------------------

*** nftables.SlackBuild 2018/06/05 00:30:03     1.7
--- nftables.SlackBuild 2018/08/17 01:14:20
***************
*** 22,28 ****
  
  PKGNAM=nftables
  VERSION=${VERSION:-$(echo $PKGNAM-*.tar.?z* | rev | cut -f 3- -d . | cut -f 1 -d - | rev)}
! BUILD=${BUILD:-2}
  DEBUG=${DEBUG:-false}
  
  NUMJOBS=${NUMJOBS:-" -j7 "}
--- 22,28 ----
  
  PKGNAM=nftables
  VERSION=${VERSION:-$(echo $PKGNAM-*.tar.?z* | rev | cut -f 3- -d . | cut -f 1 -d - | rev)}
! BUILD=${BUILD:-3}
  DEBUG=${DEBUG:-false}
  
  NUMJOBS=${NUMJOBS:-" -j7 "}
***************
*** 114,121 ****
    )
  fi
  
! mkdir -p $PKG/usr/doc/$PKGNAM-$VERSION
  cp -a COPYING* INSTALL* $PKG/usr/doc/$PKGNAM-$VERSION
  
  mkdir -p $PKG/install
  cat $CWD/slack-desc > $PKG/install/slack-desc
--- 114,123 ----
    )
  fi
  
! mkdir -p $PKG/usr/doc/$PKGNAM-$VERSION/pdf
  cp -a COPYING* INSTALL* $PKG/usr/doc/$PKGNAM-$VERSION
+ (cd doc; ./build_pdfs.sh)
+ cp -a doc/*.pdf $PKG/usr/doc/$PKGNAM-$VERSION/pdf
  
  mkdir -p $PKG/install
  cat $CWD/slack-desc > $PKG/install/slack-desc
