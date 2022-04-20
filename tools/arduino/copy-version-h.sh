#!/bin/sh
#
# Copies version.h an Arduino library folder and rewrites version markers.
#
# Usage: copy-version-h dest src CMakeLists.txt

DEST_FILE="$1"
SRC_FILE="$2"
CMAKELISTS="$3"

VERSION=`grep 'AsconSuite VERSION' ${CMAKELISTS} | awk '{print $3}' -`
VERSION_MAJOR=`echo "$VERSION" | awk 'BEGIN{FS="."}{print $1}' -`
VERSION_MINOR=`echo "$VERSION" | awk 'BEGIN{FS="."}{print $2}' -`
VERSION_PATCH=`echo "$VERSION" | awk 'BEGIN{FS="."}{print $3}' -`

sed -e '
1,$s/@AsconSuite_VERSION_MAJOR@/'$VERSION_MAJOR'/g
1,$s/@AsconSuite_VERSION_MINOR@/'$VERSION_MINOR'/g
1,$s/@AsconSuite_VERSION_PATCH@/'$VERSION_PATCH'/g
1,$s/\\file /\\file ascon-/g
' "$SRC_FILE" >"$DEST_FILE"

exit 0
