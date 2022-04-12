#!/bin/sh
#
# Copies source files to an Arduino library folder and rewrites headers
# of the form <ascon*/x.h> to "ascon-x.h".
#
# Usage: copy-sources.sh dir file ...

DEST_DIR="$1"
shift

for i in $* ; do
    BASENAME=`basename $i`
    sed -e '
1,$s/<ascon\/\(.*\)>/"ascon-\1"/g
1,$s/"core\//"utility\//g
1,$s/"aead\//"utility\//g
1,$s/"mac\//"utility\//g
' $i >$DEST_DIR/$BASENAME
done

exit 0
