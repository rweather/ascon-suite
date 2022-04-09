#!/bin/sh
#
# Copies sources and include files to an Arduino utility folder and
# rewrites headers of the form <ascon*/x.h> to "../ascon-x.h".
#
# Usage: copy-utils dir file ...

DEST_DIR="$1"
shift

for i in $* ; do
    BASENAME=`basename $i`
    sed -e '1,$s/<ascon\/\(.*\)>/"..\/ascon-\1"/g' $i >$DEST_DIR/$BASENAME
done

exit 0
