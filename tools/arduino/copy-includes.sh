#!/bin/sh
#
# Copies include files to an Arduino library folder and rewrites headers
# of the form <ascon*/x.h> to "ascon-x.h".  Also rename the files from
# "x.h" to "ascon-x.h".
#
# Usage: copy-includes dir file ...

DEST_DIR="$1"
shift

for i in $* ; do
    BASENAME=`basename $i`
    sed -e '
1,$s/<ascon\/\(.*\)>/"ascon-\1"/g
1,$s/\\file /\\file ascon-/g
' $i >$DEST_DIR/ascon-$BASENAME
done

exit 0
