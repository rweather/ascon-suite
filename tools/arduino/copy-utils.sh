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
    sed -e '
1,$s/<ascon\/\(.*\)>/"..\/ascon-\1"/g
1,$s/"core\//"utility\//g
1,$s/"aead\//"utility\//g
1,$s/"mac\//"utility\//g
1,$s/"isap\//"utility\//g
1,$s/"kdf\//"utility\//g
1,$s/"random\//"utility\//g
1,$s/"masking\//"utility\//g
1,$s/"version.h"/"..\/ascon-version.h"/g
' $i >$DEST_DIR/$BASENAME
done

exit 0
