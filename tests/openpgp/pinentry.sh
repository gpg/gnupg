#!/bin/sh
# Copyright 2011 Free Software Foundation, Inc.
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.  This file is
# distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY, to the extent permitted by law; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

echo "OK - what's up?"
while read cmd rest; do
  echo "cmd=$cmd rest=$rest" >&2
  case "$cmd" in
    \#*)
      ;;
    GETPIN)
      echo "D ${PINENTRY_USER_DATA}"
      echo "OK"
      ;;
    BYE)
      echo "OK"
      exit 0
      ;;
    *)
      echo "OK"
      ;;
  esac
done
