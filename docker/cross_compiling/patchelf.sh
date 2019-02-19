#!/usr/bin/env bash

apt-get install -y patchelf

# set linker path
cd /copy_dir/cross_sysrepo
SELF=${0##*/}

PATCHELF=patchelf
TARGETS=${PWD}/root

FAKEROOT=/opt/root

find $TARGETS -type f -a -exec file {} \; | \
  sed -n -e 's/^\(.*\):.*ELF.*\(SB executable\|relocatable\|shared object\|pie executable\).*,.*/\1:\2/p' | \
(
  IFS=":"
  while read F S; do
    echo "$SELF: $F: $S"
	case ${S} in
		"relocatable")
			echo "Removing module: $F"
			rm $F
			;;
		"SB executable")
			b=$(stat -c '%a' $F)
			echo "Patching executable: $F"
			[ -z $INTERPRETER ] && INTERPRETER=$($PATCHELF --print-interpreter $F)
			$PATCHELF --set-interpreter "${FAKEROOT}${INTERPRETER}" $F
			$PATCHELF --set-rpath "$FAKEROOT/lib" $F
			a=$(stat -c '%a' $F)
			[ "$a" = "$b" ] || chmod $b $F
			;;
		"shared object"|"pie executable")
			deps=$($PATCHELF --print-needed $F | wc -l)
			if [ $deps -eq 0 ]
			then
				echo "Stripping shared object: $F"
				b=$(stat -c '%a' $F)
				a=$(stat -c '%a' $F)
				[ "$a" = "$b" ] || chmod $b $F
			else
				echo "Patching shared object: $F"
				$PATCHELF --set-rpath "$FAKEROOT/lib" $F
			fi
			;;
	esac
  done
  true
)

# tar
tar -cvf root.tar root
