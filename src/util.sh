#!/bin/bash

# Arguments:
#   1: [install/uninstall]
# 	2: module name
# 	3: port 
# 	4: IP

# Check action
if [ -z "$1" ]; then
	echo "Missing valid action" >&2
fi

ACTION="$1"

if [ "$ACTION" == "install" ]; then

	# Default values
	IP="127.0.0.1"
	PORT="8080"
	MODULE=""

	if [ -z "$2" ]; then
		echo "Missing valid .ko file as input" >&2
		exit 1
	fi

	if [ ! -f "$2.ko" ]; then
		echo "Must create $2.ko before installing. Try 'make' then 'make install'" >&2
		exit 1
	fi

	MODULE="$2"

	if [ ! -z "$3" ]; then
		PORT="$3"
	fi

	if [ ! -z "$4" ]; then
		IP="$4"
	fi

	insmod $MODULE.ko port=$PORT ip=$IP

	if [ $? -eq 0 ]; then
		MAJOR=$(cat /proc/devices | grep $MODULE | awk '{ print $1; }')

		if [ ! -z "$MAJOR" ]; then

			mknod ../tcp$PORT c $MAJOR 0

		fi

	fi

elif [ "$ACTION" == "uninstall" ]; then

	if [ -z "$2" ] || [ ! -f "$2.ko" ]; then
		echo "Missing valid .ko file" >&2 
		exit 1
	fi

	MODULE="$2"

	rmmod $MODULE
	rm -f ../tcp$PORT

else 
	echo "Unknown action" >&2
	exit 1

fi
