#!/bin/sh

case "$1" in
	list)
		echo '{ "registry_status": { } }'
	;;
	call)
		case "$2" in
			registry_status)
				# return json object or an array
				echo '{
	"registry": [
		{
			"name": "sip0",
			"username": "+3852140873X",
			"refresh": "300",
			"state": "No",
			"reg_time": "Authentication    Authentication"
		},
		{
			"name": "sip1",
			"username": "+38521408731",
			"refresh": "1785",
			"state": "Registered",
			"reg_time": "Mon, 22 Jan 2018 09:47:41"
		}
	]
}
'
			;;
		esac
	;;
esac
