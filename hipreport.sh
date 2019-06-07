#!/bin/sh

# openconnect will call this script with the follow command-line
# arguments, which are needed to populate the contents of the
# HIP report:
#
#   --cookie: a URL-encoded string, as output by openconnect
#             --authenticate --protocol=gp, which includes parameters
#             from the /ssl-vpn/login.esp response
#
#   --client-ip: IPv4 address allocated by the GlobalProtect VPN for
#                this client (included in /ssl-vpn/getconfig.esp
#                response)
#
#   --md5: The md5 digest to encode into this HIP report. I'm not sure
#          exactly what this is the md5 digest *of*, but all that
#          really matters is that the value in the HIP report
#          submission should match the value in the HIP report check.

# Read command line arguments into variables
COOKIE=
IP=
MD5=

while [ "$1" ]; do
    if [ "$1" = "--cookie" ];    then shift; COOKIE="$1"; fi
    if [ "$1" = "--client-ip" ]; then shift; IP="$1"; fi
    if [ "$1" = "--md5" ];       then shift; MD5="$1"; fi
    shift
done

if [ -z "$COOKIE" -o -z "$IP" -o -z "$MD5" ]; then
    echo "Parameters --cookie, --computer, --client-ip, and --md5 are required" >&2
    exit 1;
fi

# Extract username and domain and computer from cookie
USER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)user=([^&]+)(&.+|$)/\2/p')
DOMAIN=$(echo "$COOKIE" | sed -rn 's/(.+&|^)domain=([^&]+)(&.+|$)/\2/p')
COMPUTER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)computer=([^&]+)(&.+|$)/\2/p')

# Timestamp in the format expected by GlobalProtect server
NOW=$(date +'%m/%d/%Y %H:%M:%S')

# This value may need to be extracted from the official HIP report, if a made-up value is not accepted.
HOSTID=$(hostid)
OS=$(lsb_release -d -s)
CLIENTVERSION=$(lsb_release -r -s)
OSVENDER=$(lsb_release -i -s)
NICDESCRIPTION=$(ip route get 1.1.1.1 | grep -Po '(?<=dev\s)\w+')
MACADDRESS=$(cat /sys/class/net/$NICDESCRIPTION/address)


cat <<EOF
<hip-report name="hip-report">
	<md5-sum>$MD5</md5-sum>
	<user-name>$USER</user-name>
	<domain>$DOMAIN</domain>
	<host-name>$COMPUTER</host-name>
	<host-id>$HOSTID</host-id>
	<ip-address>$IP</ip-address>
	<ipv6-address></ipv6-address>
	<generate-time>$NOW</generate-time>
	<categories>
		<entry name="host-info">
			<client-version>$CLIENTVERSION</client-version>
			<os>$OS databricks linux-64</os>
			<os-vendor>$OSVENDER</os-vendor>
			<domain>$DOMAIN.internal</domain>
			<host-name>$COMPUTER</host-name>
			<host-id>$HOSTID</host-id>
			<network-interface>
				<entry name="{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}">
					<description>$NICDESCRIPTION</description>
					<mac-address>$MACADDRESS</mac-address>
					<ip-address>
						<entry name="$IP"/>
					</ip-address>
				</entry>
			</network-interface>
		</entry>
	</categories>
</hip-report>
EOF
