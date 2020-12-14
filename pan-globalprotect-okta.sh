#!/bin/bash

# <bitbar.title>VPN Status</bitbar.title>
# <bitbar.version>v1.1</bitbar.version>
# <bitbar.author>Ventz Petkov</bitbar.author>
# <bitbar.author.github>ventz</bitbar.author.github>
# <bitbar.desc>Connect/Disconnect OpenConnect + show status</bitbar.desc>
# <bitbar.image></bitbar.image>

BASEDIR=$(dirname "$0")

# Command to determine if VPN is connected or disconnected
VPN_CONNECTED="route -n get example.com | awk '/interface: /{print $2}' | grep tun"
# Command to run to disconnect VPN
WORKING_DIR="$BASEDIR/pan-globalprotect-okta/"
VPN_CONNECT_CMD="./gp-okta.py gp-okta.conf"
VPN_DISCONNECT_CMD="sudo killall -2 openconnect"

case $1 in
    connect)
        cd $WORKING_DIR
        $VPN_CONNECT_CMD &
        # Wait for connection so menu item refreshes instantly
        until eval "$VPN_CONNECTED"; do sleep 1; done
        sleep 1
        ;;
    disconnect)
        cd $WORKING_DIR
        $VPN_DISCONNECT_CMD
        # Wait for disconnection so menu item refreshes instantly
        until [ -z "$(eval "$VPN_CONNECTED")" ]; do sleep 1; done
        sleep 1
        ;;
esac


if [ -n "$(eval "$VPN_CONNECTED")" ]; then
    echo "🔐"
    echo '---'
    echo "Disconnect VPN | bash=$0 param1=disconnect terminal=false refresh=true"
    exit
else
    echo "🔓"
    echo '---'
    echo "Connect VPN | bash=$0 param1=connect terminal=false refresh=true"
    exit
fi
