# pan-globalprotect-okta

This is a slightly modified version of a [Command-line client for PaloAlto Networks' GlobalProtect
VPN integrated with OKTA](https://github.com/arthepsy/pan-globalprotect-okta).  The changes are as
follows:

- Passes a firefox User-Agent header to Okta in some key places to allow the script to fully log in.
  Some Okta configurations fail to log in without this.
- Does one more step in the authentication dance with the VPN gateway, and only calls `openconnect`
  to establish the final VPN connection.

This utility will do the _authentication dance_ with OKTA to retrieve `portal-userauthcookie`, and
will then pass this on to the VPN login page to retrieve the actual cookie needed to login.  It then
either executes or prints the correct invocation of [OpenConnect with PAN GlobalProtect
support](https://github.com/dlenski/openconnect) for creating actual VPN connection. Compatible with
Python 2 and 3.

Original tested on FreeBSD, Linux and MacOS X, this fork tested only on Linux.

It also supports Google and OKTA two factor authentication and can work without user interaction, if
initial TOTP secret is provided. Otherwise, it will ask for generated code.

To gather TOTP secret, there are two possibilities - either scan the provided QR code with _normal_
QR code scanner and write down the secret. Or create backup from current OTP application in
phone. Some applications have this feature, but some don't. For example, andOTP on Android do
support this feature.

## usage
This utility depends on [requests](http://www.python-requests.org/) and [lxml](https://lxml.de/)
Python libraries. If TOTP secret is being used, then [pyotp](https://github.com/pyotp/pyotp)
is also required.

```
   ./gp-okta.py gp-okta.conf
```


## configuration

Configuration file should be self-explanatory. Options can be overridden with
`GP_` prefixed respective environment variables, e.g., `GP_PASSWORD` will
override `password` option in configuration file.  If you company has multiple gateways,
make sure to select the closest to your location for improved experience.
You can enable debugging to list them when connecting.

NB: It is not wise to store passwords in your config files.

### vpn-slice

[vpn-slice](https://github.com/dlenski/vpn-slice) has been tested to work
and can be set up to [split-tunnel](https://en.wikipedia.org/wiki/Split_tunneling)
your VPN traffic.  Edit the configuration file adding your hosts and networks
as optional arguments to `openconnect` as needed.


## hip check

The hip check script is included as <a href=https://github.com/connorhetzler2/pan-globalprotect-okta/blob/master/hipreport.sh>hipreport.sh</a> this file contains the information that is sent to the hip check, you can change any of the details. The original script that replicates windows can be found here <a href=https://github.com/dlenski/openconnect/blob/HEAD/hipreport.sh>windowsHipReport.sh</a>


## docker

Build Docker image before running container:
```
docker build -t gp-okta .
```

Edit gp-okta.conf and launch Docker container:
```
sh run-docker.sh
```

## known issues

If `openconnect` returns with `ioctl` error, then this version has a bug, which
requires to prefix stdin input with a newline. Set `bug.nl=1` in configuration
file to work-around this issue.
