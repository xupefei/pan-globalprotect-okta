
# pan-globalprotect-okta for macOS

![preview](https://user-images.githubusercontent.com/1687847/102121029-9d6f9a80-3e43-11eb-8ccf-2ba4197dcfd3.png)

This is a modified version of pan-globalprotect-okta to let it works on macOS with menubar shortcuts.

This project makes use of the following:

- [pan-globalprotect-okta](https://github.com/nicklan/pan-globalprotect-okta)
- [openconnect-gui-menu-bar](https://github.com/ventz/openconnect-gui-menu-bar)

## How to use

1. Get openconnect: `brew install openconnect`.
2. Get BitBar: https://github.com/matryer/bitbar/releases (v1.9.2 is the latest version runs on Catalina) or `brew cask install bitbar`.
3. Enable no-password openconnect:
	```bash
	$ sudo echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/local/bin/openconnect" > /etc/sudoers.d/openconnect
	$ sudo echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/killall -2 openconnect" >> /etc/sudoers.d/openconnect
	```
4. Modify `gp-okta.conf`. URLs and IPs in `openconnect_args` will be redirected through the VPN gateway.
5. Edit Line 13 of `pan-globalprotect-okta.sh`, modify the domain name to one of proxied URLs in the previous step.
6. Save your password and OTP secret into macOS Keychain:
	```
	a.) Open "Keychain Access",
	b.) Click on "login" keychain (top left corner),
	c.) Click on "Passwords" category (bottom left corner),
	d.) From the "File" menu, select "New Password Item...",
	e.) Creating the following passwords:
	    i.) Item name: vpn_url in gp-okta.conf
	        Account name: username in gp-okta.conf
	        Password: your Okta password
	    ii.) Item name: okta_url in gp-okta.conf
	         Account name (it will look like "user@company.com#totp.google"):
	           username+"#totp.google" (if you use Google Authenticator), or
	           username+"#totp.okta" (if you use Okta Verify)
	         Password: the OTP secret, 16 upper-case alphabets
	```
7. Try to run `./gp-okta.py gp-okta.conf` in your console. Install any missing pip packages. On my machine, I have to execute `pip3 install pyotp keyring python-u2flib-host lxml`
8. Copy the whole folder to BitBar script directory.
9. Run BitBar and try to connect to the VPN.
