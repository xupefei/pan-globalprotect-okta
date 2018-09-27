#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)

   Copyright (C) 2018 Nick Lanham (nick@afternight.org)
   Copyright (C) 2018 Andris Raugulis (moo@arthepsy.eu)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
from __future__ import print_function
import io, os, sys, re, json, base64, getpass, subprocess, shlex, signal
from lxml import etree
import requests
import time

try:
    from urllib import urlencode
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlencode, urlparse

try:
    from u2flib_host import u2f, exc, __version__
    from u2flib_host.constants import APDU_USE_NOT_SATISFIED
    haveu2f = True
except ImportError:
    print('[INFO] Could not import u2flib_host package, will not be able to do U2F 2FA')
    haveu2f = False

import xml.etree.ElementTree as ET

ffuastr = "Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0"

try:
    input = raw_input
except NameError:
    pass

if sys.version_info >= (3, ):
    text_type = str
    binary_type = bytes
else:
    text_type = unicode
    binary_type = str

to_b = lambda v: v if isinstance(v, binary_type) else v.encode('utf-8')
to_u = lambda v: v if isinstance(v, text_type) else v.decode('utf-8')


def log(s):
    print('[INFO] {0}'.format(s), file=sys.stderr)


def dbg(d, h, *xs):
    if not d:
        return
    print('# {0}:'.format(h))
    for x in xs:
        print(x)
    print('---')


def err(s):
    print('err: {0}'.format(s), file=sys.stderr)
    sys.exit(1)


def reprr(r):
    return 'status code: {0}, text:\n{1}'.format(r.status_code, r.text)


def parse_xml(xml):
    try:
        xml = bytes(bytearray(xml, encoding='utf-8'))
        parser = etree.XMLParser(ns_clean=True, recover=True)
        return etree.fromstring(xml, parser)
    except:
        err('failed to parse xml')


def parse_html(html):
    try:
        parser = etree.HTMLParser()
        return etree.fromstring(html, parser)
    except:
        err('failed to parse html')


def parse_rjson(r):
    try:
        return r.json()
    except:
        err('failed to parse json')


def hdr_json():
    return {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': ffuastr,
    }


def parse_form(html):
    xform = html.find('.//form')
    url = xform.attrib.get('action', '').strip()
    data = {}
    for xinput in html.findall('.//input'):
        k = xinput.attrib.get('name', '').strip()
        v = xinput.attrib.get('value', '').strip()
        if len(k) > 0 and len(v) > 0:
            data[k] = v
    return url, data


def load_conf(cf):
    conf = {}
    keys = ['vpn_url', 'username', 'password', 'okta_url']
    with io.open(cf, 'r', encoding='utf-8') as fp:
        for rline in fp:
            line = rline.strip()
            mx = re.match('^\s*([^=\s]+)\s*=\s*(.*?)\s*(?:#\s+.*)?\s*$', line)
            if mx:
                k, v = mx.group(1).lower(), mx.group(2)
                if k.startswith('#'):
                    continue
                for q in '"\'':
                    if re.match('^{0}.*{0}$'.format(q), v):
                        v = v[1:-1]
                conf[k] = v
    for k, v in os.environ.items():
        k = k.lower()
        if k.startswith('gp_'):
            k = k[3:]
            if len(k) == 0:
                continue
            conf[k] = v.strip()
    if len(conf.get('username', '').strip()) == 0:
        sys.stderr.write('username: ')
        conf['username'] = input().strip()
    if len(conf.get('password', '').strip()) == 0:
        conf['password'] = getpass.getpass('password: ').strip()
    if 'root_cert_file' not in conf:
        conf['root_cert_file'] = "/tmp/pan-globalprotect-root.cert"
        log('will write root cert to %s' % conf['root_cert_file'])
    for k in keys:
        if k not in conf:
            err('missing configuration key: {0}'.format(k))
        else:
            if len(conf[k].strip()) == 0:
                err('empty configuration key: {0}'.format(k))
    conf['debug'] = conf.get('debug', '').lower() in ['1', 'true']
    return conf


def paloalto_prelogin(conf, s):
    log('prelogin request')
    r = s.get('{0}/global-protect/prelogin.esp'.format(conf.get('vpn_url')))
    if r.status_code != 200:
        err('prelogin request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'prelogin.response', reprr(r))
    x = parse_xml(r.text)
    saml_req = x.find('.//saml-request')
    if saml_req is None:
        err('did not find saml request')
    if len(saml_req.text.strip()) == 0:
        err('empty saml request')
    try:
        saml_raw = base64.b64decode(saml_req.text)
    except:
        err('failed to decode saml request')
    dbg(conf.get('debug'), 'prelogin.decoded', saml_raw)
    saml_xml = parse_html(saml_raw)
    return saml_xml


def okta_saml(conf, s, saml_xml):
    log('okta saml request')
    url, data = parse_form(saml_xml)
    r = s.post(url, data=data)
    if r.status_code != 200:
        err('okta saml request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'saml.response', reprr(r))
    c = r.text
    rx_base_url = re.search(r'var\s*baseUrl\s*=\s*\'([^\']+)\'', c)
    rx_from_uri = re.search(r'var\s*fromUri\s*=\s*\'([^\']+)\'', c)
    if rx_base_url is None:
        err('did not find baseUrl in response')
    if rx_from_uri is None:
        err('did not find fromUri in response')
    base_url = to_b(rx_base_url.group(1)).decode('unicode_escape').strip()
    from_uri = to_b(rx_from_uri.group(1)).decode('unicode_escape').strip()
    if from_uri.startswith('http'):
        redirect_url = from_uri
    else:
        redirect_url = base_url + from_uri
    return redirect_url


def okta_auth(conf, s):
    log('okta auth request')
    url = '{0}/api/v1/authn'.format(conf.get('okta_url'))
    data = {
        'username': conf.get('username'),
        'password': conf.get('password'),
        'options': {
            'warnBeforePasswordExpired': True,
            'multiOptionalFactorEnroll': True
        }
    }
    r = s.post(url, headers=hdr_json(), data=json.dumps(data))
    if r.status_code != 200:
        err('okta auth request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'auth.response', reprr(r))
    j = parse_rjson(r)
    status = j.get('status', '').strip()
    dbg(conf.get('debug'), 'status', status)
    if status.lower() == 'success':
        session_token = j.get('sessionToken', '').strip()
    elif status.lower() == 'mfa_required':
        session_token = okta_mfa(conf, s, j)
    else:
        print(j)
        err('unknown status')
    if len(session_token) == 0:
        err('empty session token')
    return session_token


def okta_mfa(conf, s, j):
    state_token = j.get('stateToken', '').strip()
    if len(state_token) == 0:
        err('empty state token')
    factors_json = j.get('_embedded', {}).get('factors', [])
    if len(factors_json) == 0:
        err('no factors found')
    factors = []
    for factor in factors_json:
        factor_id = factor.get('id', '').strip()
        factor_type = factor.get('factorType', '').strip().lower()
        provider = factor.get('provider', '').strip().lower()
        factor_url = factor.get('_links', {}).get('verify', {}).get('href')
        if len(factor_type) == 0 or len(provider) == 0 or len(factor_url) == 0:
            continue
        factors.append({
            'id': factor_id,
            'type': factor_type,
            'provider': provider,
            'url': factor_url
        })
    dbg(conf.get('debug'), 'factors', factors)
    if len(factors) == 0:
        err('no factors found')

    u2f_factors = [
        x for x in factors if x.get('type') == 'u2f'
    ]
    if len(u2f_factors) > 0 and haveu2f:
        u2f_resp = okta_mfa_u2f(conf, s, u2f_factors, state_token)
        if u2f_resp:
            return u2f_resp

    totp_factors = [
        x for x in factors if x.get('type') == 'token:software:totp'
    ]
    dbg(conf.get('debug'), 'topt_factors', totp_factors)
    if len(totp_factors) == 0:
        err('no totp factors found')
    return okta_mfa_totp(conf, s, totp_factors, state_token)

def do_u2f_sign(conf, devices, auth_request_data, facet, state_token):
        for device in devices[:]:
            try:
                device.open()
            except:
                devices.remove(device)
        try:
            prompted = False
            while devices:
                for device in devices:
                    try:
                        signed = u2f.authenticate(device,
                                                  auth_request_data,
                                                  facet,
                                                  False)
                        dbg(conf.get('debug'), 'signed.result', signed)
                        return {
                            'stateToken': state_token,
                            'clientData': signed['clientData'],
                            'signatureData': signed['signatureData']
                        }
                    except exc.APDUError as e:
                        if e.code == APDU_USE_NOT_SATISFIED:
                            if not prompted:
                                sys.stderr.write('\nTouch the U2F device to authenticate...\n')
                                prompted = True
                        else:
                            device.close()
                            devices.remove(device)
                    except exc.DeviceError:
                        device.close()
                        devices.remove(device)
                time.sleep(0.25)
        finally:
            for device in devices:
                device.close()
        sys.stderr.write('\nFailed to sign via u2f key\n')
        return None

def okta_mfa_u2f(conf, s, factors, state_token):
    devices = u2f.list_devices()
    if not devices:
        err('no u2f devices found')
        return None
    for factor in factors:
        provider = factor.get('provider', '')
        log('mfa {0} challenge request'.format(provider))
        r = s.post(
            factor.get('url'),
            headers=hdr_json(),
            data = json.dumps({
                'stateToken': state_token
            })
        )
        if r.status_code != 200:
            err('okta mfa challenge request failed. {0}'.format(reprr(r)))
        dbg(conf.get('debug'), 'challenge.response', r.status_code, r.text)
        j = parse_rjson(r)
        factor = j['_embedded']['factor']
        profile = factor['profile']
        auth_request_data = {
            'appId': profile['appId'],
            'keyHandle': profile['credentialId'],
            'version': profile['version'],
            'challenge': factor['_embedded']['challenge']['nonce']
        }
        signed = do_u2f_sign(conf, devices, auth_request_data, profile['appId'], state_token)
        if signed:
            log('mfa {0} signed request'.format(provider))
            r = s.post(
                j['_links']['next']['href'],
                headers=hdr_json(),
                data = json.dumps(signed)
            )
            if r.status_code != 200:
                err('okta mfa signed request failed. {0}'.format(reprr(r)))
            dbg(conf.get('debug'), 'u2d.next.resp', r.status_code, r.text)
            j = parse_rjson(r)
            return j.get('sessionToken', '').strip()
        else:
            return None

def okta_mfa_totp(conf, s, factors, state_token):
    for factor in factors:
        provider = factor.get('provider', '')
        secret = conf.get('totp.{0}'.format(provider))
        if secret is None:
            order = 2
        elif len(secret) == 0:
            order = 1
        else:
            order = 0
        factor['order'] = order
    for factor in sorted(factors, key=lambda x: x.get('order', 0)):
        provider = factor.get('provider', '')
        secret = conf.get('totp.{0}'.format(provider), '') or ''
        code = None
        if len(secret) == 0:
            sys.stderr.write('{0} TOTP: '.format(provider))
            code = input().strip()
        else:
            import pyotp
            totp = pyotp.TOTP(secret)
            code = totp.now()
        code = code or ''
        if len(code) == 0:
            continue
        data = {
            'factorId': factor.get('id'),
            'stateToken': state_token,
            'passCode': code
        }
        log('mfa {0} totp request'.format(provider))
        r = s.post(
            factor.get('url'), headers=hdr_json(), data=json.dumps(data))
        if r.status_code != 200:
            err('okta mfa request failed. {0}'.format(reprr(r)))
        dbg(conf.get('debug'), 'mfa.response', r.status_code, r.text)
        j = parse_rjson(r)
        return j.get('sessionToken', '').strip()
    err('no totp was processed')


def okta_redirect(conf, s, session_token, redirect_url):
    data = {
        'checkAccountSetupComplete': 'true',
        'repost': 'true',
        'token': session_token,
        'redirectUrl': redirect_url
    }
    url = '{0}/login/sessionCookieRedirect'.format(conf.get('okta_url'))
    log('okta redirect request')

    r = s.post(url, data=data)
    if r.status_code != 200:
        err('redirect request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'redirect.response', r.status_code, r.text)
    xhtml = parse_html(r.text)

    url, data = parse_form(xhtml)

    log('okta redirect form request')
    r = s.post(url, data=data)
    if r.status_code != 200:
        err('redirect form request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'form.response', r.status_code, r.text)
    saml_username = r.headers.get('saml-username', '').strip()
    if len(saml_username) == 0:
        err('saml-username empty')
    saml_auth_status = r.headers.get('saml-auth-status', '').strip()
    saml_slo = r.headers.get('saml-slo', '').strip()
    prelogin_cookie = r.headers.get('prelogin-cookie', '').strip()
    if len(prelogin_cookie) == 0:
        err('prelogin-cookie empty')
    return saml_username, prelogin_cookie


def paloalto_getconfig(conf, s, saml_username, prelogin_cookie):
    log('getconfig request')
    url = '{0}/global-protect/getconfig.esp'.format(conf.get('vpn_url'))
    data = {
        'user': saml_username,
        'passwd': '',
        'inputStr': '',
        'clientVer': '4100',
        'clientos': 'Windows',
        'clientgpversion': '4.1.0.98',
        'computer': 'DESKTOP',
        'os-version': 'Microsoft Windows 10 Pro, 64-bit',
        # 'host-id': '00:11:22:33:44:55'
        'prelogin-cookie': prelogin_cookie,
        'ipv6-support': 'yes'
    }
    r = s.post(url, data=data)
    if r.status_code != 200:
        err('getconfig request failed. {0}'.format(reprr(r)))
    dbg(conf.get('debug'), 'getconfig.response', reprr(r))
    x = parse_xml(r.text)
    xtmp = x.find('.//portal-userauthcookie')
    if xtmp is None:
        err('did not find portal-userauthcookie')
    portal_userauthcookie = xtmp.text
    if len(portal_userauthcookie) == 0:
        err('empty portal_userauthcookie')

    gateway = x.find('.//gateways//entry').get('name')
    root_cert = x.find('.//entry[@name="RootCert"]/cert').text
    with open(conf['root_cert_file'], 'w') as root_cert_file:
        root_cert_file.write(root_cert)

    return portal_userauthcookie, gateway


def globalprotect_login(conf, s, gateway, username, authcookie):
    log('global protect login')
    url = 'https://{0}/ssl-vpn/login.esp'.format(gateway)
    endpoint = urlparse(url)
    computer = os.uname()[1]

    data = dict(
        user=username,
        passwd=conf['password'],
        # required
        jnlpReady='jnlpReady',
        ok='Login',
        direct='yes',
        clientos='Windows',
        # optional but might affect behavior
        clientVer=4100,
        server=endpoint.netloc,
        prot='https:',
        computer=computer)
    # do auth like this as we have hyphens in the keys
    data['portal-userauthcookie'] = authcookie
    data['portal-prelogonuserauthcookie'] = "empty"
    data['prelogin-cookie'] = ""
    r = s.post(url, verify=conf['root_cert_file'], data=data)
    if r.status_code != 200:
        err('login request failed. {0}'.format(reprr(r)))

    # build openconnect "cookie" if the result is a <jnlp>
    try:
        xml = ET.fromstring(r.text)
    except Exception as e:
        print("got exception %s" % e)
        xml = None

    if xml.tag == 'jnlp':
        arguments = [(t.text or '') for t in xml.iter('argument')]
        cookie = urlencode({
            'authcookie':
            arguments[1],
            'portal':
            arguments[3],
            'user':
            arguments[4],
            'domain':
            arguments[7],
            'computer':
            computer,
            'preferred-ip':
            arguments[15] if len(arguments) >= 16 else ''
        })
        return cookie
    return None


def main():
    if len(sys.argv) < 2:
        print('usage: {0} <conf>'.format(sys.argv[0]))
        sys.exit(1)
    conf = load_conf(sys.argv[1])

    s = requests.Session()
    s.headers['User-Agent'] = 'PAN GlobalProtect'
    saml_xml = paloalto_prelogin(conf, s)
    redirect_url = okta_saml(conf, s, saml_xml)
    # sets the various cookies we need for automated okta login
    r = s.get(redirect_url, headers={"User-Agent": ffuastr})
    token = okta_auth(conf, s)
    log('sessionToken: {0}'.format(token))
    saml_username, prelogin_cookie = okta_redirect(conf, s, token,
                                                   redirect_url)
    log('saml-username: {0}'.format(saml_username))
    log('prelogin-cookie: {0}'.format(prelogin_cookie))
    userauthcookie, gateway = paloalto_getconfig(conf, s, saml_username,
                                                 prelogin_cookie)
    log('portal-userauthcookie: {0}'.format(userauthcookie))
    authcookie = globalprotect_login(conf, s, gateway, saml_username,
                                     userauthcookie)
    if authcookie is None:
        err("Could not get authcookie")

    cmd = conf.get('openconnect_cmd') or 'openconnect'
    cmd += ' --protocol=gp '
    cmd += ' --usergroup gateway '
    cmd += ' {0} '
    cmd += ' --mtu=5200 '
    cmd += ' --cookie="{1}" '
    cmd += conf.get('openconnect_args', '') + ' --cafile "{2}"'
    cmd = cmd.format(gateway, authcookie, conf['root_cert_file'])
    print()
    if conf.get('execute', '').lower() in ['1', 'true']:
        cmd = shlex.split(cmd)
        cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
        cp = subprocess.Popen(cmd)
        # Do not abort on SIGINT. openconnect will perform proper exit & cleanup
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cp.communicate()
    else:
        print(cmd)


if __name__ == '__main__':
    main()
