#!/usr/bin/env python3
"""Offline Hana protocol utilities. No network, login, or transfer execution."""
import argparse
import base64
import hashlib
import json
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

API = 'https://oqf.hanabank.com:8443/oqf'
LOGIN_FIELDS = ('c2dmRegIdNm', 'userId', 'pw', 'custNo', 'telNo', 'signDat',
                'elecSignVluDat', 'lstLginMean', 'tmpCrypKey', 'onsfCertCrypPw',
                'lginCertMethDtlCd', 'rskAppIstId')


def device_uuid(android_id):
    if not isinstance(android_id, str) or not android_id:
        raise ValueError('Expected a nonempty Android ID string')
    # Java UUID.nameUUIDFromBytes has no namespace prefix (unlike uuid.uuid3).
    digest = hashlib.md5((android_id + 'OQF').encode('utf-8')).digest()
    return str(uuid.UUID(bytes=digest, version=3))


def android_base64(data, flags):
    """The three flag combinations used by ApiHeaderProviderImpl."""
    if flags not in (2, 4, 10):
        raise ValueError('Supported Android Base64 flags: 2, 4, 10')
    encoded = (base64.urlsafe_b64encode(data) if flags == 10 else base64.b64encode(data)).decode('ascii')
    if flags == 4:
        return ''.join(encoded[i:i + 76] + '\r\n' for i in range(0, len(encoded), 76))
    return encoded


def public_key_header(der):
    if not der:
        raise ValueError('Expected nonempty DER public key bytes')
    pem = '-----BEGIN PUBLIC KEY-----\n' + android_base64(der, 4) + '-----END PUBLIC KEY-----'
    return android_base64(pem.encode('utf-8'), 10)


def encode_header(value):
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object, including CHNL_SYS_HDPT or CNL_HDPT wrapper')
    # JSONObject emits compact UTF-8 JSON; member order is not a protocol guarantee.
    return android_base64(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode(), 10)


def decode_header(value):
    raw = value.strip().encode('ascii')
    raw += b'=' * (-len(raw) % 4)
    return json.loads(base64.b64decode(raw, altchars=b'-_', validate=True).decode('utf-8'))


def login_body(value):
    expected = {'user_id', 'password_enc', 'push_token', 'fakefinder_install_id'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('Expected exactly: user_id, password_enc, push_token, fakefinder_install_id')
    if not all(isinstance(v, str) for v in value.values()):
        raise ValueError('All login inputs must be strings')
    if not value['user_id'] or not value['password_enc']:
        raise ValueError('user_id and password_enc must be nonempty')
    body = dict.fromkeys(LOGIN_FIELDS, '')
    body.update(userId=value['user_id'], pw=value['password_enc'],
                c2dmRegIdNm=value['push_token'], rskAppIstId=value['fakefinder_install_id'])
    return body


def joint_cert_tbs(nonce):
    if not isinstance(nonce, str) or not nonce:
        raise ValueError('nnce must be a nonempty string from createDelfinoNonce')
    # encodeURIComponent preserves these ASCII characters; spaces become %20.
    return 'delfinoNonce=' + quote(nonce, safe="~()*!.'-", encoding='utf-8', errors='strict') + '&login=true'


def joint_cert_body(value):
    expected = {'signed_data', 'push_token', 'fakefinder_install_id'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('Expected exactly: signed_data, push_token, fakefinder_install_id')
    if not all(isinstance(v, str) for v in value.values()) or not value['signed_data']:
        raise ValueError('Expected string inputs and nonempty signed_data')
    base64.b64decode(value['signed_data'], validate=True)
    body = dict.fromkeys(LOGIN_FIELDS, '')
    body.update(elecSignVluDat=value['signed_data'], lginCertMethDtlCd='02',
                c2dmRegIdNm=value['push_token'], rskAppIstId=value['fakefinder_install_id'])
    return body


def auth_request(stage, private_der, value):
    """Assemble one version 1.0.27 auth-provider request without sending it."""
    from .rsa_raw import public_der, sign
    stages = {'register': ('app_public_key', None, None),
              'first-access': ('app_first_access', 'secure_token', 'enc-secutoken'),
              'access-token': ('get_access_token', 'nonce', 'enc-nonce')}
    if stage not in stages:
        raise ValueError('Unknown app authentication stage')
    path, input_name, header_name = stages[stage]
    expected = {'android_id'}
    if input_name:
        expected |= {'system_header', 'channel_header', input_name}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('Expected exactly: ' + ', '.join(sorted(expected)))
    headers = {'app-version': '1.0.27', 'package-name': 'com.hanabank.oqf',
               'uuid': device_uuid(value['android_id'])}
    if stage == 'register':
        headers['public-key'] = public_key_header(public_der(private_der))
    else:
        for source, wrapper, name in [('system_header', 'CHNL_SYS_HDPT', 'hana-sys-header'),
                                      ('channel_header', 'CNL_HDPT', 'hana-com-header')]:
            header = value[source]
            if not isinstance(header, dict) or set(header) != {wrapper} or not isinstance(header[wrapper], dict) or not header[wrapper]:
                raise ValueError(f'{source} must contain a nonempty {wrapper} object')
            headers[name] = encode_header(header)
        if not isinstance(value[input_name], str) or not value[input_name]:
            raise ValueError(f'{input_name} must be a nonempty string')
        headers[header_name] = android_base64(sign(private_der, value[input_name].encode('utf-8')), 2)
    return {'mode': 'offline request assembly; no request sent', 'live_verified': False,
            'header_scope': 'ApiHeaderProvider only; see network-plan for interceptors and cookies',
            'method': 'GET', 'url': API + '/public/' + path,
            'headers': headers, 'body': None}


def auth_plan():
    identity = ['app-version', 'package-name', 'uuid']
    common = ['hana-sys-header', 'hana-com-header', *identity]
    return {'mode': 'offline analysis; no requests are sent', 'live_verified': False,
            'steps': [
                {'method': 'GET', 'url': API + '/public/app_public_key',
                 'input_headers': [*identity, 'public-key'], 'response_headers': ['key-save-status']},
                {'method': 'GET', 'url': API + '/public/app_first_access',
                 'input_headers': [*common, 'enc-secutoken'], 'response_headers': ['nonce']},
                {'method': 'GET', 'url': API + '/public/get_access_token',
                 'input_headers': [*common, 'enc-nonce'], 'response_headers': ['access-token']},
                {'method': 'POST', 'url': API + '/public/pcm/lgin01/capi/lginMgnt/executeNFilterKey',
                 'purpose': 'Obtain the server public key used by the secure keypad'},
                {'method': 'POST', 'url': API + '/public/pcm/lgin01/capi/lginMgnt/loginIdPw',
                 'body_fields': list(LOGIN_FIELDS), 'password_source': 'NFilterTO.getEncData()',
                 'response_headers': ['one-access-token']},
                {'method': 'POST', 'url': API + '/api/pcm/lgin01/capi/mainInfoMgnt/retrieveMainAcctInfo',
                 'body': None, 'purpose': 'Account query; app declaration has no @Body'}],
            'unresolved': ['Generality of the single observed app key/device-profile acceptance',
                           'Live server-key response and encrypted-password acceptance',
                           'Session expiry, refresh and repeated-run validation',
                           'Transfer session state, required authorization and reconciliation']}
