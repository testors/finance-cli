"""Explicit one-attempt HTTP with encrypted receipts and separate cookie jars."""
import base64
import gzip
import http.cookiejar
import time
import urllib.error
import urllib.request

from . import auth, hana_protocol, onesign_crypto as pin, onesign_issue_protocol as issue, request_activity
from . import onesign_signup_protocol as signup, onesign_compat as compat
from .onesign_codec import encode
from .transport import NoRedirect, USER_AGENT

ORIGIN = 'https://hanacert.hanabank.com'
ACCOUNTS = '/api/pcm/lgin01/capi/mainInfoMgnt/retrieveMainAcctInfo'
RA_PATHS = ('/nonce', '/requestSecretE', '/checkPinVersion', '/registerCertificate')


def send_http(scope, method, url, headers, body, cookies, timeout):
    jar = http.cookiejar.CookieJar()
    for row in cookies:
        jar.set_cookie(http.cookiejar.Cookie(**row))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(url, headers=headers, data=body, method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        status, head = response.status, list(response.headers.items())
        raw = response.read()
    fields = ('version','name','value','port','port_specified','domain','domain_specified',
              'domain_initial_dot','path','path_specified','secure','expires','discard',
              'comment','comment_url','rfc2109')
    saved = [{**{k: getattr(c, k) for k in fields}, 'rest': c._rest} for c in jar]
    return status, head, raw, saved


class Client:
    def __init__(self, state, run, session, *, send=False, exchange=send_http):
        self.state, self.run, self.session = state, run, session
        self.send, self.exchange = send, exchange
        self.count = 0
        self.sent = 0
        self.last = {'service_status': 'unconfirmed', 'processing_status': 'not_started'}
        self.cookies = {'ra': [], 'ca': []}
        self.transfer_paths = set()
        self.query_paths = set()

    def request(self, scope, method, path, headers, body, *, web=False, auth_stage=None, observe=None):
        if not self.send:
            raise ValueError('explicit_send_required')
        allowed = {issue.PATHS[name] for name in ('instant-number','application','image','identity',
            'signup-accounts','signup-account','keypad','clock','pin-check','registration','complete-signup')} | {
            signup.WEB_PATHS[name] for name in ('clear','phone-pre','sms-send','sms-verify','eligibility',
                                              'customer','terms-status','terms-save')} | {
            pin.BANK_NONCE_PATH, pin.LOGIN_PATH, ACCOUNTS} | self.transfer_paths | self.query_paths
        if scope == 'bank':
            if auth_stage:
                expected = {'register':'/public/app_public_key', 'first-access':'/public/app_first_access',
                            'access-token':'/public/get_access_token'}
                pin.require(expected.get(auth_stage) == path and method == 'GET', 'auth_endpoint_not_allowed')
            else:
                pin.require(path in allowed and method == 'POST', 'bank_endpoint_not_allowed')
            url = hana_protocol.API + path
        elif scope == 'ra':
            pin.require(path in RA_PATHS and method == 'POST', 'ra_endpoint_not_allowed')
            url = ORIGIN + pin.RA_BASE_PATH + path
        elif scope == 'ca':
            pin.require(path == issue.CA_URL and method == 'POST', 'ca_endpoint_not_allowed')
            url = path
        else:
            raise ValueError('invalid_service_scope')
        self.count += 1
        name = 'http-%04d' % self.count
        previous = self.last
        self.last = {'service_status': 'unconfirmed', 'processing_status': 'request_prepared', 'scope': scope}
        request = {'method': method, 'url': url, 'headers': headers,
                   'body': None if body is None else base64.b64encode(body).decode()}
        self.state.record(self.run, name+'-request', request)
        # A durable reservation exists before any network I/O.
        self.state.record(self.run, name+'-attempt', {'at_ms': int(time.time()*1000), 'automatic_retry': False})
        value = self.state.snapshot()['sessions'][self.session]
        cookies = value.get('cookies', []) if scope == 'bank' else self.cookies[scope]
        timeout = 5 if scope == 'ca' else 300 if path == issue.PATHS['image'] else 125 if web else 30 if scope == 'bank' else 10
        try:
            request_activity.before_request(scope)
        except request_activity.RequestBlocked:
            self.last = previous  # The local guard cannot erase an earlier service verdict.
            raise
        try:
            self.sent += 1
            status, head, raw, cookies = self.exchange(scope, method, url, headers, body, cookies, timeout)
        except Exception:
            self.last['processing_status'] = 'transport_interrupted'
            raise pin.ProtocolError('transport_interrupted_no_automatic_retry') from None
        self.last.update(http_status=status, processing_status='response_received')
        try:
            if auth_stage:
                result = auth.classify(auth_stage, status, head, status not in (204, 205))
                self.last['service_status'] = 'accepted' if result['accepted'] else 'rejected'
            elif not (200 <= status < 300 if web else status == 200):
                self.last['service_status'] = 'rejected'
            elif scope == 'bank':
                try:
                    compat.bank_business_headers(head, web=web)
                    self.last['service_status'] = 'accepted'
                except pin.ProtocolError as exc:
                    if str(exc) == 'bank_http_or_business_failure':
                        self.last['service_status'] = 'rejected'
            # CA/RA business acceptance is known only after body verification.
            if observe is not None and self.last['service_status']=='accepted':
                decoded = gzip.decompress(raw) if dict((k.lower(),v) for k,v in head).get('content-encoding','').lower()=='gzip' else raw
                self.last.update(observe(decoded))
            self.state.record(self.run, name+'-response', {'status':status, 'headers':head,
                'body':base64.b64encode(raw).decode(), 'observed_ms':int(time.time()*1000), **self.last})
            if scope == 'bank':
                with self.state.transaction() as value:
                    value['sessions'][self.session]['cookies'] = cookies
            else:
                self.cookies[scope] = cookies
        except OSError:
            self.last['processing_status'] = 'response_storage_failed'
            raise pin.ProtocolError('response_storage_failed') from None
        if self.last['service_status'] == 'rejected':
            raise pin.ProtocolError('service_rejected')
        if scope == 'bank' and self.last['service_status'] != 'accepted':
            raise pin.ProtocolError('service_verdict_unconfirmed')
        if dict((k.lower(), v) for k,v in head).get('content-encoding','').lower() == 'gzip':
            raw = gzip.decompress(raw)
        self.response_headers = head
        return raw

    def headers(self):
        session = self.state.snapshot()['sessions'][self.session]
        pin.require(session.get('app_authenticated') is True, 'app_authentication_required')
        return dict(session['headers'])

    def authenticate(self, settings):
        state = self.state.snapshot()
        session = state['sessions'][self.session]
        pin.require(not session.get('app_attempted'), 'app_auth_already_attempted')
        with self.state.transaction() as value:
            value['sessions'][self.session]['app_attempted'] = True
        profile = state['profile']
        private = pin.unb64url(profile['app_key'])
        fields = profile['service_profile']
        nonce = None
        for stage in ('register','first-access','access-token'):
            value = {'android_id':profile['app_identity']['android_id']}
            if stage != 'register':
                value.update(system_header=fields['system_header'], channel_header=fields['channel_header'])
                value['secure_token' if stage == 'first-access' else 'nonce'] = settings['secure_token'] if stage == 'first-access' else nonce
            request = hana_protocol.auth_request(stage, private, value)
            headers = {**request['headers'], 'Accept':'application/json', 'Content-Type':'application/json',
                       'User-Agent':USER_AGENT, 'Accept-Encoding':'gzip'}
            self.request('bank', 'GET', request['url'][len(hana_protocol.API):], headers, None, auth_stage=stage)
            received = {k.lower():v for k,v in self.response_headers}
            if stage == 'first-access':
                nonce = received['nonce']
        headers.pop('enc-nonce', None)
        headers.update({'nonce':nonce, 'access-token':received['access-token'], 'hana-1q-env':'Prod'})
        with self.state.transaction() as value:
            value['sessions'][self.session].update(app_authenticated=True, headers=headers)

    def phone(self, operation, body):
        headers = signup.web_headers(self.headers(), operation)
        path = signup.WEB_PATHS[operation]
        raw = self.request('bank','POST',path,headers,signup.web_body(body),web=True)
        if signup.ignores_response_body(path, body):
            return {}
        value = compat.web_value(raw)
        if operation == 'terms-status' and value is not None and not isinstance(value, dict):
            return {}
        pin.require(isinstance(value, dict), 'signup_response_object_required')
        return value

    def bank(self, path, body):
        native = path in (issue.PATHS['keypad'],issue.PATHS['clock'],issue.PATHS['pin-check'],
                         issue.PATHS['registration'],pin.BANK_NONCE_PATH,pin.LOGIN_PATH,ACCOUNTS)
        headers = self.headers()
        if path in issue.PATHS.values() and path != pin.LOGIN_PATH:
            pin.require(not headers.get('one-access-token'), 'anonymous_issuance_session_required')
        if not native:
            common = hana_protocol.decode_header(headers['hana-com-header'])
            stage = self.state.snapshot()['issuance']
            screen = ('COMC0701001501' if path == issue.PATHS['application'] else
                ('COMC0701001502' if stage.get('capture_kind') == 'resident' else 'COMC0701001503')
                if path in (issue.PATHS['image'],issue.PATHS['identity']) else
                'COMC0201001503' if path in (issue.PATHS['signup-accounts'],issue.PATHS['signup-account']) else
                'COMC1401001001' if path == issue.PATHS['complete-signup'] else 'COMC0501001501')
            common['CNL_HDPT']['SCRN_ID'] = screen
            headers['hana-com-header'] = hana_protocol.encode_header(common)
            headers['one-access-token'] = ''
        headers['Content-Type'] = 'application/json;charset=utf-8'
        raw = self.request('bank','POST',path,headers,b'' if path in (issue.PATHS['keypad'],ACCOUNTS) else signup.web_body(body),web=not native)
        if path == signup.WEB_PATHS['terms-save']:
            return {}
        if not native:
            value = compat.web_value(raw)
            if path == issue.PATHS['instant-number'] and not isinstance(value,dict):
                return {}
        else:
            fields = ('keyId','macKey','berryName','scBCertKey','custNo') if path == issue.PATHS['registration'] else ('apiRlseKey',) if path == issue.PATHS['keypad'] else ('dt','tm','bussDdYn') if path == issue.PATHS['clock'] else ('scrtRnum',) if path == pin.BANK_NONCE_PATH else ()
            defaults = ('custNo','lginCertMethCd','mvblUrl') if path == pin.LOGIN_PATH else ()
            value = compat.kotlin_object(raw,string_fields=fields,string_defaults=defaults)
            if path == issue.PATHS['clock']:
                value = issue.normalize_server_clock(value)
            if path == issue.PATHS['registration']:
                value['existSeed'] = compat.boolean(value.get('existSeed'), 'issuance_exist_seed_boolean_required')
            if path == issue.PATHS['pin-check']:
                value['scss'] = compat.boolean(value.get('scss'), 'issuance_pin_success_boolean_required')
            if path == pin.LOGIN_PATH:
                token = dict((k.lower(),v) for k,v in self.response_headers).get('one-access-token')
                pin.require(not value.get('mvblUrl'), 'login_additional_screen')
                pin.require(isinstance(token,str) and bool(token.strip()), 'login_token_unavailable')
                with self.state.transaction() as state:
                    state['sessions'][self.session]['login_response'] = value
                    state['sessions'][self.session]['headers']['one-access-token'] = token
        pin.require(isinstance(value,dict), 'bank_response_object_required')
        return value

    def ra(self, path, body):
        raw = self.request('ra','POST',path,{'Content-Type':'application/json; charset=utf-8'},encode(body))
        value = compat.android_object(raw)
        code = compat.integer(value.get('resultCode'),'invalid_service_result_code')
        self.last['service_status'] = 'accepted' if code == 0 else 'rejected'
        self.state.record(self.run,'http-%04d-verdict'%self.count,self.last)
        pin.require(code == 0, {64001:'wrong_pin',64002:'pin_attempt_limit',64004:'pin_version_changed',
                              65002:'certificate_not_found',65006:'certificate_revoked'}.get(code,'ra_business_error'))
        return value

    def image(self, content_type, body):
        headers = self.headers()
        common = hana_protocol.decode_header(headers['hana-com-header'])
        common['CNL_HDPT']['SCRN_ID'] = 'COMC0701001502' if self.state.snapshot()['issuance']['capture_kind']=='resident' else 'COMC0701001503'
        headers.update({'hana-com-header':hana_protocol.encode_header(common),'Content-Type':content_type,'one-access-token':''})
        raw = self.request('bank','POST',issue.PATHS['image'],headers,body,web=True)
        return compat.web_value(raw)

    def ca(self, body):
        raw = self.request('ca','POST',issue.CA_URL,{'Content-Type':issue.CA_MIME},body)
        mime = dict((k.lower(),v) for k,v in self.response_headers).get('content-type','')
        pin.require(mime.lower() == issue.CA_MIME,'cmp_response_mime_mismatch')
        return raw
