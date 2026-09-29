"""Offline CodeGuard wire/state stages.

No socket, SDK, preference writes, device collection or token issuance. Response
functions take fields AFTER Android JSONObject.isNull/getString, not Gson or
an assumed replacement JSON parser. Secrets are never included in repr.
"""
import base64
from dataclasses import dataclass, field

from .codeguard_codec import (CodeGuardCodecError, java_base64_decode,
                              java_form_encode, java_seed_decrypt)
from .codeguard_inputs import fallback_nonce_key
from .codeguard_rule import AnalysisLimit

PATH = 'CodeGuard/check.jsp?CODEGUARD_CMD='
FORM = 'application/x-www-form-urlencoded'


class ExchangeStageError(ValueError):
    """Observed Java failure category; no exception text/input is retained."""
    def __init__(self, suffix, stage):
        self.sdk_error_prefix = f'E101_NET_ERROR_{suffix:03d}'
        self.stage = stage
        super().__init__(self.sdk_error_prefix + ':' + stage)


def _field(fields, name, missing=''):
    value = fields.get(name)
    if value is None:
        return missing
    if type(value) is not str:
        raise AnalysisLimit('Android JSONObject.getString conversion must be resolved first')
    return value


def _append(value):
    if type(value) is bool:
        return 'true' if value else 'false'
    return 'null' if value is None else value


@dataclass(frozen=True)
class WireRequest:
    command: int
    method: str
    url: str = field(repr=False)
    headers: tuple = field(repr=False)
    body: bytes | None = field(repr=False)

    def diagnostic(self):
        return dict(command=self.command, method=self.method, network_attempted=False,
                    body_present=self.body is not None, server_token_generated=False)


def _headers(user_agent, *, form=False):
    result = []
    if user_agent:
        result.append(('User-Agent', user_agent))
    if form:
        result.append(('Content-Type', FORM))
    return tuple(result)


def cmd101_request(base_url, *, abi, native_library_dir, app_info, version, user_agent):
    """Before java.net.URL parsing; base is concatenated, NOT urljoin'd."""
    if not abi:
        if native_library_dir is None:
            raise AnalysisLimit('ApplicationInfo.nativeLibraryDir is unresolved')
        abi = 'arm64-v8a' if 'arm64' in native_library_dir else 'armeabi'
    app = ('&CODE_APP_INFO=' + java_form_encode(app_info+version+'1')) if app_info and version else ''
    # CMD=101 appends ABI literally, unlike CMD=200's URLEncoder call.
    url = _append(base_url)+PATH+'101&OS=CG1&ABI='+abi+app+'&CERT=yes'
    return WireRequest(101, 'GET', url, _headers(user_agent), None)


def rsa_wrap_key(public_key, key):
    """Updater.i RSA/NONE/PKCS1Padding after key generation/cert parsing.

    Key and actual parsed public key are explicit; no fixed/random-seed guesses.
    This is CodeGuard's key, NOT the Giro CMS/SEED session key. Trust/certificate
    selection and Updater.i's failure side effects are outside this primitive.
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    return base64.b64encode(public_key.encrypt(key, padding.PKCS1v15())).decode('ascii')


@dataclass(repr=False)
class UpdaterState:
    cookie: str | None = ''
    rcl: str | None = None
    hash_key: str | None = None
    is_mix: bool = False
    is_split: bool = False
    key: bytes | None = None
    engine_version: str | None = None
    engine_md: str | None = None
    certificate_text: str | None = None

    def consume_cmd101_fields(self, fields):
        """Metadata assignment only; engineExist, prefs and b() return unresolved."""
        version = _field(fields, 'ENGINE_VERSION')
        md = _field(fields, 'ENGINE_MD')
        cert = _field(fields, 'CERT')
        self.engine_version, self.engine_md, self.certificate_text = version, md, cert

    def cmd200_request(self, base_url, *, app_info, abi, wrapped_key, mix_setting, user_agent):
        # Updater.b(String) clears ONLY cookie, even if request preparation fails.
        self.cookie = ''
        url = (_append(base_url)+PATH+'200&CODE_APP_INFO='+java_form_encode(app_info)
               +'&ABI='+java_form_encode(abi)+'&KEY='+java_form_encode(wrapped_key)
               +'&isMix='+_append(mix_setting))
        return WireRequest(200, 'GET', url, _headers(user_agent, form=True), None)

    def append_parsed_cookies(self, cookies):
        """Already HttpCookie.parse(...).toString() values, in observed order.

        Raw Set-Cookie parsing is not replaced by SimpleCookie. The bounded
        android_cookie adapter handles version-1 formatting; getHeaderFields
        ordering still requires actual IO. Only parse exceptions are ignored.
        """
        for cookie in cookies:
            if type(cookie) is not str:
                raise AnalysisLimit('HttpCookie string conversion unresolved')
            self.cookie = (self.cookie+'; ' if self.cookie else _append(self.cookie))+cookie

    def consume_cmd200_fields(self, fields, *, agent_key=None):
        """Apply original assignment order; absent fields retain prior state."""
        challenge = _field(fields, 'CODE_CHALLENGE')
        rcl = _field(fields, 'CODE_RCL')
        version = _field(fields, 'CODE_RESPONSE2_VER')
        if rcl:
            decoded = java_base64_decode(rcl)
            if decoded is None:
                raise ExchangeStageError(5, 'rcl_null_byte_array')
            try:
                decoded = decoded.decode('utf-8')
            except UnicodeDecodeError:
                raise AnalysisLimit('Android UTF-8 replacement boundary unresolved') from None
            self.rcl = decoded
        # There are no corresponding false assignments here.
        if 'isMix' in version:
            self.is_mix = True
        if 'isSplit' in version:
            self.is_split = True
        encoded = _field(fields, 'HASH_KEY', None)
        if encoded is not None:
            separator = encoded.find('::')
            if separator < 0:
                # substring(0,-1) is outside private a(byte[],byte[])'s catch.
                raise ExchangeStageError(6, 'hash_key_substring')
            iv = java_base64_decode(encoded[separator+2:])
            ciphertext = java_base64_decode(encoded[:separator])
            if self.key is None:
                self.key = agent_key  # assignment precedes SecretKeySpec failure
            try:
                plain = java_seed_decrypt(ciphertext, self.key, iv)
            except CodeGuardCodecError:
                self.hash_key = ''  # original helper catches this and returns ''
            else:
                self.hash_key = plain.hex().upper()
        return challenge

    def nonce_key(self, challenge):
        # MainService.generateToken checks TextUtils.isEmpty(Updater.c()).
        return self.hash_key if self.hash_key else fallback_nonce_key(challenge).decode('ascii')

    def cmd300_request(self, base_url, *, response, response2, get_mode, agent_cookie, user_agent):
        text = java_form_encode(response)+'&CODE_RESPONSE2='+java_form_encode(response2)
        if self.is_mix:
            text += '&CODE_RESPONSE2_VER=isMix'
        text += '&FIXED=true'
        if get_mode:
            url = _append(base_url)+PATH+'300&CODE_RESPONSE='+text
            body = None
        else:
            url = _append(base_url)+PATH+'300'
            if not self.cookie:
                self.cookie = agent_cookie  # GET branch does NOT do this fallback
            body = ('&CODE_RESPONSE='+text).encode('ascii')
        headers = _headers(user_agent) + (('Cookie', self.cookie), ('Content-Type', FORM))
        return WireRequest(300, 'GET' if get_mode else 'POST', url, headers, body)


def token_field(fields):
    """No invented `000`, nonempty or token-schema gate at Updater.a()."""
    return _field(fields, 'CODE_TOKEN', None)


def read_line_join(text):
    """BufferedReader.readLine + append(line + '\n'), on decoded Java text.

    Only CR/LF/CRLF are line boundaries; Python str.splitlines is too broad.
    HTTP status/getInputStream and platform charset decoding occur BEFORE this.
    """
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text if not text or text.endswith('\n') else text+'\n'


def challenge_parts(text):
    """String.split("::") drops trailing empties; not Python split alone."""
    if text is None:
        raise CodeGuardCodecError('java_null_challenge_string')
    if not text:
        return ('',)
    parts = text.split('::')
    while parts and parts[-1] == '':
        parts.pop()
    return tuple(parts)


def rcl_after_challenge(rcl, challenge):
    """MainService String.substring(challenge.length), UTF-16 code units."""
    if not rcl:
        return None  # caller leaves its previous challenge.j field untouched
    raw = rcl.encode('utf-16-le', 'surrogatepass')
    width = len(challenge.encode('utf-16-le', 'surrogatepass'))
    if width > len(raw):
        raise CodeGuardCodecError('java_rcl_substring_bounds')
    return raw[width:].decode('utf-16-le', 'surrogatepass')
