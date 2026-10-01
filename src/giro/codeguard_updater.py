"""Updater CMD101/200/300 and key setup, expressed as offline effects.

No socket, SDK execution, preference IO, weak-key guessing or token issuance.
HTTP effects preserve call/catch ordering, not a replacement HTTP stack.
Pure JSON/cookie adapters are available in codeguard_http_values. Optional
codeguard_http/codeguard_crypto executors cover known normal IO/key values;
environment and unsupported provider observations remain external.
"""
import base64
from dataclasses import dataclass

from .codeguard_codec import (java_base64_decode, java_form_encode, java_seed_decrypt,
                              CodeGuardCodecError)
from .codeguard_effects import Effect, JavaFault, observed_bool, java_length
from .codeguard_exchange import UpdaterState, PATH, FORM
from .codeguard_flow import java_text
from .codeguard_platform import engine_exists_steps
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class AgentMaterial:
    certificate_text: str | None
    key: bytes | None
    engine_version: str | None
    mix: bool
    cookie: str | None


@dataclass(repr=False)
class UpdaterRuntime:
    data: UpdaterState
    context: object
    url: str | None
    timeout: int
    app_info: str | None
    version: str | None
    connection: object = None
    status: int = 0


def runtime_fault(kind, site):
    """Request original platform exception text, never invent wire diagnostics."""
    try:
        fault = yield Effect('java_runtime_fault', (kind, site))
    except JavaFault as observed:
        fault = observed
    if not isinstance(fault, JavaFault) or fault.kind != kind:
        raise AnalysisLimit('original Java exception observation required')
    raise fault


def _form(value, site):
    if value is None:
        yield from runtime_fault('NullPointerException', site)
    return java_form_encode(value)


def preference(runtime, key, default):
    if runtime.context is None:
        yield from runtime_fault('NullPointerException', 'getSharedPreferences')
    return (yield Effect('preference_read', (runtime.context, key, default)))


def agent_certificate_steps(runtime, agent):
    if agent.certificate_text:
        return agent.certificate_text
    return (yield from preference(runtime, 'CERT', ''))


def wrapped_key_steps(runtime, agent):
    """Updater.i: update BOTH keys before any certificate/RSA operation.

    Original uses new Random(), setSeed(currentTimeMillis), nextBytes(16).
    No real-time seed prediction/guessing is implemented. The explicit adapter
    returns the bytes from that operation; codeguard_crypto implements the
    known arithmetic for this client's own exchange with its explicit clock.
    """
    try:
        random = yield Effect('new_java_random')
        seed = yield Effect('clock_ms')
        key = yield Effect('java_random_seed_and_bytes', (random, seed, 16))
        if type(key) is not bytes or len(key) != 16:
            raise AnalysisLimit('exact Java nextBytes(16) observation required')
        runtime.data.key = key
        agent.key = runtime.data.key
        text = yield from agent_certificate_steps(runtime, agent)
        if text is None:
            return ''  # Base64.getBytes NPE inside catch(Exception), no wire text
        decoded = java_base64_decode(text)
        if decoded is None:
            return ''  # ByteArrayInputStream(null), also inside this catch
        # No yessign trust factory substitution: this is Android default X.509.
        certificate = yield Effect('android_parse_x509', (decoded,))
        cipher = yield Effect('rsa_cipher_instance', ('RSA/NONE/PKCS1Padding',))
        public_key = yield Effect('certificate_public_key', (certificate,))
        yield Effect('rsa_cipher_init', (cipher, 1, public_key))
        wrapped = yield Effect('rsa_cipher_final', (cipher, runtime.data.key))
        if wrapped is None:
            return ''  # original array-length dereference inside catch
        if type(wrapped) is not bytes:
            raise AnalysisLimit('actual RSA doFinal bytes required')
        return base64.b64encode(wrapped).decode('ascii')
    except JavaFault:
        return ''  # keys already assigned remain assigned; not a success token


def _call(runtime, method, *args):
    return (yield Effect('http_call', (runtime.connection, method, args)))


def _open(runtime, url):
    # The adapter includes new URL and openConnection; state assignment occurs
    # ONLY after both return. Old connection survives an observed open failure.
    runtime.connection = yield Effect('http_open', (url,))
    yield from _call(runtime, 'setReadTimeout', runtime.timeout)
    yield from _call(runtime, 'setConnectTimeout', runtime.timeout)


def _user_agent(runtime):
    value = '' if runtime.context is None else (yield from preference(runtime, 'user_agent', ''))
    if value:
        yield from _call(runtime, 'setRequestProperty', 'User-Agent', value)


def _response_code(runtime):
    try:
        return (yield from _call(runtime, 'getResponseCode'))
    except JavaFault:
        return 0  # original uses it only in logs, not a 2xx success condition


def _json_body(runtime):
    stream = yield from _call(runtime, 'getInputStream')
    reader = yield Effect('input_stream_reader', (stream,))  # Android default charset, no HTTP charset/BOM policy
    lines = []
    while True:
        line = yield Effect('read_line', (reader,))
        if line is None:
            break
        if type(line) is not str:
            raise AnalysisLimit('actual BufferedReader.readLine value required')
        lines.append(line + '\n')
    yield Effect('close_reader', (reader,))  # NOT finally: original skips it on read failure
    return ''.join(lines)


def _json_field(obj, name, default):
    # Adapter does JSONObject.isNull then getString, not Gson/Python coercion.
    value = yield Effect('json_string_field', (obj, name, default))
    if value is not None and type(value) is not str:
        raise AnalysisLimit('Android JSONObject string result required')
    return value


def _cookies(runtime):
    headers = yield Effect('set_cookie_header_values', (runtime.connection, 'Set-Cookie'))
    yield from consume_cookie_headers_steps(runtime.data,headers)


def consume_cookie_headers_steps(state,headers):
    """Original cookie loop after getHeaderFields, reusable without HTTP IO."""
    if headers is not None:
        for header in headers:
            try:
                cookies = yield Effect('http_cookie_parse', (header,))
            except JavaFault:
                continue  # Only HttpCookie.parse is inside this catch
            if cookies is not None:
                for cookie in cookies:
                    yield Effect('http_cookie_string', (cookie,))  # evaluated for logging, even if DEBUG=false
                    value = yield Effect('http_cookie_string', (cookie,))
                    state.append_parsed_cookies((value,))


def check_update_steps(runtime, agent, main):
    """CMD101: certificate preference/agent writes precede engineExist."""
    main.append_log(',E11.1')
    runtime.status = 0
    if runtime.context is None:
        return False
    try:
        yield from preference(runtime, 'ENGINE_VERSION', '')  # read even though only logged
        try:
            abi = yield Effect('cpu_abi')
        except JavaFault:
            abi = ''
        if not abi:
            directory = yield Effect('native_library_dir', (runtime.context,))
            if directory is None:
                yield from runtime_fault('NullPointerException', 'nativeLibraryDir.contains')
            abi = 'arm64-v8a' if 'arm64' in directory else 'armeabi'
        app = ''
        if runtime.app_info and runtime.version:
            app = '&CODE_APP_INFO=' + java_form_encode(runtime.app_info + runtime.version + '1')
        url = java_text(runtime.url) + PATH + '101&OS=CG1&ABI=' + abi + app + '&CERT=yes'
        yield from _open(runtime, url)
        yield from _call(runtime, 'setRequestMethod', 'GET')
        yield from _call(runtime, 'setDoInput', True)
        yield from _user_agent(runtime)
        yield Effect('clock_ms')
        yield from _call(runtime, 'connect')
        yield from _response_code(runtime)
        yield Effect('clock_ms')
        body = yield from _json_body(runtime)
        obj = yield Effect('json_object', (body,))
        version = yield from _json_field(obj, 'ENGINE_VERSION', '')
        digest = yield from _json_field(obj, 'ENGINE_MD', '')
        cert = yield from _json_field(obj, 'CERT', '')
        yield Effect('preference_write', (runtime.context, 'ENGINE_VERSION', version, 'apply'))
        agent.engine_version = version
        agent.certificate_text = cert
        yield Effect('preference_write', (runtime.context, 'CERT', cert, 'apply'))
        # getApplicationInfo is in Updater's catch, BEFORE engineExist's own
        # E19.1/catch and before the digest String.length call.
        application_info = yield Effect('application_info', (runtime.context,))
        if digest is None:
            yield from runtime_fault('NullPointerException', 'CMD101.ENGINE_MD.length')
        exists = yield from engine_exists_steps(main, application_info, digest, java_length(digest) <= 25)
        if exists:
            main.append_log(',E11')
        runtime.status = 3
        return True  # false engineExist is NOT a CMD101 failure condition
    except JavaFault as fault:
        runtime.status = 4
        main.append_log(',E11:' + java_text(fault.java_string))
        runtime.status = 3  # original overwrites 4 before returning false
        return False


def _challenge_error(main, fault):
    # Adapter provides Java ancestry (e.g. SocketTimeoutException→IOException),
    # rather than classifying unrelated Python errors as network failures.
    catches = (('ParseException',2), ('IOException',1), ('JSONException',3),
               ('IllegalArgumentException',4), ('NullPointerException',5))
    suffix = next((suffix for kind,suffix in catches if fault.is_instance(kind)),6)
    old = main.status_log
    main.append_log(',E30.5:' + java_text(fault.java_string))
    # IOException/ParseException build the return string BEFORE appending log.
    return 'E101_NET_ERROR_%03d&&' % suffix + java_text(old if suffix in (1,2) else main.status_log)


def challenge_steps(runtime, agent, main, app_info):
    """CMD200, including per-header cookie catches and partial field updates."""
    main.append_log(',E30.1')
    runtime.data.cookie = ''
    if runtime.context is None:
        return ''
    try:
        try:
            abi = yield Effect('cpu_abi')
        except JavaFault:
            abi = ''  # no CMD101-style nativeLibraryDir fallback here
        abi = yield from _form(abi, 'CMD200.ABI.encode')  # evaluated BEFORE key generation
        wrapped = yield from wrapped_key_steps(runtime, agent)
        mix = observed_bool(agent.mix)
        suffix = '&ABI=' + abi + '&KEY=' + java_form_encode(wrapped) + '&isMix=' + str(mix).lower()
        yield Effect('clock_ms')
        encoded_app = yield from _form(app_info, 'CMD200.app.encode')
        yield from _open(runtime, java_text(runtime.url) + PATH + '200&CODE_APP_INFO=' + encoded_app + suffix)
        yield from _user_agent(runtime)
        yield from _call(runtime, 'setRequestMethod', 'GET')
        yield from _call(runtime, 'setDoInput', True)
        yield from _call(runtime, 'setRequestProperty', 'Content-Type', FORM)
        yield from _call(runtime, 'connect')
        yield from _response_code(runtime)
        yield Effect('clock_ms')
        yield Effect('headers_for_logging', (runtime.connection,))
        yield from _cookies(runtime)
        body = yield from _json_body(runtime)
        obj = yield Effect('json_object', (body,))
        challenge = yield from _json_field(obj, 'CODE_CHALLENGE', '')
        rcl = yield from _json_field(obj, 'CODE_RCL', '')
        version = yield from _json_field(obj, 'CODE_RESPONSE2_VER', '')
        if rcl:
            raw = java_base64_decode(rcl)
            if raw is None:
                yield from runtime_fault('NullPointerException', 'CMD200.RCL.newString')
            runtime.data.rcl = yield Effect('java_decode_default_charset', (raw,))
        if version and 'isMix' in version:
            runtime.data.is_mix = True
        if version and 'isSplit' in version:
            runtime.data.is_split = True
        main.append_log(',E30.5')
        encoded = yield from _json_field(obj, 'HASH_KEY', None)
        if encoded is not None:
            separator = encoded.find('::')
            if separator < 0:
                yield from runtime_fault('StringIndexOutOfBoundsException', 'CMD200.HASH_KEY.substring')
            ciphertext, iv_text = encoded[:separator], encoded[separator+2:]
            iv, ciphertext = java_base64_decode(iv_text), java_base64_decode(ciphertext)
            if runtime.data.key is None:
                runtime.data.key = agent.key
            try:
                value = java_seed_decrypt(ciphertext, runtime.data.key, iv)
            except CodeGuardCodecError:
                runtime.data.hash_key = ''  # helper catch; outer CMD200 still returns challenge
            else:
                runtime.data.hash_key = value.hex().upper()
        return challenge
    except JavaFault as fault:
        return _challenge_error(main, fault)


def token_steps(runtime, agent, main, response, response2):
    """CMD300 does not parse/store Set-Cookie and does not invent code=000."""
    if runtime.context is None:
        return None
    try:
        first = yield from _form(response, 'CMD300.response.encode')
        second = yield from _form(response2, 'CMD300.response2.encode')
        body = first + '&CODE_RESPONSE2=' + second
        if runtime.data.is_mix:
            body += '&CODE_RESPONSE2_VER=isMix'
        body += '&FIXED=true'
        yield Effect('clock_ms')
        get_mode = observed_bool((yield from preference(runtime, 'GETMODE', False)))
        url = java_text(runtime.url) + PATH + '300' + ('&CODE_RESPONSE=' + body if get_mode else '')
        yield from _open(runtime, url)
        yield from _call(runtime, 'setRequestMethod', 'GET' if get_mode else 'POST')
        yield from _call(runtime, 'setDoInput', True)
        if not get_mode:
            yield from _call(runtime, 'setDoOutput', True)
        yield from _user_agent(runtime)
        if not get_mode and not runtime.data.cookie:
            runtime.data.cookie = agent.cookie
        yield from _call(runtime, 'setRequestProperty', 'Cookie', runtime.data.cookie)
        yield from _call(runtime, 'setRequestProperty', 'Content-Type', FORM)
        if not get_mode:
            stream = yield from _call(runtime, 'getOutputStream')
            yield Effect('write_bytes', (stream, ('&CODE_RESPONSE=' + body).encode('ascii')))
            yield Effect('flush_output', (stream,))
            yield Effect('close_output', (stream,))
        yield from _call(runtime, 'connect')
        yield from _response_code(runtime)
        yield Effect('headers_for_logging', (runtime.connection,))
        body = yield from _json_body(runtime)
        yield Effect('clock_ms')
        obj = yield Effect('json_object', (body,))
        return (yield from _json_field(obj, 'CODE_TOKEN', None))
    except JavaFault as fault:
        main.append_log(',E33.99:' + java_text(fault.java_string))
        return 'E101_NET_ERROR_007&&' + java_text(main.status_log)
