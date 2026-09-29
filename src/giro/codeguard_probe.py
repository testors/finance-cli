"""Fixed, PIN-free CMD101 probe, NOT a CodeGuard token/authentication client.

Uses the configured base URL and service suffix, including the repeated path.
No CMD200/300, device identity, native/environment response, cookies, original
SDK execution or disk state. Raw material exists only in memory during this
call. Metadata inspection never claims complete SDK initialization or trust.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import ssl
from urllib.parse import urlsplit

from .android_json import parse_object, string_field
from .bootstrap import _tls_context
from .codeguard_codec import java_base64_decode
from .codeguard_effects import JavaFault
from .codeguard_exchange import cmd101_request, read_line_join
from .codeguard_http_values import decode_default_utf8
from .codeguard_rule import AnalysisLimit
from .errors import GiroError
from .protocol import APP_VERSION, BASE_URL

APP_INFO='IGIROMOBILE'
VERSION=APP_VERSION+'_209'
APP_BASE=BASE_URL+'/CodeGuard/'
USER_AGENT='GiroCLI-CodeGuard-bootstrap/0.1 (CMD101-only-probe)'
PROTOCOL_ABIS=('arm64-v8a','armeabi-v7a','armeabi')
MAX_ENTITY=512*1024
TIMEOUT=15


def _request(abi, *, user_agent=USER_AGENT):
    # CMD101 appends ABI literally. Restrict the PROBE's public configuration
    # rather than permitting caller URL/header injection or altering SDK rules.
    if abi not in PROTOCOL_ABIS: raise GiroError('지원하는 ABI를 명시해야 합니다.')
    return cmd101_request(APP_BASE,abi=abi,native_library_dir=None,
                          app_info=APP_INFO,version=VERSION,user_agent=user_agent)


def plan(abi):
    request=_request(abi)
    return dict(offline=True,network_attempted=False,analysis_status='plan_only',
        command=101,method=request.method,url=request.url,abi=abi,
        application_identity_source='service_configuration',
        tls_verification_required=True,redirects=False,retries=0,
        pin_used=False,device_id_used=False,phone_number_used=False,
        environment_response_submitted=False,token_request_submitted=False,
        raw_response_persisted=False,cookies_persisted=False,
        sdk_initialization_verified=False,certificate_validation_performed=False,
        live_login_ready=False,
        differences_from_app=['explicit_probe_user_agent','python_tls_http_stack',
            'explicit_abi_not_Build_CPU_ABI','fresh_probe_no_app_preferences',
            'no_engineExist_or_JNI','connection_close','no_redirects_or_retries',
            'bounded_entity_and_socket_timeout'])


def inspect_body(data):
    """CMD101's UTF-8/readLine/JSONObject/isNull/getString, only safe metadata.

    Not an app-success gate. Certificate public-key parsing here is diagnostic
    using a local backend, not Android CertificateFactory or yessign trust.
    No current validity/KU rejection is added to CodeGuard's RSA key wrapping.
    """
    result=dict(cmd101_fields_decoded=False,sdk_initialization_verified=False,
                certificate_validation_performed=False,live_login_ready=False)
    try:
        document=parse_object(read_line_join(decode_default_utf8(data)))
        values=[string_field(document,key,'') for key in ('ENGINE_VERSION','ENGINE_MD','CERT')]
    except JavaFault:
        return {**result,'analysis_status':'cmd101_json_exception'}
    except AnalysisLimit:
        return {**result,'analysis_status':'cmd101_value_adapter_boundary'}
    version,digest,certificate=values
    result.update(analysis_status='cmd101_fields_decoded',cmd101_fields_decoded=True,
        engine_version_present=bool(version),engine_digest_present=bool(digest),
        certificate_present=bool(certificate),
        engine_file_verification_performed=False)
    if certificate:
        result['codeguard_certificate']=_certificate_metadata(certificate)
    # CMD101 itself permits empty fields; don't turn absence into failure.
    return result


def _certificate_metadata(text):
    report=dict(analysis_status='local_backend_unavailable',android_parse_equivalence_verified=False,
                certificate_validation_performed=False)
    try:
        raw=java_base64_decode(text)
        if raw is None: return {**report,'analysis_status':'base64_returned_null'}
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import rsa
        certificate=x509.load_der_x509_certificate(raw)
        try: key=certificate.public_key()
        except UnsupportedAlgorithm:
            return {**report,'analysis_status':'local_public_key_algorithm_boundary'}
        report.update(analysis_status='local_public_certificate_parsed',
            sha256=hashlib.sha256(raw).hexdigest(),rsa_public_key=isinstance(key,rsa.RSAPublicKey))
        # No subject, serial, key bytes or certificate text in the report.
    except (ImportError,ValueError,TypeError,AnalysisLimit): pass
    return report


def _fetch_request(request, result, *, count_cookie_headers=False,inspect_headers=None):
    """Internal one-shot transport; raw body is ONLY for in-memory consumers.

    This is not a URLConnection emulator. All stops are probe diagnostics.
    Never put request.url in results: CMD200's query contains ephemeral KEY.
    No cookie jar, redirect handler, retry, proxy or next-command dispatch.
    """
    url=urlsplit(request.url)
    if (request.command not in (101,200) or request.method!='GET' or request.body is not None
            or url.scheme!='https' or url.netloc!='m.giro.or.kr'
            or url.path!='/CodeGuard/CodeGuard/check.jsp' or url.fragment
            or not url.query.startswith(f'CODEGUARD_CMD={request.command}&')):
        raise GiroError('초기 프로브의 고정 HTTPS GET 범위 밖입니다.')
    result.update(offline=False,analysis_status='incomplete',http_status=None,
                  network_attempted=False,request_attempted=False,tls_endpoint_verified=False)
    connection=None
    stage='tls_context'
    try:
        context=_tls_context()  # deliberately ignores SSLKEYLOGFILE
        connection=http.client.HTTPSConnection(url.hostname,443,timeout=TIMEOUT,context=context)
        stage='tls_connect'
        result['network_attempted']=True
        connection.connect()
        result['tls_endpoint_verified']=True
        stage='http_request'
        result['request_attempted']=True
        connection.request('GET',url.path+'?'+url.query,
                           headers={**dict(request.headers),'Connection':'close','Accept-Encoding':'identity'})
        stage='http_headers'
        response=connection.getresponse()
        result['http_status']=response.status
        # Actual URLConnection stream/redirect behavior is not faked with a
        # Python getresponse() status. Need a separate adapter for these paths.
        if 300<=response.status<400 and response.status!=304:
            result['analysis_status']='redirect_not_followed'
            return None
        if response.status>=400 or response.status<200:
            result['analysis_status']='http_input_stream_path_not_replayed'
            return None
        if count_cookie_headers:
            # Diagnostic only; do not invent Android getHeaderFields ordering
            # or claim cookie parse/toString success. No cookie is forwarded.
            result['set_cookie_header_count']=sum(
                name.lower()=='set-cookie' for name,_ in response.getheaders())
            result['cookie_processing_replayed']=False
        if inspect_headers is not None:
            result['cookie_material']=inspect_headers(response.msg)
        encoding=response.getheader('Content-Encoding')
        if encoding not in (None,'','identity'):
            result['analysis_status']='http_content_encoding_boundary'
            return None
        stage='http_body'
        if response.length is not None and response.length>MAX_ENTITY:
            result['analysis_status']='response_size_budget'
            return None
        # read() detects truncated Content-Length. Undeclared length uses a
        # bounded read, not unlimited allocation on untrusted server data.
        body=response.read() if response.length is not None else response.read(MAX_ENTITY+1)
        if len(body)>MAX_ENTITY:
            result['analysis_status']='response_size_budget'
            return None
        result['analysis_status']='http_entity_received'
        return body
    except ssl.SSLCertVerificationError:
        result['probe_error']='tls_verification_failed'
    except TimeoutError:
        result['probe_error']='probe_timeout'
    except (OSError,http.client.HTTPException):
        result['probe_error']='network_or_http_io'
    finally:
        if connection is not None:
            try: connection.close()
            except OSError: pass
    result['incomplete_stage']=stage
    return None


def probe_cmd101(abi):
    """One fixed GET; no next command, body/cookie/key or success assertion."""
    result=plan(abi)
    result['observed_at_utc']=datetime.now(timezone.utc).isoformat()
    body=_fetch_request(_request(abi),result)
    if body is not None:
        result.update(inspect_body(body))
    return result
