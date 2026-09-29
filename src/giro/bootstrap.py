"""Explicit, PIN-free public recipient-certificate probe; NOT a login client.

Only one fixed POST, no redirects/retries/cookies or device identifier. The
unmodified app uses deviceId and its own UA; their absence is diagnostic, never
hidden by a fabricated identifier. TLS validates the web endpoint, NOT the
returned CMS recipient. Raw responses, cookies and exceptions never leave here.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import socket
import ssl

from .http_body import BodySizeLimit
from .protocol import APP_VERSION, ENDPOINTS
from .response import receive_bytes

HOST = 'm.giro.or.kr'
PATH = ENDPOINTS['auth.server-cert'].path
MAX_ENTITY = 2 * 1024 * 1024
MAX_INFLATED = 4 * 1024 * 1024
TIMEOUT = 15


def plan():
    return {
        'offline': True, 'network_attempted': False, 'live_login_ready': False,
        'endpoint': 'auth.server-cert', 'url': 'https://' + HOST + PATH,
        'method': 'POST', 'form_fields': ['appVersion'], 'app_version': APP_VERSION,
        'tls_verification_required': True, 'pin_used': False, 'device_id_used': False,
        'cookies_persisted': False, 'redirects': False, 'retries': 0,
        'certificate_validation_performed': False,
        'app_success': None, 'analysis_status': 'plan_only',
        'differences_from_app': ['deviceId_omitted_not_guessed', 'explicit_probe_user_agent',
                                 'python_tls_http_stack', 'connection_close', 'no_redirects_or_retries',
                                 '15_second_socket_timeout', 'bounded_response_size'],
    }


def _safe_code(value):
    # A server-controlled string could contain a token or error text. Preserve
    # the in-memory app decision but expose ONLY short ASCII numeric codes.
    return value if isinstance(value, str) and 2 <= len(value) <= 3 and value.isascii() and value.isdigit() else None


def _certificate_report(text):
    from .cert_factory import inspect_recipient, select_certificate, CertificateBackendLimit
    from .cert_input import CertificateInputError
    if text is None:
        return {'present': False, 'analysis_status': 'not_supplied'}
    data = text.encode('utf-8', errors='replace')  # Android default charset
    result = {'present': True, 'input_bytes': len(data), 'analysis_status': 'partial'}
    try:
        result['inspection'] = inspect_recipient(data)
        selection = select_certificate(data)
        from cryptography import x509
        cert = x509.load_der_x509_certificate(selection.data)
        now = datetime.now(timezone.utc)
        result['public_certificate'] = {
            'sha256': hashlib.sha256(selection.data).hexdigest(),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'within_validity_at_probe_time': cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
            'signature_algorithm_oid': cert.signature_algorithm_oid.dotted_string,
        }
        try:
            policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
            result['public_certificate']['policy_oids'] = [p.policy_identifier.dotted_string for p in policies]
        except x509.ExtensionNotFound:
            result['public_certificate']['policy_oids'] = None
        # Record only kinds/counts, not DN, serial, raw extensions or URLs.
        result['public_certificate']['extension_oids'] = [ext.oid.dotted_string for ext in cert.extensions]
    except CertificateInputError:
        result['analysis_status'] = 'original_input_structure_error'
    except CertificateBackendLimit:
        result['analysis_status'] = 'backend_unmodeled'
    except Exception:
        # Diagnostic boundary, not a replacement for application error codes.
        result['analysis_status'] = 'local_inspection_unavailable'
    return result


def _tls_context():
    # PROTOCOL_TLS_CLIENT requires hostname and chain verification. Unlike
    # create_default_context(), it never enables SSLKEYLOGFILE from the env.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    return context


def probe_server_cert():
    """Perform one explicitly authorized public bootstrap request.

    This low-level function DOES connect. CLI requires --live. No caller URL,
    PIN, token, device ID, key, cookie or arbitrary request data is accepted.
    Limits are analysis limits with app_success=None, not invented app failures.
    """
    result = {**plan(), 'offline': False, 'network_attempted': True,
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'analysis_status': 'incomplete', 'http_status': None,
              'tls_endpoint_verified': False}
    connection = None
    stage = 'tls_connect'
    try:
        connection = http.client.HTTPSConnection(HOST, 443, timeout=TIMEOUT,
                                                 context=_tls_context())
        connection.connect()
        result['tls_endpoint_verified'] = True
        stage = 'http_request'
        # App calls POST/NOTHING on a fresh cookie-free client. Bridge adds
        # gzip; receive_bytes must see pre-Bridge request headers (empty).
        connection.request('POST', PATH, body=('appVersion=' + APP_VERSION).encode('ascii'),
                           headers={'Content-Type': 'application/x-www-form-urlencoded',
                                    'Accept-Encoding': 'gzip', 'Connection': 'close',
                                    'User-Agent': 'GiroCLI-bootstrap/0.1 (public-cert-probe)'})
        response = connection.getresponse()
        result['http_status'] = response.status
        headers = response.getheaders()  # transient only; never log Set-Cookie
        body = None
        if 200 <= response.status < 300:
            stage = 'http_body'
            if response.length is not None and response.length > MAX_ENTITY:
                result['analysis_limit'] = 'response_size_budget'
                result['incomplete_stage'] = stage
                return result
            # read(amt) can silently return a short Content-Length body in
            # http.client. For a bounded declared length, read() instead uses
            # _safe_read and detects truncation BEFORE replaying any JSON.
            body = response.read() if response.length is not None else response.read(MAX_ENTITY + 1)
            if len(body) > MAX_ENTITY:
                result['analysis_limit'] = 'response_size_budget'
                result['incomplete_stage'] = stage
                return result
        stage = 'app_response_replay'
        received = receive_bytes('auth.server-cert', response.status, headers, body,
                                 max_decoded_bytes=MAX_INFLATED)
        result.update(app_success=received.app_success, analysis_status='response_replayed',
                      response_code=_safe_code(received.code), callback=received.callback,
                      callback_code=_safe_code(received.callback_code), origin=received.origin,
                      response_code_redacted=received.code is not None and _safe_code(received.code) is None,
                      callback_code_redacted=received.callback_code is not None and _safe_code(received.callback_code) is None,
                      issues=list(received.issues))
        if received.app_success:
            # Inspect only on QueryClient success, like IntroActivity. Missing
            # cert/partial rule failures MUST NOT flip the JSON success code.
            stage = 'recipient_inspection'
            result['recipient'] = _certificate_report(received.query.get('serverCert'))
    except BodySizeLimit:
        result['analysis_limit'] = 'response_size_budget'
    except ssl.SSLCertVerificationError:
        result['probe_error'] = 'tls_verification_failed'
    except (socket.timeout, TimeoutError):
        result['probe_error'] = 'probe_timeout'
    except (OSError, http.client.HTTPException):
        result['probe_error'] = 'network_or_http_io'
    except Exception:
        # No exception messages/tracebacks with remote text or raw payloads.
        result['analysis_limit'] = 'unmodeled_local_boundary'
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    if result['analysis_status'] == 'incomplete':
        result['incomplete_stage'] = stage
    return result
