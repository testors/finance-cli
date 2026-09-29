"""Pure MainService challenge/postprocessing stages; no SDK or network run.

Native return values and environment observations are explicit inputs. No
missing status becomes clean/true. Local error formatting and Android cert
parsing remain explicit adapters, not fabricated server-issued tokens.
"""
from dataclasses import dataclass
import hashlib

from .codeguard_codec import java_utf8, java_base64_decode, java_seed_decrypt, CodeGuardCodecError
from .codeguard_exchange import challenge_parts, rcl_after_challenge
from .codeguard_rule import AnalysisLimit


class JavaStageError(ValueError):
    """Observed Java exception category, without input/exception-message leaks."""


class ObservedCertificateParseFailure(ValueError):
    """Adapter reports the original Android CertificateFactory exception."""


class ObservedJavaException(ValueError):
    """Adapter reports a Java Exception, not an unresolved/local Python error."""


class ReturnedTokenDecodeError(ValueError):
    sdk_error = 'CG_RETRY01'
    sdk_message = 'token decryption fail'


def java_text(value):
    return 'null' if value is None else value


def java_substring(text, start, end=None):
    if text is None:
        raise JavaStageError('null_string_substring')
    raw = text.encode('utf-16-le','surrogatepass')
    if end is None:
        end = len(raw)//2
    if not 0 <= start <= end <= len(raw)//2:
        raise JavaStageError('string_substring_bounds')
    return raw[2*start:2*end].decode('utf-16-le','surrogatepass')


@dataclass(repr=False)
class ChallengeState:
    challenge: str | None = None
    rule: str | None = None
    certificate_text: str | None = None
    certificate: object = None
    fourth: str | None = None
    rcl_suffix: str = ''

    def consume(self, text, *, decode_certificate=None):
        """CodeGuardChallenge.a(String), including stale/partially updated fields.

        decode_certificate represents an ALREADY obtained Android default
        factory, not the yessign factory. An absent adapter leaves factory
        lookup unresolved, not a fabricated observed parse failure.
        """
        parts = challenge_parts(text)
        if len(parts) >= 2:
            self.challenge,self.rule = parts[:2]
        if len(parts) >= 3:
            if decode_certificate is None:
                raise AnalysisLimit('Android challenge CertificateFactory adapter required')
            self.certificate_text = parts[2]  # after factory lookup, before decode
            try:
                decoded = java_base64_decode(parts[2])
                if decoded is None:
                    # ByteArrayInputStream(null) fails before the factory call,
                    # inside the original catch(Exception).
                    raise ObservedCertificateParseFailure()
                certificate = decode_certificate(decoded)
            except ObservedCertificateParseFailure:
                pass  # old certificate object is retained
            else:
                self.certificate = certificate
            if len(parts) == 4:  # >4 does NOT assign fourth field
                self.fourth = parts[3]

    def apply_rcl(self, rcl):
        if rcl:
            if self.challenge is None:
                raise JavaStageError('null_challenge_rcl_length')
            suffix = rcl_after_challenge(rcl,self.challenge)
            self.rcl_suffix = suffix

    def consume_steps(self,text,*,decode_certificate=None):
        """Full factory/parse/cast/log catch order as explicit offline effects.

        The optional legacy adapter is an already-observed factory/parser
        projection; without it, actual factory lookup and logging are NOT
        silently assumed successful or replaced by a local parse failure.
        """
        if decode_certificate is not None:
            self.consume(text,decode_certificate=decode_certificate)
            return
        # Local import avoids effects → flow's exception/base-helper cycle.
        from .codeguard_effects import Effect,JavaFault
        parts=challenge_parts(text)
        if len(parts)>=2:
            self.challenge,self.rule=parts[:2]
        if len(parts)>=3:
            try:
                factory=yield Effect('x509_certificate_factory',('X.509',))
                self.certificate_text=parts[2]
                raw=java_base64_decode(parts[2])
                # ByteArrayInputStream(null) NPE is caught here and its text
                # is never used, so no platform exception text is fabricated.
                if raw is not None:
                    cert=yield Effect('x509_generate_certificate',(factory,raw))
                    cert=yield Effect('cast_x509_certificate',(cert,))
                    self.certificate=cert
                    # Evaluates subject/serial/NotAfter even if logs disabled.
                    # A logging failure retains the new certificate object.
                    yield Effect('log_codeguard_certificate',(cert,))
            except JavaFault:
                pass
            if len(parts)==4:
                self.fourth=parts[3]  # also after factory/parse/log Exception


def challenge_should_continue(value):
    # The logging StringBuilder evaluates value.indexOf BEFORE the null guard.
    if value is None:
        raise JavaStageError('null_challenge_before_guard')
    return not value.startswith('E101_NET_ERROR')


def effective_split(*, metadata_status, metadata_value, updater_split):
    if metadata_status in ('absent_bundle','exception'):
        value = False  # actual observed path, not a default for unknown inputs
    elif metadata_status == 'value' and type(metadata_value) is bool:
        value = metadata_value
    else:
        raise AnalysisLimit('actual metadata read outcome required')
    if type(updater_split) is not bool:
        raise AnalysisLimit('actual Updater split field required')
    return value or updater_split


def submission_responses(response, nonce_return, *, zip_status, zip_error,
                         fingerprint_status, fingerprint_error, format_error):
    """Values AFTER generateEncResponse/getNonce and actual environment checks.

    format_error is the original local-error Token/JSONObject adapter. Its
    serialization order/time are not guessed here. No socket or JNI execution.
    """
    if zip_status not in ('passed','failed'):
        raise AnalysisLimit('actual zip-check outcome required')
    if zip_status == 'failed':
        response = format_error('CG_CONN_ENGINE01','unZip error : '+java_text(zip_error),'CG_CONN_ENGINE')
    if fingerprint_status not in ('passed','failed','exception'):
        raise AnalysisLimit('actual fingerprint-check outcome required')
    if fingerprint_status == 'failed':
        try:
            response = format_error('CG_CONN_ENGINE01','FingerPrint error('+java_text(fingerprint_error)+')','CG_CONN_ENGINE')
        except ObservedJavaException:
            pass  # the original try also covers error-token formatting
    # fingerprint exceptions are swallowed; existing response is retained.
    if response is None:
        raise JavaStageError('null_response_before_guard')
    # indexOf E101_ENGINE_LOAD_ERROR0_12/120 results are not used to prevent CMD300.
    return response,nonce_return


def returned_token_key_iv(challenge):
    digest = java_utf8('BTW::SSLSIGN::KS-PASSWD::'+java_text(challenge))
    for _ in range(1024):
        digest = hashlib.sha1(digest).digest()
    return digest[:16],hashlib.sha1(digest).digest()[:16]


def decode_returned_token(token, *, challenge, encrypted_token):
    """MainService's optional ETOKEN return stage; not token verification/issue.

    Failure formatter needs original Java exception text; that mapping is not
    guessed. ReturnedTokenDecodeError identifies the CG_RETRY01 branch only.
    """
    if not encrypted_token:
        return token
    if token is None:
        raise JavaStageError('null_token_contains')
    if '[ETOKEN]' not in token:
        return token
    # Original contains(), then fixed substring(8), NOT marker position+8.
    encoded = java_substring(token,8)
    key,iv = returned_token_key_iv(challenge)
    try:
        plain = java_seed_decrypt(java_base64_decode(encoded),key,iv)
    except CodeGuardCodecError:
        raise ReturnedTokenDecodeError('returned_token_java_decrypt_failure') from None
    try:
        return plain.decode('utf-8')
    except UnicodeDecodeError:
        raise AnalysisLimit('Android decrypted token UTF-8 replacement boundary') from None
