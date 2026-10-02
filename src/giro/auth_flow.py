"""Standalone registration/login wiring with explicit input providers."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from finance_cli.core.paths import data_home

from .codeguard_app import giro_task_settings
from .codeguard_crypto import CodeGuardCrypto
from .codeguard_http import CodeGuardHTTP
from .codeguard_lifecycle import ManagerConfig
from .codeguard_runtime import PythonProtectionRuntime
from .errors import GiroError
from .login import PinLogin, RecipientContext
from .protection_profile import ProtectionProfile
from .public_material_io import PublicCache
from .registration import DeviceRegistration
from .registration_flow import EnrollmentStore, enroll_once
from .session_store import SessionStore


BASE = 'https://m.giro.or.kr/CodeGuard/'
CODEGUARD_USER_AGENT = 'FinanceCLI/0.1'


def auth_execution_plan(*, register=False):
    return dict(operation='register-and-login' if register else 'pin-login',
        plan_only=True, network_used=False, input_accessed=False, institution_verified=False,
        existing_phone_registration_may_be_replaced=register,
        maximum_codeguard_requests=7 if register else 5,
        maximum_business_requests=10 if register else 4,
        maximum_terms_requests=3 if register else 0,
        device_identity='persistent CLI identity', protection_inputs='recorded-state-replay',
        session_storage='AES-GCM with private local key; PIN and protection token not saved',
        automatic_retry=False, payment=False,
        required_setup=['installed private protection profile', 'current recipient certificate/CRL cache'])


@dataclass(repr=False)
class Dependencies:
    profile: ProtectionProfile
    recipient: RecipientContext
    runtime: PythonProtectionRuntime
    user_agent: str
    processing_issues: list = field(default_factory=list)


@contextmanager
def login_dependencies(*, register=False, profile_path=None, public_cache=None):
    root = data_home()/'giro'
    profile = ProtectionProfile.load(profile_path or root/'protection.json')
    settings = giro_task_settings(etc_data=None)
    if ((profile.app_info, profile.version) != (settings.app_info, settings.version)
            or profile.platform.abi != 'arm64-v8a'):
        raise GiroError('현재 지로 버전에 맞는 보호 입력 자료가 필요합니다.')
    user_agent = profile.business_user_agent()
    sequence = ((101, 'GET'),) + ((200, 'GET'), (300, 'POST')) * (3 if register else 2)
    with PublicCache(Path(public_cache or root/'public-trust').absolute(), max_bytes=16*1024*1024) as cache:
        recipient = RecipientContext.from_public_cache(cache, locale_language=profile.locale_language)
        transport = CodeGuardHTTP(endpoint=BASE+'CodeGuard/check.jsp', send=True,
            default_user_agent=CODEGUARD_USER_AGENT, max_requests=len(sequence), request_sequence=sequence)
        runtime = PythonProtectionRuntime(config=ManagerConfig(profile.platform.service,
            profile.app_info, profile.version, BASE, BASE), platform=profile.platform,
            transport=transport, crypto=CodeGuardCrypto(), locale_language=profile.locale_language,
            map_profile=profile.map_profile)
        dependencies = Dependencies(profile, recipient, runtime, user_agent)
        try:
            yield dependencies
        finally:
            try: runtime.close(timeout=30)
            except Exception: dependencies.processing_issues.append('protection_cleanup_incomplete')
            try: transport.close()
            except Exception: dependencies.processing_issues.append('protection_transport_cleanup_incomplete')


def authenticate(*, pin_provider, register=False, enrollment_providers=None, send=False,
                 profile_path=None, public_cache=None, enrollment_store=None, session_store=None):
    """No file/provider access without send; no retry after any remote result.

    Registration continues explicitly through the login PIN provider. The
    providers are UI adapters, never PIN values or command-line arguments.
    """
    if not send: return auth_execution_plan(register=register)
    result = dict(operation='register-and-login' if register else 'pin-login', plan_only=False,
        network_used=False, session_saved=False, automatic_retry=False, processing_issues=[],
        registration_service_decision='unobserved', login_service_decision='unobserved')
    dependencies = None
    enrollment_store = enrollment_store if enrollment_store is not None else EnrollmentStore()
    session_store = session_store if session_store is not None else SessionStore()
    try:
        with login_dependencies(register=register, profile_path=profile_path, public_cache=public_cache) as dependencies:
            options = dict(recipient=dependencies.recipient, protection=dependencies.runtime,
                           user_agent=dependencies.user_agent)
            if register:
                if enrollment_providers is None: raise GiroError('기기 등록 입력 제공자가 필요합니다.')
                # Identity/phone input can use the explicit profile's observed
                # phone helper; no discovery, private Android ID, or host ID.
                providers = enrollment_providers(dependencies.profile)
                attempt = enroll_once(client_factory=lambda device_id: DeviceRegistration(device_id=device_id, **options),
                    store=enrollment_store, login_pin_provider=pin_provider, send=True, **providers)
                report = attempt.report()
                result.update(report)
                result['login_service_decision'] = (report['login'] or {}).get('login_service_decision', 'unobserved')
            else:
                client = PinLogin(device_id=enrollment_store.identity(), **options)
                attempt = client.login(pin_provider=pin_provider, send=True)
                result.update(attempt.report(), events=list(client.events))
            result['network_used'] = bool(result.get('events'))
            if attempt.session is not None:
                try:
                    session_store.save(attempt.session)
                    result['session_saved'] = True
                except Exception:
                    result['processing_issues'].append('session_save_incomplete')
    except (Exception, KeyboardInterrupt):
        result['processing_issues'].append('authentication_processing_incomplete')
    if dependencies is not None:
        result['processing_issues'].extend(dependencies.processing_issues)
    return result
