"""Supported endpoint catalog.

No HTTP client is implemented here. Unresolved defaults are not guessed.
"""
from dataclasses import asdict, dataclass
from .compat import json_value, omit_null_fields, read_model, string_value
from .errors import GiroError

BASE_URL = "https://m.giro.or.kr"
APP_VERSION = "4.9.5"
COMMON = ("appVersion", "deviceId")
LIST_FIELDS = ("juminNo", "useUIDInfoYn", "page", "pageSize",
               "agreeUIDInfoSaveYn", "showUIDInfoNoticeYn")
DETAIL_FIELDS = ("sortCode", "giroNo", "elecNo")


@dataclass(frozen=True)
class Endpoint:
    name: str
    path: str
    mode: str
    fields: tuple[str, ...]
    session_required: bool = False
    codeguard_required: bool = False

    def describe(self):
        return {**asdict(self), "method": "POST", "base_url": BASE_URL,
                "common_fields": COMMON, "network_enabled": False}


_ENDPOINTS = [
    Endpoint("auth.server-cert", "/home/mQryServerCert.m", "NOTHING", ()),
    Endpoint("auth.device-status", "/home/mQryDeviceRegStatus.m", "ENVELOP", ("deviceUniqNo",)),
    Endpoint("auth.datetime", "/service/common/mQryDateTime.m", "ENVELOP", ()),
    Endpoint("auth.pin", "/home/mGiroAppLogin.m", "ENCRYPT",
             ("작업구분", "deviceUniqNo", "pin", "CODE_RESPONSE"), codeguard_required=True),
    Endpoint("integrated.summary", "/service/integrated/mIntegratedQrySimple.m", "ENCRYPT",
             ("juminNo", "useUIDInfoYn"), session_required=True),
    Endpoint("accounts.registered", "/mygiro/account/mQryUserAcntList.m", "ENCRYPT", (), True),
    Endpoint("receipts.list", "/mygiro/receipt/mQryReceiptList.m", "ENCRYPT",
             ("startDate", "endDate", "page", "pageSize"), True),
    Endpoint("receipts.detail", "/mygiro/receipt/mQryReceiptDetail.m", "ENCRYPT",
             ("sortCode", "giroNo", "key", "paidDate"), True),
    Endpoint("accounts.payable", "/service/common/mAppQryPayableAccountList.m", "ENCRYPT",
             ("serviceCode", "isReserve"), True),
    Endpoint("accounts.banks", "/service/common/mAppQryPayableBankList.m", "ENCRYPT",
             ("serviceCode", "isReserve")),
    Endpoint("hometax.detail", "/service/link/nts/mLinkNtsQryBillDetail.m", "ENCRYPT",
             ("msg", "yakgwanYn"), codeguard_required=True),
    Endpoint("national.payment", "/service/ntax/ntaxsearch/mNtaxSearchProcPayment.m", "ENCRYPT",
             ("serviceCode", "sortCode", "giroNo", "key", "when", "mnyEditYn", "bankCode",
              "계좌번호", "acntPwd", "납부금액", "acntPaymentType", "addCertMethod",
              "encAddCertValue", "signedval", "ucpidval"), True),
    Endpoint("hometax.payment", "/service/link/nts/mLinkNtsProcPayment.m", "ENCRYPT",
             ("serviceCode", "bankCode", "계좌번호", "acntPwd", "납부금액", "addCertMethod",
              "encAddCertValue", "signedval", "ucpidval")),
]
for _kind, _directory, _prefix in (
    ("national", "ntax/ntaxsearch", "NtaxSearch"),
    ("local", "localtax/localtaxsearch", "Localtax"),
    ("customs", "ntax/tariff", "Tariff"),
):
    _ENDPOINTS.extend([
        Endpoint(f"{_kind}.list", f"/service/{_directory}/m{_prefix}QryBillList.m", "ENCRYPT",
                 LIST_FIELDS + (("sortCode", "giroNo", "convNapbuNo") if _kind == "local" else ()), True),
        Endpoint(f"{_kind}.detail", f"/service/{_directory}/m{_prefix}QryBillDetail.m", "ENCRYPT",
                 DETAIL_FIELDS, True),
    ])
ENDPOINTS = {entry.name: entry for entry in _ENDPOINTS}


def endpoint(name):
    try:
        return ENDPOINTS[name]
    except KeyError:
        raise GiroError("지원하지 않는 요청입니다. 요청 목록에서 선택해 주세요.") from None


def auth_plan():
    from .runtime import deployment_plan
    return {
        "offline": True, "app_version": APP_VERSION, "live_login_ready": False,
        "deployment": deployment_plan(),
        "steps": [
            {"endpoint": "auth.server-cert", "mode": "NOTHING", "method": "POST",
             "effect": "serverCert 수신 후 용도/경로/CRL 검증; 별도 쿠키 없는 클라이언트 사용",
             "implemented_components": ["recipient_input_and_selection", "sdk_dn_rsa_and_crl_rules",
                                        "name_constraints", "supplied_path_validation_order",
                                        "issuer_crl_acquisition_effects", "anchor_loop_and_builder_walk",
                                        "ldap_uri_wire_and_response_replay", "ctl_signed_data_rsa_and_membership",
                                        "ctl_candidate_loop_and_anchor_promotion_effects",
                                        "ctl_to_remaining_path_and_crl_rules", "bounded_single_signer_selector",
                                        "bounded_android_principal_and_public_store_selectors",
                                        "builder_ctl_and_lazy_crl_pipeline", "restricted_public_cache_executor",
                                        "opt_in_anonymous_ldap_socket_executor", "offline_recipient_discovery_inspector",
                                        "pinned_public_root_preparation", "recipient_context_from_public_cache"],
             "remaining_components": ["cms_ber_provider_time_and_multisigner_boundaries", "android_selectors_and_store_order",
                                      "live_public_material_and_transport_equivalence",
                                      "ctl_global_trust_and_cache_state", "recipient_installation"]},
            {"endpoint": "auth.device-status", "mode": "ENVELOP", "method": "POST",
             "effect": "CMS 전자봉투 생성, 새 SEED 키 보관, 등록 기기 상태 확인"},
            {"endpoint": "auth.datetime", "mode": "ENVELOP", "method": "POST",
             "effect": "비로그인 경로에서 키 재생성; 이미 로그인한 경우 ENCRYPT"},
            {"operation": "mTransKey PIN codec", "effect": "직전 세션 키로 6개 독립 블록 암호화"},
            {"operation": "CodeGuard token", "implemented": False,
             "implemented_components": ["native_rule_decode", "rule_selection_and_evaluation",
                                        "java_native_base64_and_seed", "jni_modified_utf8", "response_envelope",
                                        "cg_get_auth_code_arithmetic", "nonce_100_dispatch_functions",
                                        "nonce_artifact_mix_digest", "package_digest",
                                        "first_response_arithmetic", "java_response_string_frame",
                                        "updater_request_serialization", "updater_field_state_and_hash_key",
                                        "updater_rsa_key_wrap", "java_challenge_split_and_rcl_substring",
                                        "challenge_partial_field_state", "generateToken_submission_postprocessing",
                                        "returned_etoken_decode", "task_token_consumption_and_manager_callback",
                                        "task_background_and_agent_call_effects", "oscheck_source_and_digest",
                                        "generateResponse_control_flow_effects", "agent_update_callback_effects",
                                        "generateToken_updater_response_orchestration",
                                        "updater_cmd101_200_300_call_and_catch_order",
                                        "updater_key_and_certificate_initialization_effects",
                                        "java_random_explicit_seed_key_arithmetic",
                                        "engine_single_read_and_digest_tail_comparison",
                                        "android_json_tokener_and_string_coercion",
                                        "httpcookie_wire_projection_and_parse_only_catch",
                                        "raw_http_value_to_generateToken_composition",
                                        "service_url_composition", "fixed_pin_free_cmd101_probe",
                                        "fixed_pin_free_cmd101_200_challenge_probe",
                                        "android_urlconnection_ordered_header_projection",
                                        "challenge_factory_parse_cast_log_effects",
                                        "optional_initial_material_diagnostics",
                                        "rcl_policy_inventory_and_extended_device_effects",
                                        "standard_device_and_execshell_effects",
                                        "application_package_manager_client_effects",
                                        "giro_task_settings_and_phone_build_input_steps",
                                        "native_start_jni_and_file_effect_composition",
                                        "native_nonce_jni_file_and_signer_effect_composition",
                                        "zip_preparation_cache_and_fingerprint_effect_composition",
                                        "oscheck_callable_future_device_effect_composition",
                                        "main_service_constructor_and_agent_call_composition",
                                        "agent_initial_update_and_worker_main_composition",
                                        "owned_jni_string_values_and_canonical_modified_utf8",
                                        "known_single_der_signer_value_backend",
                                        "known_signed_data_fingerprint_value_backend",
                                        "task_manager_lifetime_and_explicit_callback_dispatch",
                                        "known_local_error_json_clock_and_map_profiles"],
             "remaining_components": ["native_start_checks_and_input_collection", "getNonce_checks_and_six_input_collection",
                                      "actual_device_manager_and_async_observations",
                                      "actual_mainservice_context_and_jni_observations",
                                      "framework_queue_future_cancellation_and_thread_observations",
                                      "actual_updater_preference_and_platform_io",
                                      "certificate_provider_failures_and_local_error_runtime_boundaries",
                                      "android_value_numeric_date_locale_charset_boundaries",
                                      "actual_urlconnection_tls_stream_and_header_order",
                                      "live_exchange_and_server_token"]},
            {"endpoint": "auth.pin", "mode": "ENCRYPT", "method": "POST",
             "implemented_components": ["single_attempt_pin_login_coordinator",
                                        "device_identity_selection_from_explicit_observations",
                                        "unregistered_device_identity_verification_route",
                                        "mandatory_recipient_rules_before_envelope",
                                        "isolated_certificate_and_shared_service_transport",
                                        "prelogin_envelope_key_rotation",
                                        "two_stateful_codeguard_callbacks",
                                        "login_verdict_and_session_readiness_separation",
                                        "authenticated_query_and_payment_session_handoff"],
             "remaining_components": ["normal_protection_runtime", "current_trust_configuration",
                                      "registered_device_identity", "live_login_acceptance"],
             "effect": "내부 CODE_RESPONSE / 외부 CODE_RESPONSE_TOKEN; 쿠키·키 유지"},
        ],
        "blockers": [
            "CodeGuard 원문 JSON/쿠키→generateToken·CMD101/200/300까지 오프라인 연결; JNI/OS 실제 입력·값 변환 경계·실제 통신/발급 미완성",
            "공개 루트 준비·cache/LDAP·필수 경로/CRL 연결 구현; 일반 selector/provider·CTL trust 상태와 수신자 구성의 추가 검증 필요",
            "등록 기기 ID와 본인정보 등록 상태 필요; 기기 정보를 자동 수집하지 않음",
            "PIN 로그인→조회·납부의 쿠키/키 연결은 합성 검증; 정상 보호 모듈·현재 신뢰 자료·등록 기기 입력과 실서버 수락 검증 필요",
            "비Android 서버가 목표; Android 프로세스/패키지 결합의 독립 구현 가능 범위는 미확정이며 호스트 정보나 검사 통과 상수로 대체하지 않음",
            "실제 서버 로그인·조회 및 오류/만료 처리 검증 안 됨",
        ],
    }


def request_plan(name):
    ep = endpoint(name)
    result = ep.describe()
    result["stage"] = "schema-only; not sent"
    result["notes"] = ["필드 목록은 서버 필수값 스키마가 아닌 코드에서 확인한 요청 후보입니다."]
    if name in ('national.list', 'local.list', 'customs.list'):
        result["known_defaults"] = {"page": "1", "pageSize": "10", "agreeUIDInfoSaveYn": "Y",
                                    "showUIDInfoNoticeYn": "N"}
        result["unresolved_defaults"] = []
        result["notes"].append("서비스 초기화값 기록이며 실제 전송·동의·정보저장 권한을 의미하지 않습니다.")
        result["notes"].append("본인 조회의 useUIDInfoYn=Y는 계정의 본인정보 등록 상태를 먼저 확인해야 합니다.")
    if name == "auth.datetime":
        result["notes"].append("비로그인 기준 ENVELOP; 로그인 상태에서는 ENCRYPT")
    if name in ('accounts.payable', 'accounts.banks'):
        result['known_defaults'] = {'isReserve': 'N'}
        result['notes'].append('serviceCode는 선택한 납부 대상에서 가져옵니다. 계좌 목록을 자동 등록하지 않습니다.')
    if name.endswith('.payment'):
        result['notes'].append('요청·응답 모델만 지원합니다. 납부 전송·인증·출금은 실행하지 않습니다.')
    return result


def query_string(fields):
    """App's inner string: skip nulls, append raw values, stringify JSON arrays."""
    pairs = []
    for key, value in fields.items():
        if value is None:
            continue
        if not isinstance(key, str):
            raise GiroError("JSON 객체의 필드 이름은 문자열이어야 합니다.")
        if isinstance(value, list):
            rendered = json_value(omit_null_fields(value))
        else:
            # JsonObject.getAsString throws in the app too.
            rendered = string_value(value)
        pairs.append(f"{key}={rendered}")
    return "&".join(pairs)


def build_query(name, fields, *, device_id):
    """Gson model -> common-field assignment -> inner query, like QueryClient.

    No invented checks on cipher length, token status or device equality. The
    PIN-input UI's six-digit check remains in encode_pin, not the transport.
    """
    endpoint(name)
    values = read_model(fields, name)
    if values is None:
        raise GiroError("서비스 전송 계층은 null query를 처리하지 못합니다.")
    if name == "auth.pin":
        # Scope boundary, not inferred server validation. No mutation command.
        if values.get("작업구분") not in (None, "로그인"):
            raise GiroError("로그인 작업만 지원합니다.")
    values.update(appVersion=APP_VERSION, deviceId=string_value(device_id))
    return query_string(values)


def encrypted_form(ciphertext, *, token=None):
    """Outer UTF-8 form body, after ENCRYPT/ENVELOP. Never sends a request."""
    if not isinstance(ciphertext, bytes):
        raise GiroError("암호문 bytes가 필요합니다.")
    fields = {"encryptedData": ciphertext.hex()}
    if token is not None:
        if not isinstance(token, str):
            raise GiroError("토큰은 문자열이어야 합니다.")
        fields["CODE_RESPONSE_TOKEN"] = token
    return "&".join(_form_encode(key) + "=" + _form_encode(value)
                    for key, value in fields.items()).encode("ascii")


def _form_encode(value):
    # HttpUrl.FORM_ENCODE_SET / canonicalize(add, alreadyEncoded=false).
    # urllib.urlencode differs for space, ~ and *. Use Java form encoding.
    encode_set = set(b" \"':;<=>@[]^`{}|/\\?#&!$(),~%+")
    return "".join(f"%{byte:02X}" if byte < 32 or byte >= 127 or byte in encode_set
                   else chr(byte) for byte in value.encode("utf-8", errors="replace"))
