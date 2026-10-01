import unittest
from urllib.parse import parse_qs
from giro.errors import GiroError
from giro.protocol import ENDPOINTS, auth_plan, build_query, encrypted_form, endpoint, query_string, request_plan

class ProtocolTests(unittest.TestCase):

    def test_auth_modes_match_bridges(self):
        self.assertEqual(endpoint('auth.server-cert').mode, 'NOTHING')
        self.assertEqual(endpoint('auth.device-status').mode, 'ENVELOP')
        self.assertEqual(endpoint('auth.datetime').mode, 'ENVELOP')
        self.assertEqual(endpoint('auth.pin').mode, 'ENCRYPT')
        self.assertFalse(auth_plan()['live_login_ready'])
        self.assertEqual(auth_plan()['steps'][0]['method'], 'POST')

    def test_explicit_offline_catalog_no_arbitrary_urls(self):
        self.assertEqual(len(ENDPOINTS), 19)
        for ep in ENDPOINTS.values():
            self.assertFalse(ep.describe()['network_enabled'])
            self.assertNotIn('InsSearchKey', ep.path)
        for name in ('accounts.register', 'https://example.invalid', '/home/mGiroAppLogin.m'):
            with self.assertRaises(GiroError):
                endpoint(name)

    def test_plan_distinguishes_supplied_path_and_postprocessing_from_live_ready(self):
        plan = auth_plan()
        cert = plan['steps'][0]
        cg = next((step for step in plan['steps'] if step.get('operation') == 'CodeGuard token'))
        self.assertIn('supplied_path_validation_order', cert['implemented_components'])
        self.assertIn('issuer_crl_acquisition_effects', cert['implemented_components'])
        self.assertIn('ctl_signed_data_rsa_and_membership', cert['implemented_components'])
        self.assertIn('ctl_to_remaining_path_and_crl_rules', cert['implemented_components'])
        self.assertIn('bounded_single_signer_selector', cert['implemented_components'])
        self.assertIn('bounded_android_principal_and_public_store_selectors', cert['implemented_components'])
        self.assertIn('builder_ctl_and_lazy_crl_pipeline', cert['implemented_components'])
        self.assertIn('restricted_public_cache_executor', cert['implemented_components'])
        self.assertIn('opt_in_anonymous_ldap_socket_executor', cert['implemented_components'])
        self.assertIn('offline_recipient_discovery_inspector', cert['implemented_components'])
        self.assertIn('live_public_material_and_transport_equivalence', cert['remaining_components'])
        self.assertIn('ctl_global_trust_and_cache_state', cert['remaining_components'])
        self.assertIn('recipient_installation', cert['remaining_components'])
        self.assertNotIn('ctl_validation', cert['remaining_components'])
        self.assertIn('cms_ber_provider_time_and_multisigner_boundaries', cert['remaining_components'])
        self.assertIn('returned_etoken_decode', cg['implemented_components'])
        self.assertIn('task_token_consumption_and_manager_callback', cg['implemented_components'])
        self.assertIn('generateResponse_control_flow_effects', cg['implemented_components'])
        self.assertIn('agent_update_callback_effects', cg['implemented_components'])
        self.assertIn('generateToken_updater_response_orchestration', cg['implemented_components'])
        self.assertIn('updater_key_and_certificate_initialization_effects', cg['implemented_components'])
        self.assertIn('java_random_explicit_seed_key_arithmetic', cg['implemented_components'])
        self.assertIn('engine_single_read_and_digest_tail_comparison', cg['implemented_components'])
        self.assertIn('android_json_tokener_and_string_coercion', cg['implemented_components'])
        self.assertIn('httpcookie_wire_projection_and_parse_only_catch', cg['implemented_components'])
        self.assertIn('raw_http_value_to_generateToken_composition', cg['implemented_components'])
        self.assertIn('service_url_composition', cg['implemented_components'])
        self.assertIn('fixed_pin_free_cmd101_probe', cg['implemented_components'])
        self.assertIn('fixed_pin_free_cmd101_200_challenge_probe', cg['implemented_components'])
        self.assertIn('android_urlconnection_ordered_header_projection', cg['implemented_components'])
        self.assertIn('challenge_factory_parse_cast_log_effects', cg['implemented_components'])
        self.assertIn('optional_initial_material_diagnostics', cg['implemented_components'])
        self.assertIn('native_start_jni_and_file_effect_composition', cg['implemented_components'])
        self.assertIn('native_nonce_jni_file_and_signer_effect_composition', cg['implemented_components'])
        self.assertIn('zip_preparation_cache_and_fingerprint_effect_composition', cg['implemented_components'])
        self.assertIn('oscheck_callable_future_device_effect_composition', cg['implemented_components'])
        self.assertIn('actual_urlconnection_tls_stream_and_header_order', cg['remaining_components'])
        self.assertIn('android_value_numeric_date_locale_charset_boundaries', cg['remaining_components'])
        self.assertNotIn('android_jsonobject_httpcookie_and_urlconnection', cg['remaining_components'])
        self.assertNotIn('generateToken_orchestration_and_updater_initialization', cg['remaining_components'])
        self.assertIn('main_service_constructor_and_agent_call_composition', cg['implemented_components'])
        self.assertNotIn('mainservice_constructor_and_jni_load_state', cg['remaining_components'])
        self.assertIn('actual_mainservice_context_and_jni_observations', cg['remaining_components'])
        self.assertIn('agent_initial_update_and_worker_main_composition', cg['implemented_components'])
        self.assertIn('owned_jni_string_values_and_canonical_modified_utf8', cg['implemented_components'])
        self.assertIn('known_single_der_signer_value_backend', cg['implemented_components'])
        self.assertIn('task_manager_construction_and_queue_callback_composition', cg['remaining_components'])
        self.assertIn('actual_updater_preference_and_platform_io', cg['remaining_components'])
        self.assertIn('actual_device_manager_and_async_observations', cg['remaining_components'])
        self.assertIn('live_exchange_and_server_token', cg['remaining_components'])
        self.assertFalse(cg['implemented'])
        self.assertFalse(plan['live_login_ready'])

    def test_restored_defaults_are_described_not_injected(self):
        result = request_plan('national.list')
        self.assertEqual(result['known_defaults'], {'page': '1', 'pageSize': '10', 'agreeUIDInfoSaveYn': 'Y', 'showUIDInfoNoticeYn': 'N'})
        self.assertEqual(result['unresolved_defaults'], [])

    def test_inner_not_urlencoded(self):
        self.assertEqual(query_string({'작업구분': '로그인', 'empty': '', 'skip': None}), '작업구분=로그인&empty=')
        self.assertEqual(query_string({'a': ['한글', 1], 'b': True}), 'a=["한글",1]&b=true')

    def test_raw_delimiters_preserved_like_app(self):
        for value in ('a&b=c', 'a=b', 'a\nb', 'a+b%20'):
            self.assertEqual(query_string({'test': value}), 'test=' + value)

    def test_original_unsupported_inner_shapes_still_fail(self):
        for value in ({}, float('nan')):
            with self.subTest(value=value), self.assertRaises(GiroError):
                query_string({'test': value})

    def test_build_query_uses_original_model_not_candidate_allowlist(self):
        result = build_query('national.list', {'useUIDInfoYn': 'Y', 'page': '1'}, device_id='SYNTHETIC')
        self.assertIn('appVersion=4.9.5&deviceId=SYNTHETIC', result)
        self.assertNotIn('agreeUIDInfoSaveYn', result)
        result = build_query('national.list', {'responseCode': '000', 'unknown': {}}, device_id='SYNTHETIC')
        self.assertIn('responseCode=000', result)
        self.assertNotIn('unknown', result)

    def test_transport_has_no_invented_pin_token_device_checks(self):
        fields = {'pin': '', 'deviceUniqNo': 'DIFFERENT', 'CODE_RESPONSE': ''}
        result = build_query('auth.pin', fields, device_id='')
        self.assertIn('pin=', result)
        self.assertIn('CODE_RESPONSE=', result)
        self.assertIn('deviceUniqNo=DIFFERENT', result)
        fields['pin'] = 'ab' * 96
        self.assertIn('작업구분=로그인', build_query('auth.pin', fields, device_id='SYNTHETIC'))
        fields['작업구분'] = '변경'
        with self.assertRaises(GiroError):
            build_query('auth.pin', fields, device_id='SYNTHETIC')

    def test_outer_empty_and_null_are_distinct(self):
        self.assertEqual(encrypted_form(b'', token=''), b'encryptedData=&CODE_RESPONSE_TOKEN=')
        self.assertEqual(encrypted_form(b'', token=None), b'encryptedData=')

    def test_outer_form_matches_okhttp_literal_encoding(self):
        self.assertEqual(encrypted_form(b'\xab', token=' ~*+%\n한'), b'encryptedData=ab&CODE_RESPONSE_TOKEN=%20%7E*%2B%25%0A%ED%95%9C')

    def test_two_token_layers_not_combined(self):
        token = '{"CODE_RESPONSE":"a+b&c="}'
        result = encrypted_form(b'\xab\xcd', token=token)
        self.assertEqual(parse_qs(result.decode()), {'encryptedData': ['abcd'], 'CODE_RESPONSE_TOKEN': [token]})
