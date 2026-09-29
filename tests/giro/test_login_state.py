import json
from pathlib import Path
import re
import unittest
from giro.login_state import BOOLEAN_FIELDS, SPECIAL_FIELDS, STRING_FIELDS, REFRESH_FIELDS, DEVICE_FLAGS, LoginState, StateAnalysisLimit, parse_login_info, replay
from giro.response import receive, receive_bytes, transport_failure

def response(body, name='auth.pin'):
    return receive(name, 200, [], json.dumps(body))

class LoginStateTests(unittest.TestCase):

    def test_pin_success_order_does_not_set_login_from_server_islogin(self):
        received = response(dict(responseCode='000', sessionInfo={}, isLogin=False, defaultLoginType='3'))
        result = replay('auth.pin', received)
        self.assertTrue(result.transport.app_success)
        self.assertTrue(result.state.is_login)
        self.assertEqual(result.state.values['currentLoginType'], 'PIN')
        self.assertEqual(result.state.values['defaultLoginType'], '1')
        self.assertEqual(result.events, ('session.update', 'timer.refresh', 'login_info.deserialize', 'login_info.refresh', 'callback.success', 'timer.start', 'pin_success.login_set'))

    def test_failed_response_can_update_session_and_metadata_but_not_login_flag(self):
        result = replay('auth.pin', response(dict(responseCode='999', sessionInfo={}, pushId='SYNTHETIC', isLogin=True)))
        self.assertFalse(result.transport.app_success)
        self.assertEqual(result.state.values['pushId'], 'SYNTHETIC')
        self.assertIsNotNone(result.state.values['sessionInfo'])
        self.assertFalse(result.state.is_login)
        self.assertEqual(result.state.timer_start_events, 0)

    def test_nonnull_guard_can_copy_null_from_different_field(self):
        state = LoginState()
        state.values['pinLoginYn'] = 'prior'
        result = replay('auth.pin', response(dict(responseCode='999', pinLoginYn='Y')), state)
        self.assertIsNone(result.state.values['pinLoginYn'])
        self.assertEqual(state.values['pinLoginYn'], 'prior')

    def test_device_flag_cross_copies_and_member_overwrites_default(self):
        body = dict(responseCode='999', deviceRegYn='N', certLoginYn='Y', pinLoginYn='Y', fidoLoginYn='Y', finCertLoginYn='Y', defaultLoginType='1', memberType='2')
        result = replay('auth.pin', response(body))
        for field in ('certLoginYn', 'pinLoginYn', 'fidoLoginYn', 'finCertLoginYn'):
            self.assertEqual(result.state.values[field], 'N')
        self.assertEqual(result.state.values['defaultLoginType'], '2')
        self.assertIsNone(result.state.values['memberType'])
        self.assertFalse(result.state.values['isPinLogin'])

    def test_null_metadata_retains_prior_values_empty_string_replaces(self):
        state = LoginState()
        state.values.update(pushId='old', paypinChangeDate='old')
        result = replay('auth.pin', response(dict(responseCode='999', pushId=None, paypinChangeDate='')), state)
        self.assertEqual(result.state.values['pushId'], 'old')
        self.assertEqual(result.state.values['paypinChangeDate'], '')

    def test_refresh_does_not_copy_datetime_fido_extra_or_saupno(self):
        state = LoginState()
        body = dict(responseCode='999', currentDateTime='not-copied', saupNo='not-copied', fidoCertFailCo='not-copied', fidoDelReqMsg='not-copied', currentLoginType='CERT')
        result = replay('auth.pin', response(body), state)
        for key in ('currentDateTime', 'saupNo', 'fidoCertFailCo', 'fidoDelReqMsg'):
            self.assertIsNone(result.state.values[key])
        self.assertEqual(result.state.values['currentLoginType'], 'PIN')

    def test_session_user_type_nine_refresh_member_is_zero_but_session_retained(self):
        result = replay('auth.pin', response(dict(responseCode='999', sessionInfo=dict(userType='9'))))
        self.assertEqual(result.state.values['memberType'], '0')
        self.assertEqual(result.state.values['sessionInfo']['userType'], '9')

    def test_disconnect_refreshes_before_logout_and_retains_key_metadata(self):
        state = LoginState(favorites_initialized=True)
        state.values.update(isLogin=True, sessionInfo={'userId': 'prior'}, sessionKey=b'SYNTHETIC', loginCertificateInfo='SYNTHETIC')
        result = replay('auth.pin', response(dict(responseCode='301', pushId='updated', sessionInfo=dict(userType='2', userId='new'))), state)
        self.assertEqual(result.callback, 'disconnected_session')
        self.assertFalse(result.state.is_login)
        self.assertIsNone(result.state.values['loginCertificateInfo'])
        self.assertEqual(result.state.values['sessionKey'], b'SYNTHETIC')
        self.assertEqual(result.state.values['pushId'], 'updated')
        self.assertEqual(result.state.favorite_context, ('2', 'new'))
        self.assertLess(result.events.index('login_info.refresh'), result.events.index('login.logout'))

    def test_no_listener_still_updates_session_and_timer_but_not_refresh_or_logout(self):
        state = LoginState()
        state.values.update(isLogin=True, sessionInfo={})
        result = replay('auth.pin', response(dict(responseCode='300', sessionInfo={}, pushId='not-copied')), state, listener_present=False)
        self.assertEqual(result.callback, 'none')
        self.assertTrue(result.state.is_login)
        self.assertIsNone(result.state.values['pushId'])
        self.assertEqual(result.events, ('session.update', 'timer.refresh'))

    def test_missing_session_on_success_is_ui_exception_not_transport_failure(self):
        result = replay('auth.pin', response(dict(responseCode='000')))
        self.assertTrue(result.transport.app_success)
        self.assertEqual(result.callback, 'success')
        self.assertEqual(result.ui_status, 'ui_exception')
        self.assertFalse(result.state.is_login)
        self.assertEqual(result.state.timer_start_events, 0)

    def test_secondary_model_failure_preserves_transport_success_and_worker_session(self):
        result = replay('auth.pin', response(dict(responseCode='000', sessionInfo={}, isLogin=[])))
        self.assertTrue(result.transport.app_success)
        self.assertEqual(result.ui_status, 'ui_exception')
        self.assertEqual(result.callback, 'none')
        self.assertIsNotNone(result.state.values['sessionInfo'])

    def test_null_parsed_query_differs_from_syntax_error_original_request(self):
        syntax = replay('auth.pin', receive('auth.pin', 200, [], '{'))
        literal_null = replay('auth.pin', receive('auth.pin', 200, [], 'null'))
        self.assertEqual(syntax.transport.code, '605')
        self.assertEqual(literal_null.transport.code, '605')
        self.assertEqual(syntax.callback, 'none')
        self.assertEqual(literal_null.callback, 'failure')

    def test_http_error_pin_secondary_refresh_null_exception(self):
        result = replay('auth.pin', receive('auth.pin', 503, [], 'not-consumed'))
        self.assertEqual(result.transport.code, '503')
        self.assertEqual(result.ui_status, 'ui_exception')
        self.assertEqual(result.callback, 'none')

    def test_body_io_vs_transport_io_differ_even_with_same_code(self):
        body = receive_bytes('auth.pin', 200, [('Content-Encoding', 'gzip')], b'bad')
        io = transport_failure('auth.pin')
        self.assertEqual((body.code, io.code), ('603', '603'))
        (body_replay, io_replay) = (replay('auth.pin', body), replay('auth.pin', io))
        self.assertEqual(body_replay.callback, 'none')
        self.assertEqual(io_replay.callback, 'failure')
        self.assertEqual(body_replay.state.timer_refresh_events, 1)
        self.assertEqual(io_replay.state.timer_refresh_events, 0)
        self.assertEqual(transport_failure('auth.pin', timeout=True).callback_code, '601')

    def test_original_request_error_info_wins_on_body_http_failure(self):
        original = {'errorInfo': {'errorCode': '', 'errorName': 'n', 'errorMessage': 'm'}}
        result = receive('national.list', 500, [], '', request_query=original)
        self.assertEqual(result.code, '500')
        self.assertEqual(result.callback_code, '')
        self.assertEqual(result.error_html, '<b>n</b><br/><br/>m')
        self.assertEqual(transport_failure('national.list', request_query=original).callback_code, '603')

    def test_datetime_callback_clears_null_only_on_success(self):
        state = LoginState()
        state.values['currentDateTime'] = 'old'
        for (code, expected) in (('000', None), ('999', 'old')):
            result = replay('auth.datetime', response(dict(responseCode=code), 'auth.datetime'), state)
            self.assertEqual(result.state.values['currentDateTime'], expected)

    def test_model_gaps_are_diagnostics_not_app_rejection(self):
        for (field, value) in (('sessionKey', [1]), ('loginCertificateInfo', {})):
            result = replay('auth.pin', response(dict(responseCode='000', sessionInfo={}, **{field: value})))
            self.assertTrue(result.transport.app_success)
            self.assertEqual(result.ui_status, 'unmodeled')
            self.assertFalse(result.state.is_login)
            self.assertIn('login_info_secondary_model_unmodeled', result.issues)

    def test_repr_redacts_private_state_and_response_text(self):
        state = LoginState()
        state.values['sessionKey'] = b'DO_NOT_DISPLAY'
        result = replay('auth.pin', response(dict(responseCode='999', pushId='DO_NOT_DISPLAY')), state)
        self.assertNotIn('DO_NOT_DISPLAY', repr(result))
        self.assertNotIn('DO_NOT_DISPLAY', repr(result.state))

class LoginMetadataParserTests(unittest.TestCase):

    def test_boolean_null_keeps_primitive_default_or_earlier_value(self):
        self.assertFalse(parse_login_info('{isLogin:null}')['isLogin'])
        self.assertTrue(parse_login_info('{isLogin:true,isLogin:null}')['isLogin'])
        self.assertFalse(parse_login_info('{isLogin:"yes"}')['isLogin'])
        self.assertTrue(parse_login_info('{isLogin:"TrUe"}')['isLogin'])

    def test_numbers_coerce_strings_but_not_boolean_or_enum_boolean(self):
        from giro.errors import GiroError
        self.assertEqual(parse_login_info('{pushId:1e2}')['pushId'], '1e2')
        for text in ('{isLogin:1}', '{currentLoginType:true}', '{pushId:[]}'):
            with self.assertRaises(GiroError):
                parse_login_info(text)
        self.assertIsNone(parse_login_info('{currentLoginType:123}')['currentLoginType'])

    def test_invalid_earlier_duplicate_is_not_masked(self):
        from giro.errors import GiroError
        with self.assertRaises(GiroError):
            parse_login_info('{pushId:[],pushId:"okay"}')

class DeviceStatusTests(unittest.TestCase):

    def run_status(self, body, state=None):
        return replay('auth.device-status', response(body, 'auth.device-status'), state)

    def test_exact_y_boolean_setters_also_update_strings(self):
        values = ('Y', 'y', None, True, '')
        body = dict(responseCode='000', **dict(zip((f[0] for f in DEVICE_FLAGS), values)))
        result = self.run_status(body)
        for ((field, boolean), value) in zip(DEVICE_FLAGS, values):
            self.assertEqual(result.state.values[boolean], value == 'Y')
            self.assertEqual(result.state.values[field], 'Y' if value == 'Y' else 'N')
        self.assertFalse(result.state.is_login)
        self.assertNotIn('login_info.deserialize', result.events)

    def test_missing_fields_reset_flags_on_success_not_failure(self):
        state = LoginState()
        for (field, boolean) in DEVICE_FLAGS:
            state.values.update({field: 'Y', boolean: True})
        for code in ('000', '999'):
            result = self.run_status(dict(responseCode=code), state)
            for (field, boolean) in DEVICE_FLAGS:
                self.assertEqual(result.state.values[boolean], code != '000')
                self.assertEqual(result.state.values[field], 'Y' if code != '000' else 'N')

    def test_saupno_only_member_one_even_null_and_no_membertype_copy(self):
        state = LoginState()
        state.values.update(saupNo='SYNTHETIC', memberType='retained')
        for member in ('1', '2', None, ''):
            result = self.run_status(dict(responseCode='000', memberType=member), state)
            self.assertEqual(result.state.values['saupNo'], None if member == '1' else 'SYNTHETIC')
            self.assertEqual(result.state.values['memberType'], 'retained')

    def test_default_type_is_raw_not_enum_fallback_and_current_type_untouched(self):
        state = LoginState()
        state.values['currentLoginType'] = 'CERT'
        for value in ('0', '1', '2', '3', 'unknown', '', None):
            result = self.run_status(dict(responseCode='000', defaultLoginType=value), state)
            self.assertEqual(result.state.values['defaultLoginType'], value)
            self.assertEqual(result.state.values['currentLoginType'], 'CERT')

    def test_favorites_initialized_using_worker_session_not_membertype(self):
        result = self.run_status(dict(responseCode='000', memberType='1', sessionInfo=dict(userType='2', userId='SYNTHETIC')))
        self.assertTrue(result.state.favorites_initialized)
        self.assertEqual(result.state.favorite_context, ('2', 'SYNTHETIC'))
        self.assertLess(result.events.index('session.update'), result.events.index('favorite.change_context'))
        self.assertEqual(self.run_status(dict(responseCode='000')).state.favorite_context, ('0', '0'))

    def test_pin_refresh_can_diverge_string_and_boolean_flags(self):
        device = self.run_status(dict(responseCode='000', pinLoginYn='Y'))
        pin = replay('auth.pin', response(dict(responseCode='000', sessionInfo={}, deviceRegYn='N', pinLoginYn='Y')), device.state)
        self.assertTrue(pin.state.is_login)
        self.assertTrue(pin.state.values['isPinLogin'])
        self.assertEqual(pin.state.values['pinLoginYn'], 'N')
ROOT = Path(__file__).resolve().parents[1]
