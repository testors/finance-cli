"""Server-selected account password, OTP, ARS and shared certificate signing."""
import base64
import re

from Crypto.PublicKey import RSA
from cryptography import x509
from finance_cli.credentials.registry import Registry
from finance_cli.credentials.joint import cms
from finance_cli.services.hana.nfilter_crypto import encrypt_numeric_password
from . import keypad, operations as op, protocol, transfer_protocol as wire


def required_input(inputs, name, *args):
    provider = inputs.get(name)
    protocol.require(callable(provider), name + '_input_required')
    return provider(*args)


def numeric(auth, inputs, name, length, settings):
    _, mac = keypad.resolve(settings)
    public = auth.get('NSHC_PUBLIC_KEY')
    protocol.require(isinstance(public, str) and public, 'keypad_public_key_unavailable')
    value = required_input(inputs, name)
    protocol.require(isinstance(value, str) and re.fullmatch('[0-9]{' + str(length) + '}', value) is not None,
                     'invalid_' + name)
    return encrypt_numeric_password(public, value, mac)


def authorize(client, confirmation, step, *, inputs, credential=None, phone=None, ars_completed=False):
    fields = wire.signed_fields(confirmation)
    params = {'ACCT_NO': confirmation.get('acctNo'), 'elementId': 'ACCT_PW', 'autoCloseYn': 'Y',
              'SIGNED_JSON': [{**field, 'val': field.get('val')} for field in fields]}
    auth = step('unified-auth', params)
    protocol.require(auth.get('UNUSABLE_OTP_VNDR_TRN') != 'Y', 'otp_unusable')
    login_type = wire.text_value(auth.get('LOGINED_TYPE_CD'))
    cert_type = '1' if login_type in ('0', '1', 'C', 'D') else login_type
    params['CERT_TYPE'] = cert_type
    password_needed = auth.get('PW_VRFC_YN') == 'Y' and auth.get('PW_VRFC_CPLT_YN') != 'Y'
    if password_needed:
        def password_body():
            encrypted = numeric(auth, inputs, 'account_password', 4, client.saved.get('settings'))
            return {**params, 'encAcctPwText': encrypted, 'ACCT_PW': encrypted, 'nfilterFields': 'ACCT_PW=num'}
        checked = step('account-password', password_body, redact=('encAcctPwText', 'ACCT_PW'))
        protocol.require(checked.get('PW_VRFC_CPLT_YN') == 'Y', 'account_password_not_verified')
    if password_needed or auth.get('SCRT_MDCL_VRFC_YN') == 'Y':
        fds = auth.get('RESULT_FDS_INQ')
        protocol.require(fds != 'ENTP', 'transfer_stopped_by_bank')
        protocol.require(fds != 'ITBL', 'transfer_not_eligible_for_delay')
        if fds == 'EATP':
            def ars_body():
                listing = step('ars-phones', {})
                rows = (listing.get('ARS_OUTPUT_MSG') or {}).get('BIZ.CUM0118.OUT.REC')
                protocol.require(isinstance(rows, list) and rows, 'ars_phone_unavailable')
                chosen = next((r for r in rows if str(r.get('SEQ_NO')) == str(phone)), None) if phone is not None else rows[0]
                protocol.require(chosen is not None, 'ars_phone_not_found')
                return {**op.pick(chosen, ('SEQ_NO', 'CERT_RQST_TEL_NO', 'CERT_RQST_TEL_NO_TYP_CD')),
                        'ARS_CERT_TRSC_DV_CD': '023'}
            requested = step('ars-request', ars_body, redact=('CERT_RQST_TEL_NO',))
            protocol.require(requested.get('ARS_APV_NO_RESULT') == 'SUCCESS', 'ars_request_not_confirmed')
            # No polling and no repeated telephone request. A subsequent explicit
            # execution may check again using the already requested transaction.
            if not ars_completed:
                protocol.require(required_input(inputs, 'ars_completed', requested.get('ARS_APV_NO')) is True,
                                 'ars_authentication_pending')
            checked = step('ars-check', {'ARS_APC_NO_REQ_YN': 'Y', 'RSEV_TRSC_YN': 'N'}, repeatable=True)
            protocol.require(checked.get('ARS_APV_NO_RESULT') == 'SUCCESS', 'ars_authentication_pending')
        if auth.get('SCRT_MDCL_VRFC_YN') == 'Y':
            protocol.require(auth.get('MOTP_USR_YN') != 'Y', 'mobile_otp_required_not_supported')
            def otp_body():
                encrypted = numeric(auth, inputs, 'otp', 6, client.saved.get('settings'))
                return {'OTP_RSPS_CD': encrypted, '_OTP_SECURITY_CERT_PWD_': encrypted,
                        'nfilterFields': 'OTP_RSPS_CD=num', 'CNFM_TRSC_YN': 'N'}
            checked = step('otp', otp_body, redact=('OTP_RSPS_CD', '_OTP_SECURITY_CERT_PWD_'))
            protocol.require(checked.get('ERROR_CODE') not in ('BCOM16812', 'BCOM18818'), 'otp_correction_required')
            protocol.require(checked.get('OTP_VALID_YN') == 'Y', 'otp_not_verified')
    if auth.get('SEND_CERT_SBMT_YN') != 'Y':
        simple_sign = password_needed or auth.get('SCRT_MDCL_VRFC_YN') == 'Y' or auth.get('SEF_ACCT_YN') == 'Y' or auth.get('PW_VRFC_CPLT_YN') == 'Y'
        protocol.require(not simple_sign or cert_type not in ('J', '8', 'G', 'K', 'L'), 'private_certificate_signing_not_supported')
        return {}
    protocol.require(cert_type in ('1', 'S', '2'), 'certificate_type_not_supported')
    registry = Registry()
    if credential is None:
        reference = client.saved.get('credential') or {}
        if reference.get('type') == 'joint':
            credential = reference.get('ref')
        else:
            entries = registry.list()
            protocol.require(len(entries) == 1, 'shared_certificate_selection_required')
            credential = entries[0]['name']
    certificate, private, _ = registry.material(credential, required_input(inputs, 'password'))
    serials = auth.get('CERT_SERIALS')
    if serials:
        protocol.require(isinstance(serials, list), 'certificate_filter_unavailable')
        serial = x509.load_der_x509_certificate(certificate).serial_number
        protocol.require(serial in [int(str(value), 10) for value in serials], 'certificate_not_in_bank_selection')
    key = RSA.import_key(private)
    cms.require_matching_key(certificate, key)
    random = cms.extract_vid_random(private)
    del private
    moment = client.request('server-time')
    signature = cms.sign_cms(certificate, key, wire.signing_bytes(fields, moment))
    head = {'LGIN_CERT_METH_CD': cert_type, 'SIGNED_MSG': base64.b64encode(signature).decode()}
    if random is not None:
        head['VID_MSG'] = base64.b64encode(random).decode()
    return head
