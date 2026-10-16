"""Complete verified enrollment through CMP, CA registration and bank preferences.

The caller supplies server-issued enrollment values after identity verification.
This internal workflow is not an alternative to that preceding verification.
"""
import hashlib
import hmac
import json
import uuid

from finance_cli.credentials.registry import encode, decode
from finance_cli.credentials.shinhan import Registry
from . import cmp

# Eight-byte protocol version returned by the supported certificate engine.
MSB_VERSION = 'b67f8f18a018118d'


def registration_request(enrollment, credential, unique, device):
    values = {'RA_CERT_DCD': '001', 'RQST_CHNL_DCD': 'SOL',
              'REFERENCE_VALUE': enrollment['referenceNumber'], 'SECRET_VALUE': enrollment['authCode'],
              'CERT_SEQ_NO': credential['alias'], 'MSB_VRSN_VL': credential['msb_version'],
              'CUST_ID': enrollment['customerNumber'], 'CUST_NM': enrollment['customerName'],
              'CUST_CCTN_MCTL_ID': device['device_id'], 'CUST_CCTN_MCTL_OPSS_DCD': 'A',
              'CUST_CCTN_MCTL_OPSS_VRSN_VL': device['os_version'], 'PIN_DATA_CON': unique,
              'PTN_DATA_CON': '', 'BIO_ELSG_CON': '', 'BIO_CRTC_DCD': '00'}
    if not all(isinstance(v, str) for v in values.values()):
        raise ValueError('invalid_registration_input')
    if not values['SECRET_VALUE']:
        raise ValueError('registration_secret_missing')
    message = ''.join(values[key] for key in ('REFERENCE_VALUE', 'SECRET_VALUE', 'CERT_SEQ_NO',
                      'RA_CERT_DCD', 'RQST_CHNL_DCD', 'MSB_VRSN_VL', 'CUST_ID', 'CUST_CCTN_MCTL_ID',
                      'CUST_CCTN_MCTL_OPSS_DCD', 'CUST_CCTN_MCTL_OPSS_VRSN_VL', 'PIN_DATA_CON', 'BIO_CRTC_DCD'))
    values['PARAMMAC'] = hmac.new(values['SECRET_VALUE'].encode(), message.encode(), hashlib.sha256).hexdigest()
    return values


def registration_result(document):
    if (not isinstance(document, dict) or not isinstance(document.get('ERR_CD'), str)
            or not isinstance(document.get('ERR_MSG'), (str, int, float, bool))
            or document.get('data') is not None and not isinstance(document['data'], dict)):
        return 'unknown', None
    if document['ERR_CD'] != 'RA0000':
        return 'failure', None
    data = document.get('data') or {}
    return 'success', {'number': data.get('CERT_SEQ_NO') or '', 'date': data.get('ISNC_TS') or ''}


def complete(exchange, enrollment, password, unique, salt, *, registry=None):
    """Consume verified bridge inputs once; preserve every observed remote result."""
    registry = registry or Registry()
    report, state = exchange.report, exchange.state
    report.update(certificate_issuance='unknown', certificate_registration='unknown', cmp_confirm='unknown')
    reference = 'shinhan-'+uuid.uuid4().hex
    registered = False
    try:
        state['disabled_credentials'] = [row['name'] for row in registry.list()]
        state['authenticated'] = False
        report['previous_connections_disabled'] = True
        exchange.save()
        if not unique or not enrollment['referenceNumber'] or not enrollment['authCode']:
            raise ValueError('issuance_input_unavailable')
        credential = registry.prepare(reference, password, unique, salt, exchange.settings['device']['device_id'])
        report.update(credential=reference, local_key_generation='complete')
        context = cmp.Context(enrollment['referenceNumber'].encode(), enrollment['authCode'].encode())
        step, raw = exchange.cmp('cmp_genm', '/v1.0/prsn-cert/issue/genm', context.genm())
        if step['result'] != 'http_success':
            return stop(exchange, reference, 'cmp_genm_unavailable')
        context.genp(cmp.unwire(raw))
        step.update(result='success', processing_status='complete', protection_verified=context.protection_verified)
        request = context.ir(decode(credential['private_key']), decode(credential['vid_random']), enrollment['customerNumber'].encode())
        step, raw = exchange.cmp('cmp_ir', '/v1.0/prsn-cert/issue/ir', request)
        if step['result'] != 'http_success':
            return stop(exchange, reference, 'cmp_ir_unavailable')
        certificate, alias = context.ip(cmp.unwire(raw))
        report['certificate_issuance'] = 'success'
        step.update(result='success', processing_status='complete', protection_verified=context.protection_verified)
        credential.update(certificate=encode(certificate), alias=alias, state='certificate_received')
        registry.save(reference, password, credential)
        report['certificate_saved'] = True
        step, raw = exchange.cmp('cmp_confirm', '/v1.0/prsn-cert/issue/confirm', context.confirm())
        if step['result'] != 'http_success':
            return stop(exchange, reference, 'cmp_confirm_unavailable')
        # Confirmation consumes the encoding only; it does not parse CMP contents.
        cmp.unwire(raw)
        report['cmp_confirm'] = 'success'
        step.update(result='success', processing_status='complete')
        credential.update(state='confirmed', msb_version=MSB_VERSION)
        registry.save(reference, password, credential)
        request = registration_request(enrollment, credential, unique, exchange.settings['device'])
        step, raw = exchange.ca('certificate_registration', '/v1.1/prsn-cert/issue/regist-cert', request)
        # HTTP success resets local authentication choices before business result consumption.
        if step.get('http_status') is not None and 200 <= step['http_status'] < 300:
            state.update(authentication_method='pin', pattern_enabled=False, biometric_enabled=False)
        if step['result'] != 'http_success':
            return stop(exchange, reference, 'registration_unavailable')
        result, info = registration_result(json.loads(raw))
        report['certificate_registration'] = result
        step.update(result=result, processing_status='complete' if result != 'unknown' else 'incomplete')
        if result != 'success':
            return stop(exchange, reference, 'registration_not_accepted')
        registered = True
        credential.update(state='issued', registration=info)
        try:
            registry.save(reference, password, credential)
            report['credential_saved'] = True
        except Exception:
            report['credential_saved'] = False
            exchange.warning('credential_save_error')
        state['credential'] = reference
        post_registration(exchange)
        report['processing_status'] = 'complete'
        exchange.save()
        return report
    except cmp.ProtocolError as error:
        if error.issuance == 'failure':
            report['certificate_issuance'] = 'failure'
        if report['stages']:
            report['stages'][-1].update(processing_status='incomplete', error=error.code)
        return stop(exchange, None if registered else reference, error.code)
    except (KeyboardInterrupt, EOFError):
        return stop(exchange, None if registered else reference, 'interrupted')
    except Exception:
        return stop(exchange, None if registered else reference, 'local_issuance_processing_error')


def post_registration(exchange):
    state, report = exchange.state, exchange.report
    step, document = exchange.bank('login_method_registration', 'RSMCM0203A04',
                                  {'loginGS1': 'G', 'lstLoginMdiaUpdYnS1': '', 'trxObjCS2': '', 'smasSnsJoinS1': None})
    accepted = step['result'] == 'success' and document.get('dataBody') is not None
    report['login_method_registration'] = step['result']
    report['simple_transfer_registration'] = 'skipped'
    if accepted:
        step, document = exchange.bank('simple_transfer_registration', 'RSMDE0219A02',
                                      {'trxGS1': '1', 'appIdS100': 'SBANK', 'pkeyS1000': 'X',
                                       'idS64': state.get('simple_transfer_id', '')})
        report['simple_transfer_registration'] = step['result']
        if step['result'] == 'success' and isinstance(document.get('dataBody'), dict):
            body = document['dataBody']
            identity = body.get('idS64', '')
            if isinstance(identity, str):
                state['simple_transfer_id'] = identity
            else:
                step.update(processing_status='incomplete', error='simple_transfer_id_decode_error')
    # Returned business errors do not cancel issuance completion.
    state['next_login_shinhan_certificate'] = True


def stop(exchange, disabled_reference, error):
    if disabled_reference:
        disabled = exchange.state.setdefault('disabled_credentials', [])
        if disabled_reference not in disabled:
            disabled.append(disabled_reference)
    exchange.report.update(processing_status='incomplete', error=error)
    exchange.save()
    return exchange.report
