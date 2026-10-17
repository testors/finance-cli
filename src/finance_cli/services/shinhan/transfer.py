"""User-prepared, single-use native immediate transfers on an existing session."""
from datetime import datetime
import hashlib
import hmac

from finance_cli.core import storage
from finance_cli.credentials.registry import decode
from finance_cli.credentials.shinhan import Registry
from . import additional_auth, balance_protocol, crypto, keypad, login, security_media, setup, transport
from . import transfer_balance, transfer_protocol as protocol, transfer_selection as selection
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired


def request(exchange, stage, transaction, body, parser=transport.parse):
    step, document = exchange.bank(stage, transaction, body, path=protocol.ENDPOINT, response_parser=parser)
    if step['result'] != 'success':
        raise Pending(step.get('entry_error') or stage+'_unavailable')
    if step.get('processing_status') != 'complete':
        raise Pending(stage+'_body_unavailable')
    return document.get('dataBody') if document is not None else None


def save_data(exchange, name, value):
    try:
        path = exchange.run/name
        storage.atomic_json(path, value)
        exchange.report['data_file'] = str(path)
    except Exception:
        exchange.warning('transfer_data_save_error')


def withdrawal_list(exchange):
    body = request(exchange, 'transfer_withdrawals', selection.WITHDRAWAL_TRANSACTION, {}, selection.parse_withdrawal)
    rows = selection.withdrawals(body)
    exchange.report['withdrawal_count'] = len(rows)
    save_data(exchange, 'transfer-accounts.json', {'accounts': rows})
    return rows


def prepare(exchange, bank, account, amount, source, memos):
    # A new prepare explicitly replaces the previous pending inquiry. It never
    # reuses earlier A12 serials, auth results, or a generic account-list row.
    exchange.state.pop('transfer_pending', None)
    exchange.save()
    body = request(exchange, 'transfer_entry', selection.CHECK_TRANSACTION,
                   selection.check_request(source or ''), selection.parse_check)
    entry = selection.initial_model(selection.initial(body))
    if entry['bridgeType'] == 'BackUp':
        exchange.report['entry_program'] = selection.bridge_program(entry)
        raise Pending('transfer_backup_route_required')
    withdrawal = entry['withdrawalAccount']
    if source is not None or not withdrawal['accountNumber']:
        rows = withdrawal_list(exchange)
        if source is None and len(rows) == 1:
            selected = rows[0]
        else:
            selected = next((r for r in rows if protocol.digits(r['accountNumber']) == source), None)
        if selected is None:
            raise Pending('withdrawal_account_selection_required')
        withdrawal = selection.withdrawal_model(selected)
    if not withdrawal['isShinhan']:
        raise Pending('openbanking_withdrawal_not_implemented')
    if withdrawal['isLimitAccount']:
        step, document = exchange.bank('transfer_account_limit', transfer_balance.LIMIT_TRANSACTION,
            transfer_balance.limit_request(withdrawal['accountNumber']), path=protocol.ENDPOINT,
            response_parser=transfer_balance.parse_limit)
        limit = document['dataBody'] if document is not None else None
        withdrawal = transfer_balance.apply_limit(withdrawal,
            transfer_balance.limit_amount(limit) if step['result'] == 'success' and limit is not None else None)
    step, document = exchange.bank('transfer_balance', balance_protocol.TRANSACTION,
        transfer_balance.balance_request(withdrawal), path=balance_protocol.ENDPOINT, response_parser=balance_protocol.parse)
    balance = document['dataBody'] if document is not None else None
    if step['result'] == 'success' and balance is not None:
        withdrawal, balance_status = transfer_balance.initial_balance(withdrawal, balance_protocol.entity(balance))
        exchange.report['balance_status'] = balance_status
    else:
        exchange.report['balance_status'] = 'unavailable'
    owner = request(exchange, 'transfer_owner', 'RSMDE0200A10', protocol.owner_request(withdrawal, bank, account),
                    protocol.parser(protocol.OWNER, 'transfer_owner'))
    if balance_protocol.blank(owner['ipAcSungNmS20']):
        raise Pending('receiver_name_unavailable')
    if (owner['ipAcNoS16'] == owner['jiAcnoS16'] and withdrawal['bankCode'] == bank):
        raise Pending('sender_receiver_same_account')
    inquiry = protocol.inquiry_request(withdrawal, bank, account, amount, owner['ipAcSungNmS20'], exchange.settings, **memos)
    body = request(exchange, 'transfer_inquiry', 'RSMDE1402A12', inquiry,
                   protocol.parser(protocol.INQUIRY, 'transfer_inquiry'))
    auth = protocol.authentication(body)
    preview = {'withdrawal': withdrawal, 'requested': {'bank': bank, 'account': account, 'amount': amount},
               'receiver_name': body['ipAcSungNmS20'], 'receiver_bank': body['ipbnkCS3_display'],
               'receiver_account': body['ipAcNoS16'], 'amount': selection.narrow(body['icheamtN15_originalValue']),
               'fee': body['aplFeamtN18'], 'authentication': auth,
               'notices': [body['btmShtMsg1S100'], body['btmShtMsg2S100']],
               'fraud_questions': body['fincSagiQstnMsg']}
    context = {'attempt': exchange.attempt, 'status': 'prepared', 'withdrawal': withdrawal, 'inquiry': body,
               'memos': memos, 'preview': preview, 'credential': exchange.state.get('credential')}
    # Persist the binding before advertising it as executable. Save errors are
    # local, and never change the already observed A12 result to bank failure.
    exchange.state['transfer_pending'] = context
    storage.atomic_json(exchange.folder/'session.json', exchange.state)
    save_data(exchange, 'transfer-preview.json', preview)
    exchange.report.update(bank_result='success', processing_status='complete', prepared=True,
                           transfer_result='not_sent', authentication_required=auth)


def pisp(exchange, context, input_provider):
    reference = login.select(context.get('credential'))
    if reference in exchange.state.get('disabled_credentials', []):
        raise Pending('certificate_reissue_required')
    credential = Registry().load(reference, input_provider('storage_password', {}))
    if credential.get('state') != 'issued' or credential.get('device_id') != exchange.settings['device']['device_id']:
        raise Pending('issued_certificate_required')
    unique = login.authenticate_pin(exchange, credential, lambda: input_provider('pin', {}))
    plaintext = 'login'+datetime.now().strftime('%y%m%d%H%M%S')
    nonce_body = request(exchange, 'transfer_nonce', 'RSMCM0800C12', {})
    nonce = nonce_body.get('randomUid') or '' if isinstance(nonce_body, dict) else ''
    if not credential['alias'] or not unique:
        raise Pending('local_signing_input_unavailable')
    if not hmac.compare_digest(hashlib.sha256(unique.encode()).hexdigest(), credential['access_key_digest']):
        raise Pending('local_key_access_rejected')
    signature = crypto.sign(decode(credential['certificate']), decode(credential['private_key']),
                            plaintext.encode(), nonce.encode()).hex()
    body = request(exchange, 'transfer_pisp', 'RSMDE0907A08',
        protocol.pisp_request(credential, exchange.settings['device'], unique, plaintext, signature),
        protocol.parser(protocol.PISP, 'transfer_pisp'))
    if not body['authNoS64']:
        raise Pending('pisp_authentication_incomplete')
    exchange.report['pisp_authentication'] = 'success'
    # The native result callback consumes authNoS64; it is NOT A04.reqKey.


def execute(exchange, input_provider):
    context = exchange.state.get('transfer_pending')
    if not context:
        raise Pending('transfer_prepare_required')
    if context['status'] != 'prepared':
        raise Pending('transfer_attempt_already_used')
    exchange.report['prepare_attempt'] = context['attempt']
    body, withdrawal = context['inquiry'], context['withdrawal']
    auth = protocol.authentication(body)
    if auth['fraud_questionnaire']:
        raise Pending('transfer_fraud_questionnaire_required')
    if auth['security_media'] and auth['security_media_kind'] != 'OTP':
        raise Pending('transfer_security_media_route_not_implemented')
    if auth['login'] and exchange.state.get('last_login_type') != 'G':
        raise Pending('transfer_login_auth_route_not_implemented')
    if input_provider is None:
        raise Pending('transfer_input_provider_required')
    # A separate exclusive file also prevents replay if a later session write
    # fails or an older session.json is restored. Reserve before the first auth.
    claim = exchange.folder/'runs'/context['attempt']/'transfer-used.json'
    try:
        storage.write_new(claim, b'{"used":true}\n')
    except FileExistsError:
        raise Pending('transfer_attempt_already_used') from None
    context['status'] = 'used'
    storage.atomic_json(exchange.folder/'session.json', exchange.state)
    channel = keypad.Channel(exchange)
    if auth['account_password']:
        encrypted = channel.read(lambda: input_provider('account_password', {}), 4)
        request(exchange, 'transfer_account_password', 'RSMDE1402C01', protocol.password_request(body, withdrawal, encrypted))
        exchange.report['account_password_verification'] = 'success'
    if auth['login']:
        pisp(exchange, context, input_provider)
    if auth['security_media']:
        encrypted = channel.read(lambda: input_provider('otp', {}), 6)
        security_media.verify_otp(exchange, encrypted, service='RSMCM1100A04', next_service='')
    # The screen keeps the requested amount; A12 numbers are shown separately.
    additional = request(exchange, 'transfer_additional_auth_check', 'RSMDE1402A06',
        protocol.additional_request(context['preview']['requested']['amount']),
        protocol.parser(protocol.ADDITIONAL, 'transfer_additional_auth'))
    required, params = protocol.additional_parameters(additional, context['preview']['receiver_bank'])
    exchange.report['additional_auth_required'] = required
    if required:
        result = additional_auth.authenticate(exchange, params,
            lambda options: input_provider('additional_select', options),
            lambda method, remaining: input_provider('additional_response', {'method': method, 'remaining': remaining}),
            login_info=exchange.state.get('login'))
        if result.get('인증여부') != 'Y':
            raise Pending('transfer_additional_auth_incomplete')
    # Exchange reserves this stage durably before post(); a timeout is never
    # retried. A04 has no account/amount: its A12 binding is retained unchanged.
    exchange.report['transfer_result'] = 'unknown'
    context['result'] = 'unknown'
    step, document = exchange.bank('transfer_execute', 'RSMDE1402A04',
        protocol.execute_request(body, **context['memos']), path=protocol.ENDPOINT, response_parser=protocol.parse_receipt)
    verdict = step['bank_result']
    exchange.report.update(bank_result=verdict, transfer_result=verdict)
    context.update(status='complete', result=verdict, execute_attempt=exchange.attempt)
    if verdict == 'success':
        exchange.report['processing_status'] = step['processing_status']
        exchange.report['receipt_available'] = document is not None and document.get('dataBody') is not None
        if not exchange.report['receipt_available']:
            exchange.report['required_action'] = 'transfer_receipt_unavailable'
        save_data(exchange, 'transfer-result.json', {'preview': context['preview'], 'response': document})
    elif verdict == 'failure' and not balance_protocol.blank(step.get('bank_code') or ''):
        raise Pending('transfer_rejected')
    else:
        exchange.report['transfer_result'] = 'unknown'
        context['result'] = 'unknown'
        raise Pending('transfer_outcome_requires_history_check')


def run(action, *, bank=None, account=None, amount=None, source=None,
        withdrawal_memo='', receiver_memo='', input_provider=None):
    if action == 'prepare':
        bank = protocol.bank_code(bank)
        if not isinstance(account, str) or not protocol.digits(account):
            raise ValueError('receiver_account_required')
        account = protocol.digits(account)
        source = protocol.digits(source) if source is not None else None
        if type(amount) is not int or not 0 < amount < 2**63:
            raise ValueError('positive_amount_required')
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if action == 'show':
            context = state.get('transfer_pending')
            if not context:
                raise Pending('transfer_prepare_required')
            return {'operation': 'transfer_show', 'network_used': False, 'status': context['status'],
                    'preview': context['preview'], 'transfer_result': context.get('result', 'not_sent')}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(setup.load(), state, 'transfer_'+action)
        exchange.report['transfer_result'] = 'not_sent'
        try:
            if action == 'accounts':
                withdrawal_list(exchange)
                exchange.report.update(bank_result='success', processing_status='complete')
            elif action == 'prepare':
                prepare(exchange, bank, account, amount, source,
                        {'withdrawal_memo': withdrawal_memo, 'receiver_memo': receiver_memo})
            elif action == 'execute':
                execute(exchange, input_provider)
            else:
                raise ValueError('unknown_transfer_action')
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='transfer_processing_error')
        if exchange.report['transfer_result'] == 'unknown':
            exchange.report['required_action'] = 'transfer_outcome_requires_history_check'
        # Preserve each preparatory success without mislabelling it a payment.
        if exchange.report['transfer_result'] == 'not_sent' and exchange.report['stages']:
            exchange.report['bank_result'] = exchange.report['stages'][-1].get('bank_result', 'unknown')
        exchange.save()
        return exchange.report
