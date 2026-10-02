"""Reviewable server preparations and one final submission per transfer."""
import re
import uuid

from finance_cli.core import storage
from finance_cli.services.hana.onesign_io import send_http
from . import operations as op, protocol, queries, store, transfer_auth, transfer_protocol as wire


def pending(client):
    path = client.state_directory / 'pending-transfer.json'
    protocol.require(path.exists(), 'prepared_transfer_required')
    value = storage.read_json(path)
    directory = storage.no_symlinks(client.state_directory / 'transfers' / store.name(value['transfer']))
    protocol.require(directory.is_dir(), 'prepared_transfer_unavailable')
    return value, directory


def prepare(account, bank, recipient, amount, *, memo='', sender_text=None, recipient_text=None,
            cms_code='', delayed=False, session=None, send=False, exchange=send_http):
    output = op.result('transfer-prepare', send)
    output['transfer_sent'] = False
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        account, recipient = queries.account_number(account), queries.account_number(recipient)
        protocol.require(re.fullmatch('[0-9]{3}', bank or '') is not None and bank not in ('996', '997', '998', '999'),
                         'ordinary_transfer_bank_required')
        protocol.require(re.fullmatch('[0-9]+', str(amount)) is not None and int(amount) > 0, 'invalid_transfer_amount')
        amount = str(int(amount))
        previous = client.state_directory / 'pending-transfer.json'
        if previous.exists():
            old, old_directory = pending(client)
            protocol.require((old_directory / 'finished.json').exists(), 'pending_transfer_exists_use_execute_result_or_cancel')
        directory = storage.directory(client.state_directory / 'transfers') / uuid.uuid4().hex
        directory.mkdir(mode=0o700)
        output['transfer'] = directory.name
        storage.atomic_json(previous, {'transfer': directory.name})
        initial = client.request('transfer-init', {'ACCT_NO': account})
        delayed = delayed or initial.get('dlayTrnsYn') in (True, 1, '1')
        rows = initial.get('acctList')
        protocol.require(isinstance(rows, list), 'withdrawal_accounts_unavailable')
        protocol.require(rows, 'no_withdrawal_accounts')
        selected = next((r for r in rows if r.get('accountNo') == account), None)
        protocol.require(selected is not None, 'withdrawal_account_not_available')
        if len(rows) == 1:
            detail = initial
            balance = initial.get('paymPossAmt')
        else:
            detail = client.request('transfer-withdrawal', {'ACCT_NO': account})
            balance = detail.get('paymPossBal')
        named = client.request('transfer-recipient', {'REC_NCNT': 1, 'RCV_BNK_CD': bank, 'RCV_ACCT_NO': recipient, 'TRNS_AMT': 0})
        recipient_name = '' if named.get('resResult') == 'JSON_NO_DATA' else named.get('resResult', '')
        client.request('transfer-amount', {'inqCd': '01', 'paymPossAmt': balance, 'ACCT_NO': account, 'trnsAmt': amount, 'rcvBnkCd': bank})
        body = {'ADD_TRNS_CALL_YN': 'Y', 'ACCT_NO': account, 'RCV_BNK_CD': bank, 'RCV_ACCT_NO': recipient,
                'TRNS_AMT': int(amount), 'CMSV_NO': cms_code, 'RCV_PSBK_MARK_CTT': detail.get('owacNm', '') if sender_text is None else sender_text,
                'WDRW_PSBK_MARK_CTT': recipient_name if recipient_text is None else recipient_text,
                'MEMO': memo, 'ACCT_NM': selected.get('alias') or selected.get('prdNm') or selected.get('title') or '',
                'DLAY_TRNS_YN': 'Y' if delayed else 'N', 'RMTE_NM': recipient_name, 'OWAC_NM': detail.get('custNm', '')}
        wire.check_notes(body, output)
        if bank != '081':
            clock = op.current_time(client)
            if 0 <= int(clock['time'][:4]) <= 15:
                op.warning(output, 'other_bank_transfer_time_notice')
        if delayed:
            day = client.request('server-time', attempt_name='delayed-business-date')
            possible = False
            if day.get('bizDayCheck') == 'Y':
                clock = op.current_time(client, attempt_name='delayed-business-time')
                possible = 800 <= int(clock['time'][:4]) < 1600
            if not possible:
                op.warning(output, 'delayed_transfer_time_notice_check_result')
        try:
            store.record(directory / 'requested.json', body)
        except (OSError, ValueError):
            op.warning(output, 'transfer_request_log_storage_failed')
        client.request('transfer-prepare', body)
        confirmation = client.request('transfer-confirm', observe=op.observe(output))
        output.update(preview=wire.preview(confirmation), transfer_status='prepared', next='fin hana corporate transfer execute --send')
        store.record(directory / 'confirmation.json', confirmation)
    return output


def stepper(client, directory):
    def step(stage, body=None, *, redact=(), repeatable=False, observe=None):
        cached = directory / (stage + '-received.json')
        if cached.exists() and not repeatable:
            saved = storage.read_json(cached)
            if observe:
                observe(saved['receipt'], saved['data'])
            protocol.require(saved['receipt']['service_status'] == 'accepted', saved['receipt']['reason'])
            return saved['data']
        reserved = directory / (stage + '-attempt.json')
        protocol.require(repeatable or not reserved.exists(), 'previous_' + stage.replace('-', '_') + '_attempt_unconfirmed')
        # Collect input before reserving its single submission. Cached validation
        # results never request the same password or OTP again.
        value = body() if callable(body) else body
        if not repeatable:
            store.record(reserved, {'automatic_retry': False})
        captured = None
        def received(receipt, data):
            nonlocal captured
            captured = {'receipt': dict(receipt), 'data': data}
            if observe:
                observe(receipt, data)
        try:
            return client.request(stage, value, redact=redact, observe=received)
        finally:
            if captured is not None and not repeatable:
                try:
                    store.record(cached, captured)
                except (OSError, ValueError):
                    op.warning(client.result, 'transfer_step_storage_failed')
    return step


def read_result(client, directory, output):
    response = client.request('transfer-result')
    completed = wire.completion(response)
    for code in completed.pop('warnings', []):
        op.warning(output, code)
    output.update(completed)
    try:
        if not (directory / 'finished.json').exists():
            store.record(directory / 'finished.json', {'result_received': True})
    except (OSError, ValueError):
        op.warning(output, 'transfer_result_storage_failed')


def execute(*, session=None, send=False, inputs=None, credential=None, allow_duplicate=False,
            phone=None, ars_completed=False, exchange=send_http):
    output = op.result('transfer-execute', send)
    output.update(transfer_sent=False, transfer_status='unconfirmed')
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        saved, directory = pending(client)
        output['transfer'] = saved['transfer']
        protocol.require(not (directory / 'transfer-execute-attempt.json').exists(), 'transfer_already_attempted_use_result')
        protocol.require(not (directory / 'finished.json').exists(), 'transfer_already_finished')
        confirmation = storage.read_json(directory / 'confirmation.json')
        output['preview'] = wire.preview(confirmation)
        rows = confirmation.get('cts0004InRec') or []
        protocol.require(allow_duplicate or not any(r.get('DUP_YN') == 'Y' for r in rows), 'duplicate_transfer_confirmation_required')
        step = stepper(client, directory)
        head = transfer_auth.authorize(client, confirmation, step, inputs=inputs or {}, credential=credential,
                                       phone=phone, ars_completed=ars_completed)
        def submitted(receipt, data):
            op.observe(output)(receipt, data)
            if receipt['service_status'] == 'accepted':
                output['transfer_status'] = 'submitted'
            elif receipt['service_status'] == 'rejected':
                output['transfer_status'] = 'rejected'
        try:
            step('transfer-execute', {'COMM_HEAD': head}, redact=('SIGNED_MSG', 'VID_MSG'), observe=submitted)
        finally:
            output['transfer_sent'] = any(r['stage'] == 'transfer-execute' and r['processing_status'] != 'prepared' for r in output['stages'])
        read_result(client, directory, output)
    return output


def result(*, session=None, send=False, exchange=send_http):
    output = op.result('transfer-result', send)
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        saved, directory = pending(client)
        output['transfer'] = saved['transfer']
        protocol.require((directory / 'transfer-execute-attempt.json').exists(), 'transfer_not_submitted')
        receipt = directory / 'transfer-execute-received.json'
        if receipt.exists():
            observed = storage.read_json(receipt)
            op.observe(output)(observed['receipt'], observed['data'])
        read_result(client, directory, output)
    return output


def cancel(*, session=None, send=False, exchange=send_http):
    output = op.result('transfer-cancel', send)
    if not send:
        return output
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        saved, directory = pending(client)
        output['transfer'] = saved['transfer']
        protocol.require(not (directory / 'transfer-execute-attempt.json').exists(), 'submitted_transfer_cannot_be_cancelled_here')
        protocol.require(not (directory / 'finished.json').exists(), 'transfer_already_finished')
        client.request('transfer-clear', observe=op.observe(output))
        output['transfer_status'] = 'preparation_cancelled'
        try:
            store.record(directory / 'finished.json', {'preparation_cancelled': True})
        except (OSError, ValueError):
            op.warning(output, 'transfer_result_storage_failed')
    return output
