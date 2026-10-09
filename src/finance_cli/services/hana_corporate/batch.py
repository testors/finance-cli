"""CSV recipient lists and serialized preparation of one reviewed KRW batch."""
import csv
from pathlib import Path
import re

from finance_cli.services.hana.onesign_io import send_http
from . import operations as op, protocol, queries, store, transfers, transfer_protocol as wire

REQUIRED = {'to_bank', 'to_account', 'amount'}
OPTIONAL = {'employee', 'credit_memo', 'debit_memo', 'memo', 'cms_code'}


class RowError(protocol.Stop):
    def __init__(self, row):
        super().__init__('invalid_batch_row')
        self.row = row


def read_items(path):
    """Keep account identifiers as text and validate the entire file before I/O."""
    try:
        with Path(path).open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            headers = reader.fieldnames or []
            protocol.require(len(headers) == len(set(headers)) and REQUIRED <= set(headers)
                             and set(headers) <= REQUIRED | OPTIONAL, 'invalid_batch_columns')
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error):
        raise protocol.Stop('batch_file_unreadable') from None
    protocol.require(rows, 'empty_transfer_batch')
    items = []
    for index, row in enumerate(rows, 1):
        try:
            protocol.require(None not in row and all(isinstance(v, str) for v in row.values()), 'invalid_batch_row')
            bank = row['to_bank'].strip()
            protocol.require(re.fullmatch('[0-9]{3}', bank) is not None and bank not in ('996', '997', '998', '999'),
                             'ordinary_transfer_bank_required')
            recipient = queries.account_number(row['to_account'].strip())
            amount = row['amount'].strip()
            protocol.require(re.fullmatch('[0-9]+', amount) is not None and int(amount) > 0, 'invalid_transfer_amount')
            item = {'bank': bank, 'recipient': recipient, 'amount': str(int(amount)),
                    'memo': row.get('memo', ''), 'cms_code': row.get('cms_code', ''),
                    'sender_text': row.get('credit_memo') or None, 'recipient_text': row.get('debit_memo') or None}
            wire.check_notes({'CMSV_NO': item['cms_code'], 'WDRW_PSBK_MARK_CTT': item['recipient_text'] or '',
                              'RCV_PSBK_MARK_CTT': item['sender_text'] or '', 'MEMO': item['memo']}, {})
            items.append(item)
        except (protocol.Stop, ValueError):
            # Do not echo employee names, account numbers, or CSV contents.
            raise RowError(index) from None
    return items


def summary(items):
    seen, duplicates = set(), []
    for index, item in enumerate(items, 1):
        key = (item['bank'], item['recipient'], item['amount'])
        if key in seen:
            duplicates.append(index)
        seen.add(key)
    return {'item_count': len(items), 'total_amount': str(sum(int(item['amount']) for item in items)),
            'duplicate_rows': duplicates, 'bank_verified': False}


def check(path):
    output = op.result('transfer-check-batch', False)
    output.update(summary(read_items(path)), processing_status='completed', transfer_sent=False)
    return output


def prepare(account, path, *, delayed=False, session=None, send=False, exchange=send_http):
    output = op.result('transfer-prepare-batch', send)
    output.update(transfer_sent=False, prepared_items=0)
    if not send:
        return output
    # No partial server preparation when a later CSV row is invalid.
    account = queries.account_number(account)
    items = read_items(path)
    output['input_summary'] = summary(items)
    if output['input_summary']['duplicate_rows']:
        op.warning(output, 'duplicate_rows_in_batch_review_confirmation')
    with op.operation(output, session, exchange=exchange) as client:
        if client is None:
            return output
        directory = transfers.new_preparation(client, output)
        confirmation = None
        for index, item in enumerate(items, 1):
            output['preparing_item'] = index
            confirmation = transfers.prepare_item(client, directory, output, account, **item,
                delayed=delayed, previous=confirmation, prefix=str(index) + '-')
            output['prepared_items'] = index
            output['preview'] = wire.preview(confirmation)
        output.pop('preparing_item', None)
        if len(confirmation.get('cts0004InRec') or []) != len(items):
            op.warning(output, 'batch_confirmation_count_differs_review_bank_items')
        # An interrupted preparation must never expose an earlier, partial
        # confirmation to execute. Persist only after every row is prepared.
        store.record(directory / 'confirmation.json', confirmation)
        output.update(transfer_status='prepared', next='fin hana corporate transfer execute --send')
    return output
