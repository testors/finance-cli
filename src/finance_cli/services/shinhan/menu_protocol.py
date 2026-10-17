"""Menu key expansion and native program lookup response decoding."""
import json
from . import account_protocol, transport

PROGRAM_FIELDS = 'PR_ID PR_NM PR_TYPE MOVE_URL LOGIN_LEVEL LONGTERM_TRANSFER_CHK_YN ACCOUNT_CHECK_YN GRP_AGREE_YN AND_MIN_APP_VER ID_USABLE_YN OVOV_ID ASIS_SCRID CLOSE_DT_TM IOS_MIN_APP_VER OPEN_DT_TM REL_MENU_ID USABLE_ED_TM USABLE_ST_TM'.split()
REMOTE_FIELDS = 'prId prNm prType moveUrl loginLevel longtermTransferChkYn accountCheckYn grpAgreeYn andMinAppVer idUsableYn ovovId'.split()
REMOTE = {name: ('required_string', None) for name in REMOTE_FIELDS}


class Literal(str):
    """An unquoted JSON primitive, distinct from a quoted string in tree decoding."""


class Reader(account_protocol.Reader):
    def tree(self):
        char = self.peek()
        if char == '{':
            self.take('{')
            result = {}
            if self.peek() != '}':
                while True:
                    key, _ = self.token()
                    self.take(':')
                    result[key] = self.tree()
                    if self.peek() == '}':
                        break
                    self.take(',')
            self.take('}')
            return result
        if char == '[':
            self.take('[')
            result = []
            if self.peek() != ']':
                while True:
                    result.append(self.tree())
                    if self.peek() == ']':
                        break
                    self.take(',')
            self.take(']')
            return result
        value, quoted = self.token()
        return value if quoted else None if value == 'null' else Literal(value)


def string(value):
    if type(value) is not str:
        raise ValueError('menu_string_required')
    return value


def object_value(value):
    if not isinstance(value, dict):
        raise ValueError('menu_object_required')
    return value


def strings(value, names, *, optional=False):
    object_value(value)
    return {name: '' if optional and value.get(name) is None else string(value.get(name)) for name in names.split()}


def array(value, convert):
    if not isinstance(value, list):
        raise ValueError('menu_list_required')
    return [convert(item) for item in value]


def sub_menu(value):
    return strings(value, 'MENU_DEPTH LINK_PR_ID MENU_NM NEWTAG_YN TOOLTIP_YN TOOLTIP_MSG', optional=True)


def menu_item(value):
    return strings(value, 'MENU_DEPTH MENU_NM') | {'SUB_MENU_LIST': array(value.get('SUB_MENU_LIST'), sub_menu)}


def category(value):
    return strings(value, 'MENU_DEPTH CATEGORY_NM') | {'MENU_LIST': array(value.get('MENU_LIST'), menu_item)}


def decode(text):
    reader = Reader(text)
    source = object_value(reader.tree())
    if reader.peek():
        raise ValueError('menu_document')
    keys = object_value(source['LIGHT_PRG_KEY_DATA']) if 'LIGHT_PRG_KEY_DATA' in source else {}
    for value in keys.values():
        if value is not None and not isinstance(value, str):
            raise ValueError('menu_key_primitive_required')
    keys = {key: 'null' if value is None else str(value) for key, value in keys.items()}
    def expand(value):
        if isinstance(value, dict):
            return {keys.get(key, key): expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        return value
    value = expand(source)
    return strings(value, 'VERSION CHATBOT_ERR_LIST') | {
        'PROGRAM_LIST': array(value.get('PROGRAM_LIST'), lambda row: strings(row, ' '.join(PROGRAM_FIELDS), optional=True)),
        'ASIS_PRID_MAP': array(value.get('ASIS_PRID_MAP'), lambda row: strings(row, 'PR_ID ASIS_SCRID')),
        'BANK_CODE_SERACH_LIST': array(value.get('BANK_CODE_SERACH_LIST'), lambda row: strings(row, 'BANK_CODE BANK_NAME')),
        'CATEGORY_MENU_LIST': array(value.get('CATEGORY_MENU_LIST'), category),
    }


class NativeReader(account_protocol.Reader):
    def value(self, kind):
        if kind == 'required_string':
            result = super().value('string')
            if result is None:
                raise ValueError('program_required_string_null')
            return result
        return super().value(kind)


def native_decode(text, schema):
    reader = NativeReader(text)
    result = reader.value(schema)
    if reader.peek() or result is None:
        raise ValueError('program_json_document')
    return result


def decode_remote(text):
    value = native_decode(text, REMOTE)
    if any(item is None for item in value.values()):
        raise ValueError('program_required_field_missing')
    return value


def parse_reply(reply):
    # Bank judgement survives a subsequent typed body decoding error.
    try:
        text = reply.body.decode('utf-8-sig')
        document = account_protocol.decode(text, {'dataHeader': (account_protocol.HEADER, None)})
    except (ValueError, UnicodeError, RecursionError):
        return transport.parse(reply)
    verdict, _ = transport.parse(transport.Reply(reply.status, reply.headers, json.dumps(document).encode(), reply.error))
    if verdict['bank_result'] == 'success':
        try:
            document = native_decode(text, {'dataHeader': (account_protocol.HEADER, None), 'dataBody': (REMOTE, None)})
            body = document['dataBody']
            if body is not None and any(item is None for item in body.values()):
                raise ValueError('program_required_field_missing')
        except (ValueError, RecursionError):
            verdict.update(processing_status='incomplete', error='program_body_unavailable')
            document['dataBody'] = None
    return verdict, document


def local(value, identity):
    programs = {row['PR_ID']: row for row in value['PROGRAM_LIST']}
    aliases = {row['ASIS_SCRID']: row['PR_ID'] for row in value['ASIS_PRID_MAP']}
    return programs.get(identity) or programs.get(aliases.get(identity))


def remote(value):
    return dict(zip(PROGRAM_FIELDS, (value[name] for name in REMOTE_FIELDS)))
