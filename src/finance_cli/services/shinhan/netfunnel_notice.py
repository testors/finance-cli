"""Typed queue-block notice and its fallback, separate from admission decisions."""
import copy
from . import account_protocol as codec


def required(kind):
    return ('required', kind)


BUTTON = {name: (required('string'), None) for name in ('title', 'type')}
ACTION = {'message': (required('string'), None), 'blockTypes': (required(['string']), None),
          'button': (required(BUTTON), None)}
BLOCK = codec.strings('title iconImageURL webURL android programId')
SCHEMA = {'errAction': (required('string'), None), 'errActionType': (required(('map', ACTION)), None),
          'blocks': (required(('map', BLOCK)), None)}
DEFAULT = {'message': '거래량이 많아 접속이 원활하지 않아요', 'blocks': [], 'button': {'title': '앱 종료', 'type': 'exit'}}


class Reader(codec.Reader):
    def value(self, kind):
        if isinstance(kind, tuple):
            if kind[0] == 'required':
                value = self.value(kind[1])
                if value is None:
                    raise ValueError('queue_notice_required_value')
                return value
            self.take('{')
            value = {}
            if self.peek() != '}':
                while True:
                    key, _ = self.token()
                    self.take(':')
                    value[key] = self.value(required(kind[1]))
                    if self.peek() == '}': break
                    self.take(',')
            self.take('}')
            return value
        value = super().value(kind)
        if isinstance(kind, dict) and value is not None and any(
                isinstance(spec, tuple) and spec[0] == 'required' and value[name] is None
                for name, (spec, default) in kind.items()):
            raise ValueError('queue_notice_required_field')
        return value


def parse(text):
    try:
        reader = Reader(text)
        value = reader.value(required(SCHEMA))
        if reader.peek(): raise ValueError('queue_notice_document')
        action = value['errActionType'].get(value['errAction'])
        if action is None: return copy.deepcopy(DEFAULT)
        return {'message': action['message'], 'button': action['button'],
                'blocks': [dict(type=name, **value['blocks'][name]) for name in action['blockTypes'] if name in value['blocks']]}
    except Exception:
        return copy.deepcopy(DEFAULT)
