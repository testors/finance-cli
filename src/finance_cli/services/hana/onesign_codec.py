"""JSON encoding shared by encrypted records and service messages."""
import base64
import json
import re
from .onesign_crypto import ProtocolError, require


def segment(value):
    """The service's lenient base64 decoder (not the local record decoder)."""
    require(isinstance(value,str),'invalid_base64url')
    value = re.sub(r'[^A-Za-z0-9+/_-]','',value.split('=',1)[0]).replace('-','+').replace('_','/')
    if len(value)%4==1:
        value=value[:-1]
    return base64.b64decode(value+'='*(-len(value)%4))

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_field')
            result[key] = value
        return result
    require(isinstance(raw, (str, bytes)), 'invalid_json_size')
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError('invalid_json_number')))
        require(isinstance(result, dict), 'json_object_required')
        return result
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError('invalid_json') from None
