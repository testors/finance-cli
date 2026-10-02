"""Install or reuse local keypad settings without enrolling a certificate."""
import base64
import hashlib
import json
from pathlib import Path
import zipfile

from finance_cli.core import storage
from finance_cli.services.hana import store as shared
from .protocol import require, Stop, VERSION

ENTRY = 'lib/arm64-v8a/libNSaferJNI.so'
DIGEST = '2066cbdbf7bdf7d384c86dee02aa6c33a1b26cbb80cc55d70dba76739832b87f'
OFFSET = 436012


def install(package, name):
    name = shared.name(name)
    path = storage.no_symlinks(Path(package).expanduser())
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [row for row in archive.infolist() if row.filename == ENTRY]
            require(len(entries) == 1 and entries[0].file_size <= 4 * 1024 * 1024, 'keypad_entry_unavailable')
            require(not entries[0].flag_bits & 1, 'encrypted_package_not_supported')
            data = archive.read(entries[0])
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError):
        raise Stop('invalid_keypad_package') from None
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'unsupported_keypad_package')
    material = data[OFFSET:OFFSET + 20]
    require(len(material) == 20, 'keypad_material_unavailable')
    directory = shared.root('settings')
    for parent in (directory.parents[1], directory.parent, directory):
        storage.directory(parent)
    value = {'format': 'finance-hana-keypad-v1', 'version': VERSION,
             'keypad_mac': base64.b64encode(material).decode(), 'source_sha256': DIGEST}
    storage.write_new(directory / (name + '.json'), json.dumps(value).encode())
    return {'settings': name, 'version': VERSION, 'extracted': True, 'network_used': False}


def load(name):
    value = storage.read_json(shared.root('settings') / (shared.name(name) + '.json'))
    require(isinstance(value, dict) and (value.get('format'), value.get('version')) in (
        ('finance-hana-keypad-v1', VERSION), ('finance-hana-settings-v1', '1.0.27')), 'unsupported_keypad_settings')
    material = base64.b64decode(value['keypad_mac'], validate=True)
    require(len(material) == 20, 'invalid_keypad_mac')
    return material
