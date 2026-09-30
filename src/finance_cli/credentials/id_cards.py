"""Saved identity cards: a prepared card photo and the text the user reviewed, sealed by a passphrase.

A card is stored once, away from any institution session, and selected when a
service asks for it, so no session idles while a photo is found and typed in.
The index keeps the name, card kind, the card's issue date and when it was
saved. The holder name, resident and licence numbers and the photo stay in a
scrypt/AES-GCM envelope. Institution-specific encryption happens at use time.
"""
from datetime import date
import io
import json
import re
import secrets
import time
import warnings

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageOps

from finance_cli.core import storage
from finance_cli.core.paths import data_home
from .registry import decode, encode, key, name

FORMAT = 'finance-id-card-v1'
KINDS = ('resident', 'driver')
IMAGE_LIMIT = 8 * 1024 * 1024
WIDTH = 1024
BASE = ('name', 'issueDate', 'birthDate', 'resident')
DRIVER = (('regionCode', 2), ('driver1', 2), ('driver2', 6), ('driver3', 2))
DATE = re.compile(r'[0-9]{4}\.[0-9]{2}\.[0-9]{2}')


def prepare_jpeg(raw):
    """Re-encode the user's JPEG in memory: orientation applied, at most 1024 pixels wide, no metadata."""
    if not raw:
        raise ValueError('identity_image_required')
    if len(raw) > IMAGE_LIMIT:
        raise ValueError('identity_image_too_large')
    if raw[:2] != b'\xff\xd8':
        raise ValueError('identity_jpeg_required')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw), formats=('JPEG',)) as original:
                photo = ImageOps.exif_transpose(original)
                if photo.width > WIDTH:
                    photo = photo.resize((WIDTH, max(1, round(photo.height * WIDTH / photo.width))),
                                         Image.Resampling.LANCZOS)
                output = io.BytesIO()
                # Re-encode pixels only: no EXIF, GPS, comments or original filename.
                photo = photo.convert('RGB')
                photo.info.clear()
                photo.save(output, format='JPEG', quality=95, subsampling=0)
                prepared = output.getvalue()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValueError('identity_image_dimensions_too_large') from None
    except (OSError, ValueError):
        raise ValueError('identity_jpeg_invalid') from None
    if len(prepared) > IMAGE_LIMIT:
        raise ValueError('identity_image_too_large')
    return prepared


def check_fields(kind, fields):
    """Local form rules for the reviewed card text; each service repeats its own rules at use time."""
    keys = set(BASE) | ({k for k, _ in DRIVER} if kind == 'driver' else set())
    if kind not in KINDS or not isinstance(fields, dict) or set(fields) != keys \
            or not all(isinstance(v, str) for v in fields.values()):
        raise ValueError('invalid_identity_capture')
    if not re.fullmatch('[0-9]{6}', fields['birthDate']) or not re.fullmatch('[0-9]{7}', fields['resident']):
        raise ValueError('resident_number_format')
    if not DATE.fullmatch(fields['issueDate']):
        raise ValueError('identity_date_format')
    try:
        year, month, day = map(int, fields['issueDate'].split('.'))
        date(year, month, day)
    except ValueError:
        raise ValueError('identity_date_invalid') from None
    if year < 100:
        raise ValueError('identity_date_invalid')
    if kind == 'driver' and any(not re.fullmatch('[0-9]{%d}' % size, fields[k]) for k, size in DRIVER):
        raise ValueError('driver_number_format')
    if not fields['name'].strip():
        raise ValueError('identity_name_required')
    if len(fields['name']) > 100 or any(ord(c) < 32 for c in fields['name']):
        raise ValueError('identity_name_invalid')
    return {k: fields[k] for k in sorted(keys)}


def passphrase_bytes(value):
    if not isinstance(value, str) or len(value) < 4:
        raise ValueError('passphrase_minimum_4_characters')
    if len(value) > 1024:
        raise ValueError('passphrase_too_long')
    return value.encode('utf-8')


def masked(value):
    """What `show` prints: enough to recognise the card, never a full number or the photo."""
    fields = value['fields']
    holder = fields['name'].strip()
    summary = {'kind': value['kind'], 'holder': holder[:1] + '●' * (len(holder) - 1),
               'issue_date': fields['issueDate'], 'resident_number': fields['birthDate'][:2] + '●●●●-' +
               fields['resident'][:1] + '●●●●●●'}
    if value['kind'] == 'driver':
        summary['driver_license'] = f"{fields['regionCode']}-{fields['driver1']}-●●●●●●-●●"
    with Image.open(io.BytesIO(value['jpeg']), formats=('JPEG',)) as photo:
        summary['photo'] = {'width': photo.width, 'height': photo.height, 'bytes': len(value['jpeg'])}
    return summary


class IdCards:
    def __init__(self, home=None):
        self.home = (home or data_home()).absolute()
        self.root = self.home / 'id-cards'

    def index(self):
        path = self.root / 'index.json'
        storage.no_symlinks(path)
        if not path.exists():
            return {'format': FORMAT, 'entries': {}}
        state = storage.read_json(path)
        if state.get('format') != FORMAT or not isinstance(state.get('entries'), dict):
            raise ValueError('invalid_id_card_index')
        for alias, row in state['entries'].items():
            name(alias)
            if (not isinstance(row, dict) or re.fullmatch('[0-9a-f]{32}', row.get('blob', '')) is None
                    or row.get('kind') not in KINDS or not DATE.fullmatch(row.get('issue_date', ''))
                    or type(row.get('saved_at')) is not int):
                raise ValueError('invalid_id_card_entry')
        return state

    def list(self):
        return [{'name': alias, 'kind': row['kind'], 'issue_date': row['issue_date'], 'saved_at': row['saved_at']}
                for alias, row in sorted(self.index()['entries'].items())]

    def entry(self, alias):
        name(alias)
        row = self.index()['entries'].get(alias)
        if row is None:
            raise ValueError('id_card_not_found')
        return row

    def add(self, alias, kind, fields, jpeg, passphrase):
        """Check and seal a card before anything is written; an existing name is never replaced."""
        name(alias)
        secret = passphrase_bytes(passphrase)
        fields = check_fields(kind, fields)
        photo = prepare_jpeg(jpeg)
        storage.directory(self.home)
        storage.directory(self.root)
        storage.directory(self.root / 'blobs')
        with storage.lock(self.root / 'lock'):
            state = self.index()
            if alias in state['entries']:
                raise ValueError('id_card_name_exists')
            blob, salt, nonce = secrets.token_hex(16), secrets.token_bytes(16), secrets.token_bytes(12)
            row = {'blob': blob, 'kind': kind, 'issue_date': fields['issueDate'], 'saved_at': int(time.time())}
            value = json.dumps({'kind': kind, 'fields': fields, 'image': encode(photo)}, ensure_ascii=False).encode()
            sealed = AESGCM(key(secret, salt)).encrypt(nonce, value, self._aad(row))
            envelope = {'format': FORMAT, 'salt': encode(salt), 'nonce': encode(nonce), 'sealed': encode(sealed)}
            storage.write_new(self.root / 'blobs' / blob, json.dumps(envelope).encode())
            state['entries'][alias] = row
            storage.atomic_json(self.root / 'index.json', state)
        return {'name': alias, 'kind': kind, 'saved': True, 'network_used': False}

    @staticmethod
    def _aad(row):
        # The listed kind and issue date are bound to the sealed card; editing the index breaks opening.
        return f"{FORMAT}/{row['blob']}/{row['kind']}/{row['issue_date']}".encode()

    def load(self, alias, passphrase):
        """The card as saved: kind, reviewed fields and the prepared JPEG bytes."""
        row = self.entry(alias)
        envelope = storage.read_json(self.root / 'blobs' / row['blob'])
        if envelope.get('format') != FORMAT:
            raise ValueError('invalid_id_card_envelope')
        try:
            plain = AESGCM(key(passphrase_bytes(passphrase), decode(envelope['salt']))).decrypt(
                decode(envelope['nonce']), decode(envelope['sealed']), self._aad(row))
        except InvalidTag:
            raise ValueError('incorrect_passphrase_or_damaged_id_card') from None
        value = json.loads(plain)
        if value['kind'] != row['kind'] or value['fields']['issueDate'] != row['issue_date']:
            raise ValueError('id_card_identity_mismatch')
        return {'kind': value['kind'], 'fields': check_fields(value['kind'], value['fields']),
                'jpeg': decode(value['image']), 'issue_date': row['issue_date'], 'saved_at': row['saved_at']}

    def show(self, alias, passphrase):
        row = self.entry(alias)
        return {'name': alias, **masked(self.load(alias, passphrase)), 'saved_at': row['saved_at'],
                'network_used': False}

    def rename(self, alias, new_alias):
        """Change the name only; the sealed card is untouched. No passphrase needed."""
        name(alias)
        name(new_alias)
        with storage.lock(self._lock_path()):
            state = self.index()
            if alias not in state['entries']:
                raise ValueError('id_card_not_found')
            if new_alias == alias:
                raise ValueError('id_card_name_unchanged')
            if new_alias in state['entries']:
                raise ValueError('id_card_name_exists')
            state['entries'][new_alias] = state['entries'].pop(alias)
            storage.atomic_json(self.root / 'index.json', state)
        return {'name': new_alias, 'previous_name': alias, 'renamed': True, 'network_used': False}

    def remove(self, alias):
        """Drop the index entry first, then the sealed file; the card is never decrypted."""
        name(alias)
        with storage.lock(self._lock_path()):
            state = self.index()
            row = state['entries'].pop(alias, None)
            if row is None:
                raise ValueError('id_card_not_found')
            storage.atomic_json(self.root / 'index.json', state)
            blob = storage.no_symlinks(self.root / 'blobs' / row['blob'])
            blob_removed = False
            if blob.is_file():
                blob.unlink()
                blob_removed = True
        return {'name': alias, 'removed': True, 'blob_removed': blob_removed, 'network_used': False}

    def _lock_path(self):
        if not self.root.is_dir():
            raise ValueError('id_card_not_found')
        return self.root / 'lock'

    def export(self, alias, passphrase, destination):
        """Write the prepared photo and reviewed fields to a new private directory."""
        from pathlib import Path
        destination = storage.no_symlinks(Path(destination))
        value = self.load(alias, passphrase)
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        storage.write_new(destination / 'card.jpg', value['jpeg'])
        storage.write_new(destination / 'card.json', json.dumps(
            {'kind': value['kind'], 'fields': value['fields']}, ensure_ascii=False, indent=2).encode() + b'\n')
        return {'exported': True, 'files': ['card.jpg', 'card.json'], 'output': str(destination),
                'network_used': False}
