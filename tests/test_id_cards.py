"""Saved identity cards with synthetic photos and numbers only; no institution connections."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

from finance_cli.cli import id_cards as cli
from finance_cli.cli.main import main
from finance_cli.credentials import id_cards
from finance_cli.credentials.id_cards import IdCards

PASSPHRASE = 'SYNTHETIC-card-passphrase'
FIELDS = {'name': '합성 이름', 'issueDate': '2020.02.29', 'birthDate': '900101', 'resident': '1000000'}
DRIVER = {**FIELDS, 'regionCode': '11', 'driver1': '20', 'driver2': '123456', 'driver3': '78'}


def synthetic_jpeg(width=2400, height=1500):
    image = Image.new('RGB', (width, height), 'white')
    metadata = Image.Exif()
    metadata[270] = 'SYNTHETIC-PRIVATE-METADATA'
    output = io.BytesIO()
    image.save(output, format='JPEG', exif=metadata, comment=b'SYNTHETIC-PRIVATE-COMMENT')
    return output.getvalue()


class IdCardStore(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temp).resolve()
        self.home = self.root / 'home'
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(self.home)}))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('No institution requests')))
        self.cards = IdCards()

    def add(self, alias='resident-card', kind='resident', fields=FIELDS):
        return self.cards.add(alias, kind, copy.deepcopy(fields), synthetic_jpeg(), PASSPHRASE)

    def command(self, argv, stdin=''):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('sys.stdin', io.TextIOWrapper(io.BytesIO(stdin.encode()))):
            code = main(argv)
        return code, json.loads(output.getvalue())

    def test_empty_listing_has_no_side_effect(self):
        self.assertEqual(self.cards.list(), [])
        self.assertFalse(self.home.exists())

    def test_roundtrip_keeps_reviewed_text_and_prepared_photo_only(self):
        self.assertEqual(self.add(), {'name': 'resident-card', 'kind': 'resident', 'saved': True, 'network_used': False})
        card = self.cards.load('resident-card', PASSPHRASE)
        self.assertEqual((card['kind'], card['fields'], card['issue_date']), ('resident', FIELDS, '2020.02.29'))
        with Image.open(io.BytesIO(card['jpeg'])) as photo:
            self.assertEqual((photo.format, photo.size), ('JPEG', (1024, 640)))
            self.assertEqual(dict(photo.getexif()), {})
        self.assertNotIn(b'SYNTHETIC-PRIVATE', card['jpeg'])
        listed = self.cards.list()
        self.assertEqual([{k: v for k, v in row.items() if k != 'saved_at'} for row in listed],
                         [{'name': 'resident-card', 'kind': 'resident', 'issue_date': '2020.02.29'}])
        self.assertIsInstance(listed[0]['saved_at'], int)

    def test_store_files_are_private_and_hold_no_clear_card_data(self):
        self.add('driver-card', 'driver', DRIVER)
        files = [p for p in (self.home / 'id-cards').rglob('*') if p.is_file()]
        self.assertTrue(files)
        for path in files:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path)
            raw = path.read_bytes()
            for value in ('합성 이름'.encode(), '합성 이름'.encode('unicode_escape'), b'1000000', b'900101', b'123456',
                          PASSPHRASE.encode(), b'SYNTHETIC-PRIVATE', b'\xff\xd8'):
                self.assertNotIn(value, raw, path)

    def test_wrong_passphrase_and_edited_index_do_not_open(self):
        self.add()
        with self.assertRaisesRegex(ValueError, 'incorrect_passphrase_or_damaged_id_card'):
            self.cards.load('resident-card', 'SYNTHETIC-other')
        index = self.home / 'id-cards' / 'index.json'
        state = json.loads(index.read_text())
        state['entries']['resident-card']['issue_date'] = '2024.01.01'
        index.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, 'incorrect_passphrase_or_damaged_id_card'):
            self.cards.load('resident-card', PASSPHRASE)

    def test_field_and_photo_rules_refuse_before_writing(self):
        cases = [(dict(FIELDS, resident='100000'), 'resident_number_format'),
                 (dict(FIELDS, issueDate='20200229'), 'identity_date_format'),
                 (dict(FIELDS, issueDate='2021.02.29'), 'identity_date_invalid'),
                 (dict(FIELDS, name=' '), 'identity_name_required'),
                 (dict(FIELDS, name='합성\n이름'), 'identity_name_invalid'),
                 ({**FIELDS, 'extra': 'x'}, 'invalid_identity_capture')]
        for fields, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                self.cards.add('card', 'resident', fields, synthetic_jpeg(), PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'driver_number_format'):
            self.cards.add('card', 'driver', dict(DRIVER, driver2='12345'), synthetic_jpeg(), PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'identity_jpeg_required'):
            self.cards.add('card', 'resident', FIELDS, b'\x89PNG\r\n\x1a\nSYNTHETIC', PASSPHRASE)
        with self.assertRaisesRegex(ValueError, 'passphrase_minimum_4_characters'):
            self.cards.add('card', 'resident', FIELDS, synthetic_jpeg(), 'abc')
        self.assertEqual(self.cards.list(), [])

    def test_existing_name_is_never_replaced(self):
        self.add()
        blob = next((self.home / 'id-cards' / 'blobs').iterdir()).read_bytes()
        with self.assertRaisesRegex(ValueError, 'id_card_name_exists'):
            self.cards.add('resident-card', 'driver', DRIVER, synthetic_jpeg(), 'SYNTHETIC-other')
        self.assertEqual(next((self.home / 'id-cards' / 'blobs').iterdir()).read_bytes(), blob)
        self.assertEqual(self.cards.load('resident-card', PASSPHRASE)['kind'], 'resident')

    def test_rename_remove_and_export(self):
        self.add()
        self.assertEqual(self.cards.rename('resident-card', 'card-2020')['name'], 'card-2020')
        self.assertEqual(self.cards.load('card-2020', PASSPHRASE)['fields'], FIELDS)
        self.add('other')
        with self.assertRaisesRegex(ValueError, 'id_card_name_exists'):
            self.cards.rename('card-2020', 'other')
        destination = self.root / 'export'
        result = self.cards.export('card-2020', PASSPHRASE, destination)
        self.assertEqual(result['files'], ['card.jpg', 'card.json'])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(json.loads((destination / 'card.json').read_text()), {'kind': 'resident', 'fields': FIELDS})
        self.assertEqual((destination / 'card.jpg').read_bytes(), self.cards.load('card-2020', PASSPHRASE)['jpeg'])
        with self.assertRaises(FileExistsError):
            self.cards.export('card-2020', PASSPHRASE, destination)
        removed = self.cards.remove('card-2020')
        self.assertEqual((removed['removed'], removed['blob_removed']), (True, True))
        self.assertEqual([row['name'] for row in self.cards.list()], ['other'])
        self.assertEqual(len(list((self.home / 'id-cards' / 'blobs').iterdir())), 1)
        with self.assertRaisesRegex(ValueError, 'id_card_not_found'):
            self.cards.remove('card-2020')

    def test_show_masks_numbers_and_never_prints_the_photo(self):
        self.add('driver-card', 'driver', DRIVER)
        shown = self.cards.show('driver-card', PASSPHRASE)
        text = json.dumps(shown, ensure_ascii=False)
        for value in ('합성 이름', '1000000', '900101', '123456'):
            self.assertNotIn(value, text)
        self.assertEqual((shown['holder'], shown['resident_number'], shown['driver_license']),
                         ('합●●●●', '90●●●●-1●●●●●●', '11-20-●●●●●●-●●'))
        self.assertEqual(shown['photo']['width'], 1024)

    def test_cli_add_prompts_after_checking_name_and_photo(self):
        image = self.root / 'card.jpg'
        image.write_bytes(synthetic_jpeg())
        answers = iter(['본인 신분증', FIELDS['name'], FIELDS['issueDate']])
        secrets = iter([FIELDS['birthDate'], FIELDS['resident'], PASSPHRASE, PASSPHRASE])
        with patch.object(cli, 'text', side_effect=lambda prompt: next(answers)), \
                patch.object(cli, 'hidden', side_effect=lambda prompt: next(secrets)):
            code, result = self.command(['idcard', 'add', 'resident-card', '--image', str(image)])
        self.assertEqual((code, result['saved']), (0, True))
        self.assertEqual(self.cards.load('resident-card', PASSPHRASE)['fields'], FIELDS)
        with patch.object(cli, 'text', side_effect=AssertionError('must not prompt')), \
                patch.object(cli, 'hidden', side_effect=AssertionError('must not prompt')):
            code, refused = self.command(['idcard', 'add', 'resident-card', '--image', str(image)])
            self.assertEqual((code, refused['message']), (2, 'id_card_name_exists'))
            image.write_bytes(b'\xff\xd8SYNTHETIC-broken')
            code, refused = self.command(['idcard', 'add', 'other', '--image', str(image)])
            self.assertEqual((code, refused['message']), (2, 'identity_jpeg_invalid'))

    def test_cli_add_requires_matching_passphrase_confirmation_and_terminal(self):
        image = self.root / 'card.jpg'
        image.write_bytes(synthetic_jpeg())
        answers = iter(['본인 신분증', FIELDS['name'], FIELDS['issueDate']])
        secrets = iter([FIELDS['birthDate'], FIELDS['resident'], PASSPHRASE, 'SYNTHETIC-mismatch'])
        with patch.object(cli, 'text', side_effect=lambda prompt: next(answers)), \
                patch.object(cli, 'hidden', side_effect=lambda prompt: next(secrets)):
            code, refused = self.command(['idcard', 'add', 'resident-card', '--image', str(image)])
        self.assertEqual((code, refused['message']), (2, 'passphrase_confirmation_mismatch'))
        code, refused = self.command(['idcard', 'add', 'resident-card', '--image', str(image)])
        self.assertEqual((code, refused['message']), (2, 'interactive_terminal_required'))
        self.assertEqual(self.cards.list(), [])

    def test_cli_list_show_rename_remove(self):
        self.add()
        code, listed = self.command(['idcard', 'list'])
        self.assertEqual((code, [row['name'] for row in listed['id_cards']], listed['network_used']),
                         (0, ['resident-card'], False))
        code, shown = self.command(['idcard', 'show', 'resident-card', '--password-stdin'], PASSPHRASE + '\n')
        self.assertEqual((code, shown['resident_number']), (0, '90●●●●-1●●●●●●'))
        self.assertEqual(self.command(['idcard', 'rename', 'resident-card', 'card-2020'])[1]['name'], 'card-2020')
        self.assertTrue(self.command(['idcard', 'remove', 'card-2020'])[1]['removed'])
        code, refused = self.command(['--format', 'json-v1', 'idcard', 'show', 'card-2020', '--password-stdin'],
                                     PASSPHRASE + '\n')
        self.assertEqual(code, 2)
        self.assertNotIn(PASSPHRASE, json.dumps(refused))

    def test_capabilities_list_the_store(self):
        code, value = self.command(['capabilities'])
        self.assertIn('hana-onesign-issuance-selection', value['credentials']['id_cards'])
        self.assertIn('id-card-storage', value['web']['scope'])


class SavedCardIssuance(unittest.TestCase):
    """`--id-card` feeds the same local preparation as a typed-in card, and opens the card before any stage."""

    @classmethod
    def setUpClass(cls):
        import test_hana_onesign as fixture
        cls.fixture = fixture
        fixture.FlowTests.setUpClass()

    def setUp(self):
        from finance_cli.services.hana import onesign
        from finance_cli.services.hana.onesign_state import State
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {'FINANCE_HOME': str(Path(temp).resolve() / 'home')}))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')))
        self.onesign, self.State = onesign, State
        with State('synthetic', self.fixture.PASSWORD, copy.deepcopy(self.fixture.FlowTests.template)):
            pass
        IdCards().add('driver-card', 'driver', dict(DRIVER), synthetic_jpeg(), PASSPHRASE)

    def begin(self):
        flow = self.fixture.FlowTests
        self.state = self.enterContext(self.State('synthetic', self.fixture.PASSWORD))
        self.services = self.fixture.Services(self.state, flow.cert, flow.public)
        inputs = {'phone': lambda: {'name': '합성 이름', 'birth7': '9001011', 'phone': '01000000000', 'carrier': '4'},
                  'agree': lambda *a: True, 'sms': lambda: '012345'}
        for number, action in enumerate((*self.onesign.PHONE, 'begin-id')):
            result = self.onesign.operate(self.state, action, f'run-{number}', send=True, inputs=inputs,
                                          exchange=self.services)
            self.assertEqual(result['processing_status'], 'completed', (action, result))

    def test_saved_card_prepares_identity_with_its_own_kind(self):
        from types import SimpleNamespace
        from finance_cli.services.hana import onesign_cli
        self.begin()
        count = len(self.services.calls)
        args = SimpleNamespace(id_card='driver-card', image=None, kind='resident')
        with patch.object(onesign_cli, 'hidden', return_value=PASSPHRASE), \
                patch.object(onesign_cli, 'text', return_value='본인 신분증'):
            result = onesign_cli.prepare_id(self.state, args)
        self.assertEqual((result['prepared'], result['network_used']), (True, False))
        self.assertEqual(len(self.services.calls), count)
        issuance = self.state.snapshot()['issuance']
        self.assertEqual(issuance['capture_kind'], 'driver')
        self.assertEqual(issuance['capture']['regionCode'], '11')

    def test_wrong_passphrase_or_unconfirmed_card_prepares_nothing(self):
        from types import SimpleNamespace
        from finance_cli.services.hana import onesign_cli
        self.begin()
        args = SimpleNamespace(id_card='driver-card', image=None, kind='resident')
        for secret, answer, code in ((PASSPHRASE, 'no', 'identity_not_confirmed'),
                                     ('SYNTHETIC-other', '본인 신분증', 'incorrect_passphrase_or_damaged_id_card')):
            with self.subTest(code=code), patch.object(onesign_cli, 'hidden', return_value=secret), \
                    patch.object(onesign_cli, 'text', return_value=answer), self.assertRaisesRegex(ValueError, code):
                onesign_cli.prepare_id(self.state, args)
        self.assertNotIn('capture', self.state.snapshot()['issuance'])

    def test_enroll_opens_the_saved_card_before_any_request(self):
        from finance_cli.services.hana import onesign_cli
        stdin = io.TextIOWrapper(io.BytesIO((self.fixture.PASSWORD + '\n').encode()))
        with patch.object(onesign_cli, 'hidden', return_value='SYNTHETIC-other'), \
                patch.object(onesign_cli, 'text', return_value='본인 신분증'), \
                patch.object(self.onesign, 'operate', side_effect=AssertionError('must not start a stage')), \
                patch('sys.stdin', stdin), contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            code = main(['hana', 'onesign', 'enroll', '--name', 'synthetic', '--run', 'r1', '--send',
                         '--id-card', 'driver-card', '--password-stdin'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['message'], 'incorrect_passphrase_or_damaged_id_card')

    def test_image_and_saved_card_are_mutually_exclusive(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            main(['hana', 'onesign', 'issue', '--name', 'synthetic', '--run', 'r', '--stage', 'prepare-id',
                  '--image', 'card.jpg', '--id-card', 'driver-card'])


if __name__ == '__main__':
    unittest.main()
