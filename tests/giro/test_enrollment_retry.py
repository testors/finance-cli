import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from finance_cli.core import storage
from giro.registration_flow import EnrollmentStore, EnrollmentRetryUnavailable, retryable_start_report


def rejected():
    return dict(state='finished', next_action='stopped', registration_service_decision='unobserved',
        login=None, steps=[dict(stage='auth.device-status', response_endpoint='auth.device-status',
            response_origin='response', service_decision='failure', next_action='stopped',
            registration_service_decision='unobserved')])


class EnrollmentRetryTests(unittest.TestCase):
    def test_only_confirmed_initial_rejection_is_eligible(self):
        self.assertTrue(retryable_start_report(rejected()))
        values = [None, [], {}, rejected() | {'state': 'reserved'},
            rejected() | {'registration_service_decision': 'success'},
            rejected() | {'login': {}}, rejected() | {'steps': []}]
        for field, value in (('stage', 'registration.pin'), ('service_decision', 'unobserved'),
                             ('response_origin', 'transport'), ('service_decision', 'success'),
                             ('response_endpoint', 'registration.sms-send')):
            document = rejected()
            document['steps'][0][field] = value
            values.append(document)
        for document in values:
            with self.subTest(document=document): self.assertFalse(retryable_start_report(document))

    def test_retry_never_creates_missing_identity_or_replaces_pending_or_later_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = EnrollmentStore(root)
            with self.assertRaises(EnrollmentRetryUnavailable): store.identity(create=False)
            self.assertFalse((root / 'identity.json').exists())
            with self.assertRaises(EnrollmentRetryUnavailable): store.reserve(retry=True)
            self.assertFalse((root / 'attempt.json').exists())
            path = store.reserve()
            for document in ({'state': 'reserved'}, rejected() | {'registration_service_decision': 'success'},
                             rejected() | {'steps': [rejected()['steps'][0]] * 2}):
                storage.atomic_json(path, document)
                original = path.read_bytes()
                with self.assertRaises(EnrollmentRetryUnavailable): store.reserve(retry=True)
                self.assertEqual(path.read_bytes(), original)
            path.write_bytes(b'not-json')
            with self.assertRaises(EnrollmentRetryUnavailable): store.reserve(retry=True)
            self.assertEqual(path.read_bytes(), b'not-json')

    def test_archive_write_failure_keeps_old_record_and_does_not_reserve_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            storage.write_new(root / 'attempt.json', json.dumps(rejected()).encode())
            before = (root / 'attempt.json').read_bytes()
            with patch('giro.registration_flow.storage.write_new', side_effect=OSError('synthetic')):
                with self.assertRaises(OSError): EnrollmentStore(root).reserve(retry=True)
            self.assertEqual((root / 'attempt.json').read_bytes(), before)

    def test_interrupted_replacement_preserves_archive_and_allows_explicit_later_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            storage.write_new(root / 'attempt.json', json.dumps(rejected()).encode())
            before = (root / 'attempt.json').read_bytes()
            store = EnrollmentStore(root)
            with patch('giro.registration_flow.storage.atomic_json', side_effect=OSError('synthetic')):
                with self.assertRaises(OSError): store.reserve(retry=True)
            self.assertEqual((root / 'attempt.json').read_bytes(), before)
            store.reserve(retry=True)
            archives = list((root / 'attempts').iterdir())
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_bytes(), before)
            with self.assertRaises(EnrollmentRetryUnavailable): store.reserve(retry=True)

    def test_parallel_reservation_cannot_archive_or_replace_active_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            storage.write_new(root / 'attempt.json', json.dumps(rejected()).encode())
            with storage.lock(root / '.attempt.lock'):
                with self.assertRaises(BlockingIOError): EnrollmentStore(root).reserve(retry=True)
            self.assertFalse((root / 'attempts').exists())
