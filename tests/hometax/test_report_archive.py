import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.dom import minidom

from PIL import Image
from hometax_cli.report_archive import archive_report, report_image

IMAGES = json.loads(Path(__file__).with_name('report-images.json').read_text())


def svg(content):
    return ('<svg xmlns="http://www.w3.org/2000/svg" '
            'xmlns:xlink="http://www.w3.org/1999/xlink">' + content + '</svg>')


class ReportArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {'output': self.temp.name, 'title': '보고서 & <상호>',
                       'expected_page_count': 1, 'pages': []}

    def save(self, content):
        self.config['pages'] = [{'svg': svg(content), 'width': 2100, 'height': 2970}]
        return archive_report(self.config)

    def test_png_and_mislabeled_jpeg_keep_bytes_dimensions_and_namespaces(self):
        images = ''.join('<image xlink:href="data:image/png;base64,' + IMAGES[key] + '"/>'
                         for key in ('png', 'jpg'))
        # No Node or other subprocess participates in local file construction.
        with patch('subprocess.Popen', side_effect=AssertionError('unexpected process')):
            result = self.save(images + '<text onclick="secret()">합성 &amp; 자료</text>')
        self.assertTrue(result['complete'])
        self.assertEqual(result['image_count'], 2)
        file = Path(self.temp.name) / 'report.html'
        data = file.read_bytes()
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['bytes'], len(data))
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        text = data.decode()
        self.assertIn('@page sheet0{size:21cm 29.7cm;margin:0}', text)
        self.assertIn('보고서 &amp; &lt;상호&gt;', text)
        self.assertNotIn('onclick', text)
        self.assertNotIn('secret()', text)
        with minidom.parseString(text[text.index('<svg'):text.index('</svg>') + 6]) as doc:
            for node, key, mime in zip(doc.getElementsByTagName('image'),
                                      ('png', 'jpg'), ('image/png', 'image/jpeg')):
                href = node.getAttributeNS('http://www.w3.org/1999/xlink', 'href')
                self.assertEqual(href, 'data:' + mime + ';base64,' + IMAGES[key])
                self.assertEqual(report_image(base64.b64decode(IMAGES[key])),
                                 {'mime': mime, 'width': 1, 'height': 1})

    def test_missing_corrupt_external_images_mark_archive_incomplete(self):
        result = self.save('<image/><image href="https://example.invalid/image"/>'
                           '<image href="data:image/png;base64,INVALID_PNG"/>'
                           '<path fill="url(/outside)"/><script src="/code"/>')
        self.assertTrue(result['saved'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['missing_images'], 2)
        self.assertEqual(result['invalid_images'], 1)
        self.assertEqual(result['external_references'], 4)
        self.assertNotIn('branch', result)

    def test_partial_page_count_is_not_service_failure(self):
        self.config['expected_page_count'] = 2
        result = self.save('<text>one page</text>')
        self.assertEqual(result['page_count'], 1)
        self.assertTrue(result['saved'])
        self.assertFalse(result['complete'])
        self.assertNotIn('branch', result)

    def test_existing_file_is_not_overwritten(self):
        self.save('<text>first</text>')
        path = Path(self.temp.name) / 'report.html'
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.save('<text>second</text>')
        self.assertEqual(path.read_bytes(), before)

    def test_pixel_decode_not_just_header_check(self):
        for key in ('png', 'jpg'):
            data = base64.b64decode(IMAGES[key])
            with self.subTest(format=key), self.assertRaises(Exception):
                report_image(data[:len(data)//2])
        buffer = io.BytesIO()
        Image.new('RGB', (1, 1)).save(buffer, format='GIF')
        with self.assertRaises(Exception):
            report_image(buffer.getvalue())

    def test_module_input_uses_stdin_and_errors_do_not_echo_page_data(self):
        self.config['pages'] = [{'svg': '<SYNTHETIC_PRIVATE_VALUE', 'width': 1, 'height': 1}]
        result = subprocess.run([sys.executable, '-m', 'hometax_cli.report_archive'],
                                input=json.dumps(self.config), capture_output=True, text=True,
                                env={**os.environ, 'PATH': self.temp.name})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', result.stderr)
        self.config['pages'][0]['svg'] = svg('<text>synthetic</text>')
        result = subprocess.run([sys.executable, '-m', 'hometax_cli.report_archive'],
                                input=json.dumps(self.config), capture_output=True, text=True,
                                env={**os.environ, 'PATH': self.temp.name})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['complete'])


if __name__ == '__main__':
    unittest.main()
