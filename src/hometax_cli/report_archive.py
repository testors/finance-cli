"""Build the local HTML archive from rendered SVG pages, without a JS runtime."""
import base64
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import sys
import warnings
from xml.dom import minidom

from PIL import Image

XLINK = 'http://www.w3.org/1999/xlink'
STYLE = ('body{margin:0;background:#eee}.page{background:white;margin:12px auto;'
         'width:max-content;break-after:page}.page:last-child{break-after:auto}'
         'svg{display:block}@media print{body{background:white}.page{margin:0}}')


def report_image(data):
    """Decode pixels as well as headers; never re-encode the archived bytes."""
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data), formats=('PNG', 'JPEG')) as image:
            metadata = {'mime': 'image/png' if image.format == 'PNG' else 'image/jpeg',
                        'width': image.width, 'height': image.height}
            image.verify()
        with Image.open(io.BytesIO(data), formats=('PNG', 'JPEG')) as image:
            image.load()
    return metadata


def decode_image(value):
    # Match the permissive base64 input used by the viewer's byte decoder.
    value = re.sub(r'[^A-Za-z0-9+/=_-]', '', value).split('=')[0]
    if len(value) % 4 == 1:
        value = value[:-1]
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_')


def archive_report(config):
    pages = []
    style = STYLE
    image_count = missing_images = invalid_images = external_references = 0
    for index, page in enumerate(config['pages']):
        # XMLSerializer supplies namespaces. Parsing does not load references.
        with minidom.parseString(page['svg']) as document:
            if document.doctype:
                raise ValueError('Unexpected SVG document type')
            svg = document.documentElement
            nodes = [svg, *svg.getElementsByTagName('*')]
            for node in nodes:
                if node.localName == 'image':
                    image_count += 1
                    href = node.getAttribute('href') or node.getAttributeNS(XLINK, 'href')
                    if not href.startswith('data:image/'):
                        missing_images += 1
                    elif re.match(r'^data:image/(png|jpeg);base64,', href):
                        try:
                            encoded = href.split(',', 1)[1]
                            mime = report_image(decode_image(encoded))['mime']
                            corrected = 'data:' + mime + ';base64,' + encoded
                            if node.getAttribute('href'):
                                node.setAttribute('href', corrected)
                            else:
                                node.getAttributeNodeNS(XLINK, 'href').value = corrected
                        except Exception:
                            invalid_images += 1
                for attribute in list(node.attributes.values()):
                    name, value = attribute.name, attribute.value
                    if name.lower().startswith('on'):
                        node.removeAttributeNode(attribute)
                    elif ((name in ('href', 'src') or
                           (attribute.namespaceURI == XLINK and attribute.localName == 'href')) and value
                          and not value.startswith(('#', 'data:'))):
                        external_references += 1
                    elif re.search(r'''url\(\s*['"]?(?:https?:|/)''', value, re.I):
                        external_references += 1
                if node.localName in ('script', 'iframe', 'object', 'embed'):
                    external_references += 1
            width = str(float(page['width']) / 100).removesuffix('.0')
            height = str(float(page['height']) / 100).removesuffix('.0')
            style += f'@page sheet{index}{{size:{width}cm {height}cm;margin:0}}'
            pages.append(f'<section class="page" style="page:sheet{index}">{svg.toxml()}</section>')
    title = html.escape(str(config.get('title') or '보고서'))
    data = (f'<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            f'<title>{title}</title><style>{style}</style></head><body>'
            + ''.join(pages) + '</body></html>').encode('utf-8')
    # The caller creates a new private directory before any service requests.
    destination = Path(config['output']) / 'report.html'
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data)
    return {'saved': True, 'file': 'report.html', 'format': 'html-svg',
            'page_count': len(pages), 'image_count': image_count,
            'missing_images': missing_images, 'invalid_images': invalid_images,
            'external_references': external_references, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'complete': (len(pages) == config['expected_page_count']
                         and missing_images == invalid_images == external_references == 0)}


def main():
    try:
        result = archive_report(json.load(sys.stdin))
    except Exception:
        # Input can contain taxpayer data. Do not echo exceptions or page data.
        print('error: 보고서 파일 생성 오류', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
