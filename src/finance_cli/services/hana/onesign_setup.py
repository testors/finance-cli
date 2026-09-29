"""Offline, version-specific extraction of locally supplied service settings.

Only data is read. No application code, constructors, devices or network are used.
Unknown input revisions are rejected before any output is installed.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zipfile

from cryptography import x509
from finance_cli.core import storage
from . import store

VERSION = '1.0.27'
RECIPES = {
    'token': ('classes9.dex', '2b59199af3be4f7836105e82105a37a28037ebb7d86808c3a77582d1299417c4',
              3080236, 100, (3080200, 3080206, 3080212, 3080192)),
    'ca': ('classes4.dex', '31786c6c89e9db8ba78a421cf516fbaf18dd7ae1a630f84cc110f224fff6dfbc',
           9638508, 1032, (9633316, 9633322, 9633328, 9633306)),
    'mac': ('lib/arm64-v8a/libNSaferJNI.so', '35c92e50c49b30291c151f789af7a105524609f114f5e0dcf407aa27243fe0bc',
            468780, 20, ()),
}
CA_SHA256 = 'd6c798f7dc8954fffcea871c7ef78913ac48acc35691064dcd28c5d7ff5a8ffe'
SIGNER_SHA256 = '7bf3140fcb1dea3e38272612b6deac13448a2d84af052a7f59c3f1c92f5d95ce'


def manifest_version(data):
    """Read manifest root attributes from the binary XML string pool."""
    try:
        return _manifest_version(data)
    except (IndexError, KeyError, struct.error, UnicodeError):
        raise ValueError('invalid_manifest') from None


def _manifest_version(data):
    if len(data)<8 or data[:4]!=b'\x03\x00\x08\x00' or struct.unpack_from('<I',data,4)[0]!=len(data):
        raise ValueError('invalid_manifest')
    strings, position = [], 8
    while position + 8 <= len(data):
        kind, header, size = struct.unpack_from('<HHI',data,position)
        if size < header or header < 8 or position+size > len(data):
            raise ValueError('invalid_manifest')
        if kind == 1:
            count, _, flags, start, _ = struct.unpack_from('<IIIII',data,position+8)
            if count > size//4:
                raise ValueError('invalid_manifest_strings')
            def length(offset, utf8):
                value = data[offset] if utf8 else struct.unpack_from('<H',data,offset)[0]
                width, bit = (1,128) if utf8 else (2,32768)
                if value & bit:
                    tail = data[offset+width] if utf8 else struct.unpack_from('<H',data,offset+width)[0]
                    return ((value & (bit-1)) << (8*width)) | tail, offset+2*width
                return value, offset+width
            for i in range(count):
                offset = position+start+struct.unpack_from('<I',data,position+header+i*4)[0]
                units, offset = length(offset,bool(flags&256))
                if flags&256:
                    units, offset = length(offset,True)
                    strings.append(data[offset:offset+units].decode('utf-8'))
                else:
                    strings.append(data[offset:offset+units*2].decode('utf-16-le'))
        elif kind == 0x102:
            extension = position+16
            _, name, first, width, count = struct.unpack_from('<IIHHH',data,extension)
            if strings[name] == 'manifest':
                fields = {}
                for i in range(count):
                    offset = extension+first+i*width
                    _, name, raw, _, _, datatype, value = struct.unpack_from('<IIIHBBI',data,offset)
                    fields[strings[name]] = strings[raw] if raw != 0xffffffff else strings[value] if datatype==3 else value
                if fields.get('package') != 'com.hanabank.oqf' or fields.get('versionName') != VERSION:
                    raise ValueError('unsupported_package_version')
                return str(fields['versionCode'])
        position += size
    raise ValueError('manifest_version_missing')


def rol(value, count):
    value &= 0xffffffff
    return ((value << count) | (value >> (32-count))) & 0xffffffff


def mask(kind, a, b, c, d):
    # Integer overflow and rotations of the versioned string representation.
    if kind == 'token':
        value = rol(-1545092504 + c - a, 23) ^ a
        value = rol(rol(value, 4) ^ b, 10) + c
        value = rol(rol(value, 28), 7) + c
        value = (a ^ (rol(value, 14) + b - c + a - d)) ^ c
        return rol(rol(value, 22) ^ b, 9)
    value = (((-621995359 - c + a) ^ b) + c - a) + b
    value = rol(value, 24)
    value = (rol(value, 15) + c + c - a) ^ d
    value = (b ^ rol(value, 2)) + a - d
    return rol(rol(value, 3), 18)


def extract_value(kind, data):
    _, digest, offset, size, parameters = RECIPES[kind]
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('unsupported_service_data_version: ' + kind)
    raw = data[offset:offset+size]
    if parameters:
        key = mask(kind, *(struct.unpack_from('<i', data, p)[0] for p in parameters)).to_bytes(4, 'little')
        raw = bytes(v ^ key[i % 4] for i, v in enumerate(raw))
    return raw


def length_prefixed(data, position=0):
    if position < 0 or position + 4 > len(data):
        raise ValueError('invalid_signing_block')
    size = struct.unpack_from('<I', data, position)[0]
    end = position + 4 + size
    if end > len(data):
        raise ValueError('invalid_signing_block')
    return data[position+4:end], end


def signer_certificate(path):
    # v2 signing block certificate; input identity is pinned separately below.
    with Path(path).open('rb') as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        tail = stream.read()
        eocd = tail.rfind(b'PK\x05\x06')
        if eocd < 0 or eocd + 22 > len(tail):
            raise ValueError('missing_zip_directory')
        directory = struct.unpack_from('<I', tail, eocd + 16)[0]
        if directory < 24:
            raise ValueError('missing_signing_block')
        stream.seek(directory-24)
        footer = stream.read(24)
        length = struct.unpack_from('<Q', footer)[0]
        if footer[8:] != b'APK Sig Block 42' or not 24 <= length <= min(directory-8, 4*1024*1024):
            raise ValueError('missing_signing_block')
        stream.seek(directory-length-8)
        block = stream.read(length+8)
    if struct.unpack_from('<Q', block)[0] != length:
        raise ValueError('invalid_signing_block')
    position = 8
    while position < len(block)-24:
        entry_size, identity = struct.unpack_from('<QI', block, position)
        if entry_size < 4 or position+8+entry_size > len(block)-24:
            raise ValueError('invalid_signing_block')
        if identity == 0x7109871a:
            signers, _ = length_prefixed(block[position+12:position+8+entry_size])
            signer, _ = length_prefixed(signers)
            signed, _ = length_prefixed(signer)
            _, end = length_prefixed(signed)
            certs, _ = length_prefixed(signed, end)
            certificate, _ = length_prefixed(certs)
            return certificate
        position += 8+entry_size
    raise ValueError('v2_signer_required')


def extract(packages):
    found, provenance, base = {}, [], None
    for path in packages:
        path = storage.no_symlinks(Path(path).expanduser())
        with path.open('rb') as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024*1024), b''):
                digest.update(chunk)
        provenance.append({'file': path.name, 'sha256': digest.hexdigest()})
        with zipfile.ZipFile(path) as archive:
            for kind, (entry, *_) in RECIPES.items():
                matches = [row for row in archive.infolist() if row.filename == entry]
                if not matches:
                    continue
                if kind in found or len(matches) != 1 or matches[0].file_size > 32*1024*1024:
                    raise ValueError('duplicate_or_oversized_service_entry')
                found[kind] = extract_value(kind, archive.read(matches[0]))
                if kind == 'token':
                    base = path
    if set(found) != set(RECIPES):
        raise ValueError('missing_service_entries: ' + ','.join(sorted(set(RECIPES)-set(found))))
    signer = signer_certificate(base)
    with zipfile.ZipFile(base) as archive:
        manifests=[row for row in archive.infolist() if row.filename=='AndroidManifest.xml']
        if len(manifests)!=1 or manifests[0].file_size>4*1024*1024:
            raise ValueError('missing_duplicate_or_oversized_manifest')
        build = manifest_version(archive.read(manifests[0]))
    if hashlib.sha256(signer).hexdigest() != SIGNER_SHA256:
        raise ValueError('unsupported_package_signer')
    ca = base64.b64decode(found['ca'], validate=True)
    x509.load_der_x509_certificate(ca)
    if hashlib.sha256(ca).hexdigest() != CA_SHA256:
        raise ValueError('service_ca_mismatch')
    sms_hash = base64.b64encode(hashlib.sha256(('com.hanabank.oqf '+signer.hex()).encode()).digest()).decode()[:11]
    return {'format': 'finance-hana-settings-v1', 'version': VERSION, 'build_version':build,
            'secure_token': found['token'].decode('utf-8'), 'keypad_mac': base64.b64encode(found['mac']).decode(),
            'ca_certificate': base64.b64encode(ca).decode(), 'sms_hash': sms_hash,
            'sources': provenance}


def install(packages, name):
    store.name(name)
    value = extract(packages)
    directory = store.root('settings')
    for parent in (directory.parents[1],directory.parent,directory):
        storage.directory(parent)
    storage.write_new(directory / (store.name(name)+'.json'), json.dumps(value).encode())
    return {'settings': name, 'version': VERSION, 'extracted': True, 'network_used': False}


def load(name):
    value = storage.read_json(store.root('settings') / (store.name(name)+'.json'))
    if value.get('format') != 'finance-hana-settings-v1' or value.get('version') != VERSION:
        raise ValueError('unsupported_service_settings')
    if len(base64.b64decode(value['keypad_mac'], validate=True)) != 20:
        raise ValueError('invalid_keypad_mac')
    if hashlib.sha256(base64.b64decode(value['ca_certificate'], validate=True)).hexdigest() != CA_SHA256:
        raise ValueError('service_ca_mismatch')
    return value


def configure(name, *, android_sdk, model, width, height, webview_user_agent, timezone):
    from zoneinfo import ZoneInfo
    value = load(name)
    if not (1 <= android_sdk <= 100 and 1 <= width <= 10000 and 1 <= height <= 10000
            and model.strip() and webview_user_agent.strip()):
        raise ValueError('invalid_device_profile')
    ZoneInfo(timezone)
    system = dict.fromkeys(('TMSG_GLOB_ID','RECV_SVC_CD','PROC_RSLT_DV_CD','STD_TMSG_ERR_CD'),'')
    system.update(TRMS_SYS_CD='OQF',RQST_RSPS_DV_CD='Q',TRSC_SYNC_DV_CD='S',LNGG_DV_CD='KR',CHNL_TYP_CD='ESB',FST_TRMS_SYS_CD='OQF')
    channel = {'MBLE_OS':'AOS','OS_VER_NM':str(android_sdk),'TMNL_MDL_NM':model,
        'MBLE_WDTH':str(width),'MBLE_HGHT':str(height),'USR_CHNL_INFO_CTT':webview_user_agent,
        'APP_NM':'OneQFirst','APP_VER_NM':value['version'],'BULD_VER_NM':value['build_version'],'TIME_ZONE_ID':timezone}
    value['service_profile'] = {'system_header':{'CHNL_SYS_HDPT':system},'channel_header':{'CNL_HDPT':channel},
                                 'profile_provenance':{'source':'user-supplied-device-profile'}}
    storage.atomic_json(store.root('settings')/(store.name(name)+'.json'), value)
    return {'settings':name,'configured':True,'network_used':False}
