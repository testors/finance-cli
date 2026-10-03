"""Login methods and signing purposes each institution adapter supports.

Only methods listed here can be configured or shown as runnable. Adding a bank
or channel means adding its adapter first; profile types never decide these.
"""

INSTITUTIONS = {
    'giro': {
        'name': '모바일지로',
        'methods': {'pin': {'name': '간편비밀번호 6자리', 'credential': None, 'registration': ()}},
        'purposes': {'login': ('pin',)},
        'channels': (None,),
        'target_kinds': (),
    },
    'hometax': {
        'name': '홈택스',
        'methods': {
            'joint_certificate': {'name': '공동인증서', 'credential': 'joint', 'registration': ()},
        },
        'purposes': {'login': ('joint_certificate',), 'invoice_sign': ('joint_certificate',)},
        'channels': (None,),
        'target_kinds': ('personal', 'business'),
    },
    'hana': {
        'name': '하나개인뱅킹',
        'methods': {
            'joint_certificate': {'name': '공동인증서', 'credential': 'joint',
                                  'registration': ('app_profile', 'login_input')},
            'onesign': {'name': '하나인증서', 'credential': 'onesign', 'registration': ('onesign_settings',)},
        },
        'purposes': {'login': ('joint_certificate', 'onesign'), 'transfer_sign': ('onesign',)},
        'channels': (None, 'personal'),
        'target_kinds': ('account',),
    },
    'hana_corporate': {
        'name': '하나기업뱅킹',
        'methods': {
            'id_password': {'name': '기업 ID/PW', 'credential': 'id_password', 'registration': ()},
            'joint_certificate': {'name': '공동인증서', 'credential': 'joint', 'registration': ()},
            'onesign': {'name': '하나인증서 (개인사업자)', 'credential': 'onesign', 'registration': ()},
        },
        'purposes': {'login': ('id_password', 'joint_certificate', 'onesign'),
                     'transfer_sign': ('joint_certificate',)},
        'channels': (None, 'corporate'),
        'target_kinds': ('account',),
    },
}

PURPOSES = ('login', 'transfer_sign', 'invoice_sign')


def institution(value):
    if value not in INSTITUTIONS:
        raise ValueError('unsupported_institution')
    return INSTITUTIONS[value]


def auth_options(value, method=None):
    spec = institution(value)
    rows = []
    for purpose, methods in spec['purposes'].items():
        for key in methods:
            item = spec['methods'][key]
            rows.append({'purpose': purpose, 'method': key, 'name': item['name'],
                         'credential_type': item['credential'], 'registration': list(item['registration']),
                         'selected_login_method': method == key if purpose == 'login' else None})
    return {'institution': value, 'name': spec['name'], 'options': rows,
            'channels': [c for c in spec['channels'] if c], 'automatic_fallback': False}
