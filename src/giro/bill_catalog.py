"""Read-only bill services and their user-facing input contracts."""

PAYMENT_TYPES = ('national', 'local', 'customs')
LABELS = dict(national='국세', local='지방세', customs='관세', env='환경개선부담금',
    nontax='세외수입', traffic='경찰청범칙금', penalty='법무부국고금', patent='특허수수료',
    marine='항만수수료', fund='기금 및 기타국고', water='상하수도요금', social='통합사회보험료',
    annuity='국민연금 반납금·추납보험료', employ='고용보험 연납·분기납',
    industry='산재보험 연납·분기납', kepco='전기요금', ktcomm='KT 통신요금', tv='TV수신료', giro='일반지로')
BILL_TYPES = tuple(LABELS)
OWN_TYPES = ('national', 'local', 'customs', 'env', 'nontax', 'traffic', 'penalty', 'patent', 'marine', 'fund')
REGION_TYPES = ('local', 'env', 'nontax')
SIMPLE_TYPES = ('social', 'annuity', 'kepco', 'ktcomm', 'tv')
INPUTS = {kind: () for kind in OWN_TYPES}
INPUTS.update(water=('elec_water_no',), social=('number',), annuity=('number',),
    employ=('insure_no',), industry=('insure_no',), kepco=('number',),
    ktcomm=('number',), tv=('number',), giro=('giro_no', 'number'))
INPUT_LABELS = dict(number='전자납부번호·고객번호', elec_water_no='전자수용가번호',
    manage_no='상하수도 고객관리번호', insure_no='보험관리번호', giro_no='지로번호',
    area_code='시도 코드', district_code='지자체 구분 코드', district_giro_no='지자체 지로번호')
SUMMARY_KEYS = dict(local='localtax', env='env', nontax='nontax', national='nts', customs='tariff',
    traffic='traffic', penalty='penalty', patent='patent', marine='maritime', fund='fund')

# name -> (service-relative URL, allowed request fields). Authentication and
# payment routes never enter this read-only catalog.
QUERY_ROUTES = {}
for kind, directory, prefix in (
    ('env', 'localtax/env', 'Env'), ('nontax', 'localtax/nontax', 'Nontax'),
    ('traffic', 'ntax/traffic', 'Traffic'), ('penalty', 'ntax/penalty', 'Penalty'),
    ('patent', 'ntax/patent', 'Patent'), ('marine', 'ntax/marine', 'Marine'),
    ('fund', 'ntax/fund', 'Fund'), ('water', 'localtax/water', 'Water'),
    ('employ', 'insure/employ/search', 'Employ'), ('industry', 'insure/industry/search', 'Industry'),
):
    fields = ('page', 'pageSize')
    if kind in OWN_TYPES:
        fields += ('useUIDInfoYn', 'agreeUIDInfoSaveYn', 'showUIDInfoNoticeYn')
    if kind in REGION_TYPES or kind == 'water': fields += ('sortCode', 'giroNo')
    if kind == 'nontax': fields += ('tongYn',)
    if kind == 'water': fields += ('elecWaterNo', 'manageNo')
    if kind in ('employ', 'industry'): fields += ('insureNo',)
    QUERY_ROUTES[kind+'.list'] = (f'{directory}/m{prefix}QryBillList.m', fields)
    QUERY_ROUTES[kind+'.detail'] = (f'{directory}/m{prefix}QryBillDetail.m',
        ('sortCode', 'giroNo', 'elecNo') + (('tongYn',) if kind == 'nontax' else ()))
    if kind in REGION_TYPES:
        defaults = ('tongYn',) if kind == 'nontax' else ()
        QUERY_ROUTES[kind+'.provinces'] = (f'{directory}/m{prefix}SelectProvince.m', defaults)
        QUERY_ROUTES[kind+'.districts'] = (f'{directory}/m{prefix}SelectDistrict.m', ('areaCode',) + defaults)
for kind, directory, prefix in (
    ('social', 'insure/social', 'SocialInsure'), ('annuity', 'insure/annuity', 'Annuity'),
    ('kepco', 'life/kepco', 'Kepco'), ('tv', 'life/kepco', 'Kepco'), ('ktcomm', 'life/ktcomm', 'Ktcomm'),
):
    QUERY_ROUTES[kind+'.list'] = (f'{directory}/m{prefix}QrySimple.m',
        ('elecNo',) + (('searchType', 'agreeUIDInfoSaveYn', 'showUIDInfoNoticeYn') if kind == 'annuity' else ()))
    QUERY_ROUTES[kind+'.detail'] = (f'{directory}/m{prefix}QryDetail.m',
        ('sortCode', 'giroNo', 'key') + (('customerNo', 'elecNo') if kind in ('social', 'annuity') else ()))
QUERY_ROUTES.update({
    'giro.lookup': ('giro/search/mGiroQryGiroNo.m', ('giroNo',)),
    'giro.list': ('giro/search/mGiroQryGiroSimpleSearch.m', ('giroNo', 'elecNo', 'page')),
    'giro.detail': ('giro/search/mGiroQryGiroDetailSearch.m', ('sortCode', 'giroNo', 'key')),
    'integrated.initialize': ('integrated/mIntegratedInsSearchKey.m', ()),
    'integrated.summary': ('integrated/mIntegratedQrySimple.m', ('juminNo', 'useUIDInfoYn')),
})


def catalog():
    return {'types': [dict(type=kind, label=label, inputs=INPUTS[kind],
        own_identity=kind in OWN_TYPES, payment_supported=kind in PAYMENT_TYPES,
        verification='live_partial' if kind in PAYMENT_TYPES else 'implemented_live_untested')
        for kind, label in LABELS.items()],
        'direct_input_only': ['인지대·송달료', '조회납부를 지원하지 않는 일반지로'],
        'network_used': False}
