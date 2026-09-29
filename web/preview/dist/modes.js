/* Navigation and synthetic records for the three Finance workspaces. */
const workspaces = {
  banking: {name:'뱅킹',service:'하나은행',home:'accounts',icon:'accounts',items:[
    ['accounts','내 계좌','계좌','accounts'],['history','거래 내역','거래','history'],
    ['transfer','이체','이체','transfer'],['inquiry','이체 내역','이체 내역','history'],
    ['security','보안매체·한도','보안','shield']]},
  giro: {name:'지로',service:'모바일지로',home:'bills',icon:'bill',items:[
    ['bills','고지서 자료','고지서','bill'],['deadlines','납부 기한','기한','calendar'],
    ['girostatus','연결 준비','연결','shield'],['giro-live','실시간 고지 조회','실시간 조회','refresh',false],['giro-pay','지로 납부','납부','transfer',false]]},
  tax: {name:'세금',service:'홈택스',home:'taxhome',icon:'tax',items:[
    ['taxhome','세금 요약','요약','tax'],['invoices','전자세금계산서','계산서','invoice'],
    ['returns','신고 내역','신고 내역','history'],['dues','납부할 세액','납부할 세액','accounts'],
    ['payments','납부 내역','납부 내역','check'],['refunds','환급금','환급금','transfer'],
    ['notices','전자고지','전자고지','bill'],['reports','보고서·접수증','보고서','report'],
    ['tax-file','세금 신고','신고','invoice',false],['tax-pay','세금 납부','납부','transfer',false]]}
};
const sharedNavigation = [
  {id:'activity',name:'전체 작업 기록',short:'작업',icon:'activity'},
  {id:'settings',name:'연결·인증서',short:'설정',icon:'shield'},
  {id:'coverage',name:'전체 기능·지원 상태',short:'전체 기능',icon:'grid'}
];
const workspaceNavigation = key => workspaces[key].items.map(([id,name,short,icon,available=true])=>({id,name,short,icon,available}));
const navigationForAll = () => [...Object.keys(workspaces).flatMap(workspaceNavigation),...sharedNavigation];
function modeControls() {
  return `<button class="workspace-switch" data-ui="choose-mode" aria-label="업무 영역 변경: ${workspaces[state.mode].name}" aria-haspopup="dialog"><span class="workspace-icon">${icon(workspaces[state.mode].icon)}</span><span><strong>${workspaces[state.mode].name}</strong><small>${workspaces[state.mode].service}</small></span>${icon('chevrons')}</button>`;
}
function chooseMode() {
  showDialog('어떤 업무를 볼까요?', `<div class="mode-options">${Object.entries(workspaces).map(([key,mode])=>`<button data-mode="${key}" class="mode-option ${key===state.mode?'selected':''}"><span class="workspace-icon">${icon(mode.icon)}</span><span><strong>${mode.name}</strong><small>${mode.service}${key==='giro'?' · 자료 해석 지원':''}</small></span>${key===state.mode?icon('check'):icon('arrow')}</button>`).join('')}</div><p class="dialog-note">영역을 바꿔도 각 영역에서 보던 화면을 유지해요.</p>`);
}
function changeMode(mode) {
  if(!workspaces[mode]) return;
  if(!sharedNavigation.some(item=>item.id===state.view)) state.lastViews[state.mode]=state.view;
  state.mode=mode;
  if(dialog.open) dialog.close();
  changeView(state.lastViews[mode]||workspaces[mode].home);
}
function moreMenu() {
  showDialog(`${workspaces[state.mode].name} 메뉴`, `<div class="menu-sheet">${navigation.map(item=>`<button ${item.available?'data-view="'+item.id+'"':'disabled aria-disabled="true"'}>${icon(item.icon)}${item.name}${item.available?icon('arrow'):'<span class="soon-label">준비 중</span>'}</button>`).join('')}<hr>${sharedNavigation.map(item=>`<button data-view="${item.id}">${icon(item.icon)}${item.name}${icon('arrow')}</button>`).join('')}</div>`);
}
function refreshAction() { return button('새로 조회','refresh','secondary','refresh'); }
function openView(label,view,primary=false) { return `<button class="button ${primary?'primary':'secondary'}" data-view="${view}">${label}${icon('arrow')}</button>`; }
function demoAction(label,action,primary=false) { return `<button type="button" class="button ${primary?'primary':'secondary'}" data-ui="${action}">${label}</button>`; }
function tag(text,warning=false) { return `<span class="status-pill ${warning?'warning':''}">${text}</span>`; }
function infoNote(text) { return `<div class="scope-note">${icon('info')}<p>${text}</p></div>`; }
function metric(label,value,detail,view) { return `<button class="panel metric" data-view="${view}"><span>${label}</span><strong class="number">${value}</strong><small>${detail}${icon('arrow')}</small></button>`; }
function contextPicker() {
  if(state.mode!=='tax'||sharedNavigation.some(item=>item.id===state.view)) return '';
  return `<div class="business-context"><div>${icon('business')}<span>조회 대상</span><label class="sr-only" for="business-context">홈택스 사용자·사업장 선택</label><select id="business-context"><option value="studio" ${state.business==='studio'?'selected':''}>예시 스튜디오 · 계속사업자</option><option value="personal" ${state.business==='personal'?'selected':''}>개인</option></select></div><button class="text-button" data-ui="business-info">사용자·사업장 정보 ${icon('arrow')}</button></div>`;
}
const businessName = () => state.business==='personal'?'개인':'예시 스튜디오';
const taxRecords = {
  dues:[{id:'d1',title:'부가가치세',date:'2026.10.26',meta:'2026년 2기 예정 · 예시',amount:340000,status:'납부할 세액'},{id:'d2',title:'원천세',date:'2026.10.12',meta:'2026년 9월 · 예시',amount:72000,status:'납부할 세액'}],
  payments:[{id:'p1',title:'원천세',date:'2026.09.10',meta:'홈택스 · 예시 납부 기록',amount:72000,status:'납부 완료'},{id:'p2',title:'부가가치세',date:'2026.07.27',meta:'홈택스 · 예시 납부 기록',amount:286000,status:'납부 완료'}],
  refunds:[{id:'r1',title:'부가가치세 환급금',date:'2026.09.18',meta:'2026년 · 예시 환급 기록',amount:84000,status:'미수령'},{id:'r2',title:'국세 환급금',date:'2026.06.30',meta:'2026년 · 예시 환급 기록',amount:46000,status:'지급 완료'}],
  notices:[{id:'n1',title:'부가가치세 전자고지',date:'2026.09.28',meta:'고지서 · 납부 기한 2026.10.26 · 예시',amount:340000,status:'미열람'},{id:'n2',title:'원천세 전자고지',date:'2026.09.09',meta:'고지서 · 예시',amount:72000,status:'열람'}]
};
const personalRecords = {
  dues:[{id:'pd1',title:'종합소득세',date:'2026.10.26',meta:'개인 · 예시 세액',amount:120000,status:'납부할 세액'}],
  payments:[{id:'pp1',title:'종합소득세',date:'2026.06.01',meta:'개인 · 예시 납부 기록',amount:210000,status:'납부 완료'}],
  refunds:[{id:'pr1',title:'종합소득세 환급금',date:'2026.09.18',meta:'개인 · 예시 환급 기록',amount:36000,status:'미수령'}],
  notices:[{id:'pn1',title:'종합소득세 전자고지',date:'2026.09.28',meta:'개인 · 예시 고지서',amount:120000,status:'미열람'}]
};
function taxRows(view) { return (state.business==='personal'?personalRecords:taxRecords)[view]||[]; }
const taxLabels={dues:'납부할 세액',payments:'납부 내역',refunds:'환급금',notices:'전자고지'};
function recordList(items,group) {
  return `<div class="record-list">${items.map(item=>`<button class="record-row" data-record="${group}:${item.id}"><span class="record-icon">${icon(group==='refunds'?'transfer':'bill')}</span><span class="record-main"><strong>${item.title}</strong><small>${item.meta}</small><time>${item.date}</time></span><span class="record-value"><strong class="number">${money(item.amount)}<small>원</small></strong>${tag(item.status,item.status==='미수령'||item.status==='미열람')}</span>${icon('arrow')}</button>`).join('')}</div>`;
}
function taxHomeView() {
  const dues=taxRows('dues').reduce((sum,item)=>sum+item.amount,0);
  const refunds=taxRows('refunds').filter(item=>item.status==='미수령').reduce((sum,item)=>sum+item.amount,0);
  return heading('세금 요약',`${businessName()}의 세금과 증빙을 한곳에서 확인하세요.`,refreshAction())+
    `<div class="metric-grid">${metric('납부할 세액',money(dues)+'원','납부 대상 '+taxRows('dues').length+'건','dues')}${metric('미수령 환급금',money(refunds)+'원','환급 내역 확인','refunds')}${metric('전자세금계산서','3건','이번 달 매출 · 예시','invoices')}</div>`+
    `<div class="workspace-grid tax-workspace"><section class="panel"><div class="panel-heading"><div><h2>확인할 세금</h2><p class="meta">예시 고지 내용</p></div><button class="text-button" data-view="notices">전자고지 ${icon('arrow')}</button></div>${recordList(taxRows('dues'),'dues')}</section><div class="tax-shortcuts"><section class="panel quick-transfer"><h2>전자세금계산서</h2><p>작성한 내용을 확인한 뒤 발급해요.</p>${demoAction('새 계산서 작성','invoice-new',true)}${openView('매출·매입 조회','invoices')}</section><section class="panel quick-transfer"><h2>신고 자료</h2><p>신고 내역과 접수증을 확인하세요.</p>${openView('신고 내역 보기','returns')}</section></div></div>`;
}
function taxListView(view) {
  const filter=state.taxFilters?.[view]||{from:'2026-01-01',to:'2026-09-30',status:'전체 상태'};
  const entries=taxRows(view).filter(item=>view==='dues'||((!filter.from||item.date.replaceAll('.','-')>=filter.from)&&(!filter.to||item.date.replaceAll('.','-')<=filter.to)&&(filter.status==='전체 상태'||item.status===filter.status)));
  return heading(taxLabels[view],`${businessName()} · 홈택스 조회`,refreshAction())+
    (view==='dues'?infoNote('현재 지원 범위는 납부할 세액 조회입니다. 세금 납부 실행 기능은 아직 지원하지 않아요.'):'')+
    `<section class="panel"><div class="panel-heading"><h2>${taxLabels[view]} <span class="count">${entries.length}</span></h2>${tag('예시 자료')}</div>${view==='dues'?'':`<form class="filter-bar" data-filter="tax"><label>조회 기간<input type="date" name="from" aria-label="조회 시작일" value="${filter.from}"></label><span>—</span><label class="sr-only" for="tax-end">조회 종료일</label><input id="tax-end" name="to" type="date" value="${filter.to}">${view==='refunds'?`<select name="status" aria-label="환급 상태">${['전체 상태','미수령','지급 완료'].map(value=>`<option ${filter.status===value?'selected':''}>${value}</option>`).join('')}</select>`:''}<button class="button secondary">조회</button></form>`}${entries.length?recordList(entries,view):'<div class="empty-state">조건에 맞는 예시 내역이 없어요.</div>'}<div class="list-footer">${entries.length}건 · 마지막 페이지</div></section>`;
}
const returnRecords=[{id:'ret1',title:'2026년 1기 부가가치세',date:'2026.07.24',meta:'정기 신고 · 신고서 외 2개 서식',status:'접수 완료'},{id:'ret2',title:'2026년 8월 원천세',date:'2026.09.09',meta:'정기 신고 · 원천징수이행상황신고서',status:'접수 완료'}];
function returnsView() {
  const entries=state.business==='personal'?[{id:'ret3',title:'2025년 귀속 종합소득세',date:'2026.06.01',meta:'정기 신고 · 신고서 외 3개 서식',status:'접수 완료'}]:returnRecords;
  return heading('신고 내역','접수 결과·제출서식·신고서를 확인하세요.',refreshAction())+infoNote('제출된 신고의 조회 화면입니다. 새 세금 신고를 제출하는 기능은 아직 지원하지 않아요.')+
  `<section class="panel"><div class="panel-heading"><h2>${businessName()} 신고 내역</h2>${tag('2026년 · 예시')}</div><div class="document-list">${entries.map(item=>`<article class="document-row"><span class="record-icon">${icon('report')}</span><div class="record-main"><h3>${item.title}</h3><p>${item.date} · ${item.meta}</p></div>${tag(item.status)}<div class="row-actions"><button class="button secondary" data-return="${item.id}">서식·접수 결과</button><button class="text-button" data-report="receipt">접수증</button><button class="text-button" data-report="return">신고서</button></div></article>`).join('')}</div></section>`;
}
function reportsView() {
  return heading('보고서·접수증','저장한 문서의 내용과 완전성 상태를 확인하세요.',demoAction('예시 보고서 저장','report-capture'))+
    `<section class="panel"><div class="document-list">${[['receipt','부가가치세 신고 접수증','2026.07.24','완전'],['return','부가가치세 신고서','2026.07.24','완전'],['review','신고 부속서류','2026.07.24','확인 필요']].map(([id,title,date,status])=>`<article class="document-row"><span class="record-icon">${icon('report')}</span><div class="record-main"><h3>${title}</h3><p>${date} · 독립 HTML · 예시 문서</p></div>${tag(status,status==='확인 필요')}<div class="row-actions"><button class="button secondary" data-report="${id}">보기</button><button class="text-button" data-download="report">예시 HTML 저장</button></div></article>`).join('')}</div></section>`;
}
const invoiceRecords=[{id:'inv1',name:'예시 디자인',date:'2026.09.30',item:'디자인 용역',supply:500000,tax:50000},{id:'inv2',name:'예시 파트너스',date:'2026.09.23',item:'유지보수',supply:800000,tax:80000},{id:'inv3',name:'예시 컴퍼니',date:'2026.09.10',item:'제작 용역',supply:1200000,tax:120000}];
function invoicesView() {
  const entries=state.invoiceDirection==='sales'?invoiceRecords:[{id:'buy1',name:'예시 문구',date:'2026.09.20',item:'사무용품',supply:80000,tax:8000}];
  return heading('전자세금계산서',`${businessName()} · 조회, 초안 작성, 수정 발급`,demoAction('새 계산서 작성','invoice-new',true))+
    `<section class="panel"><div class="panel-heading"><div class="segmented" aria-label="계산서 구분">${[['sales','매출'],['purchases','매입']].map(([key,name])=>`<button data-direction="${key}" class="${state.invoiceDirection===key?'active':''}" aria-pressed="${state.invoiceDirection===key}">${name}</button>`).join('')}</div><span class="muted">2026.09.01 — 09.30</span></div><div class="document-list">${entries.map(item=>`<article class="document-row"><span class="record-icon">${icon('invoice')}</span><div class="record-main"><h3>${item.name}</h3><p>${item.date} · ${item.item}</p></div><div class="record-value"><strong class="number">${money(item.supply+item.tax)}원</strong>${tag('발급 완료 · 예시')}</div><div class="row-actions"><button class="button secondary" data-invoice="${item.id}">상세</button>${state.invoiceDirection==='sales'?`<button class="text-button" data-amend="${item.id}">수정 계산서</button>`:''}</div></article>`).join('')}</div><div class="list-footer">${entries.length}건 · 마지막 페이지</div></section>`+
    infoNote('계산서 발급은 초안 확인과 별도 단계입니다. 이 시안의 발급·수정 버튼은 예시 결과만 보여줍니다.');
}
function invoiceFormView() {
  const draft=state.invoiceDraft;
  return heading(draft.amend?'수정 계산서 작성':'전자세금계산서 작성','일반 과세 · 사업자 간 거래 · 예시 초안',openView('목록으로','invoices'))+
  `<form class="panel invoice-form" id="invoice-form"><div class="form-section"><h2>거래처</h2><div class="two-fields"><div class="field"><label for="invoice-supplier">공급자</label><input id="invoice-supplier" value="${escapeHtml(businessName())}" readonly></div><div class="field"><label for="invoice-buyer">공급받는 자</label><input id="invoice-buyer" name="buyer" required value="${escapeHtml(draft.name||'예시 디자인')}" maxlength="80"></div></div><p class="field-help">시안용 거래처입니다. 실제 사업자번호·인증 정보는 필요하지 않아요.</p></div>${draft.amend?`<div class="field"><label for="amend-reason">수정 사유</label><select id="amend-reason" name="reason">${['기재사항 착오정정','공급가액 변동','환입','계약의 해제','내국신용장 사후개설','착오에 의한 이중발급'].map((text,index)=>`<option value="${index}">${text}</option>`).join('')}</select></div>`:''}<div class="form-section"><h2>공급 내용</h2><div class="two-fields"><div class="field"><label for="invoice-date">작성일</label><input id="invoice-date" type="date" name="date" value="2026-09-30" required></div><div class="field"><label for="invoice-item">품목</label><input id="invoice-item" name="item" value="${escapeHtml(draft.item||'디자인 용역')}" required maxlength="80"></div><div class="field"><label for="invoice-supply">공급가액</label><input id="invoice-supply" name="supply" inputmode="numeric" type="number" step="1" min="0" max="9999999999" value="${draft.supply||500000}" required></div><div class="field"><label for="invoice-tax">세액</label><input id="invoice-tax" name="tax" inputmode="numeric" type="number" step="1" min="0" max="9999999999" value="${draft.tax||50000}" required></div></div></div><div class="field"><label for="invoice-settlement">청구·영수</label><select id="invoice-settlement" name="settlement"><option>청구</option><option>영수</option></select></div><div class="form-actions"><button class="button primary" type="submit">초안 확인 ${icon('arrow')}</button><p class="field-help">다음 화면에서 내용을 확인합니다. 실제 발급은 실행하지 않아요.</p></div></form>`;
}
const giroRecords=[{id:'g1',title:'국세 고지 자료',date:'2026.10.26',meta:'국세 · 예시 자료 A',amount:340000,status:'기한 전'},{id:'g2',title:'지방세 고지 자료',date:'2026.09.30',meta:'지방세 · 예시 자료 B',amount:180000,status:'오늘 마감'},{id:'g3',title:'일반지로 고지 자료',date:'2026.09.25',meta:'일반지로 · 예시 자료 C',amount:24000,status:'기한 경과'}];
function giroBillsView(deadlines=false) {
  return heading(deadlines?'납부 기한':'고지서 자료',deadlines?'자료에 적힌 납부 기한을 기준일과 비교해요.':'확보해 둔 고지 자료를 읽고 항목을 확인해요.',demoAction('예시 자료 불러오기','giro-import'))+
  infoNote('모바일지로는 현재 자료 해석만 지원합니다. 실시간 고지 조회, 로그인, 납부 실행은 아직 연결되지 않았어요.')+
  (deadlines?`<div class="metric-grid">${metric('오늘 마감','1건','기준일 2026.09.30 · 예시','deadlines')}${metric('기한 전','1건','고지서에 적힌 일자 기준','bills')}${metric('기한 경과','1건','실제 납부 여부는 미확인','bills')}</div>`:'')+
  `<section class="panel"><div class="panel-heading"><h2>${deadlines?'기한순 자료':'불러온 예시 자료'}</h2>${tag('실시간 조회 아님',true)}</div>${recordList(deadlines?[...giroRecords].sort((a,b)=>a.date.localeCompare(b.date)):giroRecords,'giro')}<div class="list-footer">자료에 없는 상태나 납부 완료 여부는 추정하지 않습니다.</div></section>`;
}
function giroStatusView() {
  return heading('지로 연결 준비','현재 지원하는 기능과 남은 연결 단계를 확인하세요.')+
  `<section class="panel"><div class="panel-heading"><h2>모바일지로 지원 상태</h2>${tag('로그인 미지원',true)}</div><div class="settings-body">${[['고지서 항목·납기 해석','로컬 자료 해석 지원'],['인증·조회 요청 계획','오프라인 준비 지원'],['인증서·암호 처리 점검','로컬 도구 지원'],['초기 연결 점검','초기 연결 확인만 지원'],['실제 로그인·실시간 조회·납부','아직 미지원']].map(([label,value])=>`<div class="setting-row"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div></section>`+`<div class="section-actions">${demoAction('요청 준비 예시','giro-plan')}${demoAction('초기 점검 설명','giro-probe')}${openView('전체 지원 상태','coverage')}</div>`;
}
function inquiryView() {
  return heading('이체 내역','완료된 이체와 처리 결과를 확인하세요.',refreshAction())+
  `<section class="panel"><div class="panel-heading"><h2>최근 이체</h2><span class="muted">2026년 9월</span></div>${recordList([{id:'tr1',title:'김하나',date:'2026.09.26',meta:'생활비 통장 → 하나은행 · 예시',amount:800000,status:'이체 완료'}],'inquiry')}</section>`;
}
function securityView() {
  return heading('보안매체·한도','등록된 보안매체와 한도 상태를 조회하세요.',refreshAction())+
  `<div class="settings-grid">${[['이체한도',['1회 한도','10,000,000원'],['1일 한도','50,000,000원'],['한도 예외','없음 · 예시']],['보안매체',['인증 수단','하나인증서'],['물리 OTP','등록 상태 예시'],['OTP 사고 신고','없음 · 예시'],['모바일 OTP','미등록 · 예시']]].map(([title,...rows])=>`<section class="panel"><div class="panel-heading"><h2>${title}</h2>${tag('예시 상태')}</div><div class="settings-body">${rows.map(([label,value])=>`<div class="setting-row"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div></section>`).join('')}</div>`+infoNote('한도와 보안매체의 상태를 조회하는 화면입니다. OTP 발급이나 한도 변경 기능은 제공하지 않아요.');
}
const capabilityGroups=[
  {title:'뱅킹 · 하나은행',rows:[['계좌·잔액·거래 내역·내보내기','accounts','웹 업무'],['이체 내역·상세','inquiry','웹 업무'],['원화 이체 준비·확인·실행·결과 조회','transfer','웹 업무'],['보안매체·한도 조회','security','웹 업무'],['앱·공동인증서·하나인증서 로그인·세션 연장','settings','공통 설정'],['하나인증서 신규 발급·번들 이전·설정 추출','local','서버에서 관리'],['인증 순서·서명·전문 인코딩 도구','local','로컬 도구']]},
  {title:'세금 · 홈택스',rows:[['인증서 로그인·세션 확인·갱신','settings','공통 설정'],['사용자 정보·사업장 목록·선택','taxhome','웹 업무'],['납부할 세액·납부 내역·환급금·전자고지','dues','웹 업무'],['신고 내역·접수 결과·제출서식','returns','웹 업무'],['접수증·신고서·보고서 저장','reports','웹 업무'],['계산서 매출·매입 조회·상세','invoices','웹 업무'],['계산서 초안·수정 초안·발급','invoices','웹 업무'],['인증 응답 처리·서명 준비','local','로컬 도구'],['새 세금 신고·세금 납부','planned','준비 중']]},
  {title:'지로 · 모바일지로',rows:[['고지서 자료·납부 기한 해석','bills','자료 해석'],['인증·조회 요청 계획','girostatus','오프라인 준비'],['실행 환경·인증서·인증 처리 점검','local','로컬 도구'],['초기 연결 점검','girostatus','초기 연결만'],['실제 로그인·실시간 조회·납부','planned','준비 중']]},
  {title:'공통 · 인증서와 운영',rows:[['공동인증서 목록·정보·프로필 선택','settings','공통 설정'],['NPKI·PFX 가져오기·내보내기','local','서버에서 관리'],['금융인증서 암호 연산','local','라이브러리만'],['런타임 상태·설치·데이터 경로','local','서버에서 관리'],['영역별 작업 진행·기록·결과','activity','공통 기능']]}
];
function coverageView() {
  return heading('전체 기능·지원 상태','finance-cli의 기능을 업무·공통 설정·서버 관리에 나누어 연결합니다.')+
  infoNote('모든 화면은 가상 데이터 시안입니다. 아래 표는 현재 CLI의 구현 범위를 나타내며, 웹에서 실제 업무를 실행할 수 있다는 뜻은 아니에요.')+
  `<div class="capability-grid">${capabilityGroups.map(group=>`<section class="panel"><div class="panel-heading"><h2>${group.title}</h2></div><div class="capability-list">${group.rows.map(([label,view,status])=>`<button ${view==='planned'?'disabled aria-disabled="true"':view==='local'?'data-ui="local-tools"':`data-view="${view}"`}><span>${label}</span>${tag(status,status==='미지원'||status==='서버에서 관리')}${icon('arrow')}</button>`).join('')}</div></section>`).join('')}</div>`;
}
function allActivityView() {
  const jobs=[['tax','납부할 세액 조회','홈택스 · 예시 스튜디오 · 웹','완료','10:32'],['banking','계좌 잔액 조회','하나은행 · 개인 · 웹','완료','10:30'],['giro','고지서 납기 해석','지로 · 예시 자료 · 에이전트','완료','09:20'],['tax','신고서 저장','홈택스 · 예시 스튜디오 · 에이전트','확인 필요','09:00'],['banking','김하나님에게 이체','하나은행 · 예시 작업 · 웹','결과 미확인','어제']];
  return heading('전체 작업 기록','뱅킹·지로·세금의 작업과 결과를 함께 확인하세요.')+
  `<section class="panel"><div class="panel-heading"><h2>최근 작업</h2>${tag('예시 기록')}</div><ul class="operation-list">${jobs.map(([mode,title,desc,status,time])=>`<li class="operation-row"><span class="workspace-icon small">${icon(workspaces[mode].icon)}</span><div class="operation-body"><h3>${title}</h3><p>${desc} · ${time}</p></div>${tag(status,status!=='완료')}${status==='결과 미확인'?button('결과 확인','check-result'):status==='확인 필요'?'<button class="text-button" data-report="review">문서 확인</button>':''}</li>`).join('')}</ul></section>`;
}
function allSettingsView() {
  return heading('연결·인증서','공통 인증서를 선택하고 기관별 접속 상태를 확인하세요.')+
  `<div class="settings-grid"><section class="panel"><div class="panel-heading"><h2>기관별 연결</h2>${tag('예시 상태')}</div><div class="settings-body">${[['하나은행','하나인증서 · 개인','로그인 연장','bank-login'],['홈택스','공동인증서 · '+businessName(),'세션 확인·갱신','tax-login'],['모바일지로','자료 해석만 지원','지원 상태','giro-status']].map(([name,desc,action,key])=>`<div class="setting-row"><div><strong>${name}</strong><p class="field-help">${desc}</p></div>${demoAction(action,key)}</div>`).join('')}</div></section><section class="panel"><div class="panel-heading"><h2>인증서·프로필</h2><button class="text-button" data-ui="certificate-list">목록 보기</button></div><div class="settings-body"><div class="setting-row"><span>개인 프로필</span><strong>하나인증서 · 예시</strong></div><div class="setting-row"><label for="tax-certificate">세금 프로필</label><select id="tax-certificate" aria-label="세금 프로필 인증서"><option>사업자 공동인증서 · 예시</option><option>개인 공동인증서 · 예시</option></select></div><div class="setting-row"><span>인증서 정보</span><button class="text-button" data-ui="certificate-list">만료일·용도 확인</button></div><p class="field-help">발급·가져오기·내보내기는 서버 관리 범위로 유지합니다.</p></div></section><section class="panel"><div class="panel-heading"><h2>웹앱 접속</h2></div><div class="settings-body"><div class="setting-row"><span>현재 브라우저</span>${tag('사용 중 · 예시')}</div><div class="setting-row"><span>Android 휴대폰</span>${button('접속 해제','revoke')}</div></div></section><section class="panel"><div class="panel-heading"><h2>지원 기능</h2></div><div class="settings-body"><p class="field-help">업무 기능과 서버에서 관리할 기능의 전체 범위를 확인하세요.</p><div class="section-actions">${openView('전체 기능 보기','coverage')}</div></div></section></div>`;
}
const expandedViews={taxhome:taxHomeView,dues:()=>taxListView('dues'),payments:()=>taxListView('payments'),refunds:()=>taxListView('refunds'),notices:()=>taxListView('notices'),returns:returnsView,reports:reportsView,invoices:invoicesView,invoiceform:invoiceFormView,bills:()=>giroBillsView(),deadlines:()=>giroBillsView(true),girostatus:giroStatusView,inquiry:inquiryView,security:securityView,coverage:coverageView,activity:allActivityView,settings:allSettingsView};
