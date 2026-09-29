/* UI-only examples. No institution requests or persistent storage. */
function showReport(kind) {
  const title=kind==='receipt'?'신고 접수증':kind==='review'?'신고 부속서류':'신고서';
  showDialog(title, `<div class="sample-document"><span class="document-watermark">SAMPLE</span><p class="eyebrow">예시 문서 · 실제 증빙 아님</p><h3>${title}</h3><dl><div><dt>납세자</dt><dd>${escapeHtml(businessName())}</dd></div><div><dt>세목</dt><dd>${state.business==='personal'?'종합소득세':'부가가치세'}</dd></div><div><dt>접수일</dt><dd>2026.07.24 · 예시</dd></div><div><dt>문서 상태</dt><dd>${kind==='review'?'확인 필요':'완전 · 예시'}</dd></div></dl>${kind==='review'?'<p class="document-warning">예시: 일부 이미지가 누락되어 저장 문서의 확인이 필요합니다. 신고 접수 결과와 문서 저장 상태는 별도로 표시합니다.</p>':'<p>이 문서는 보고서 미리보기의 배치와 저장 흐름을 검토하기 위한 가상 자료입니다.</p>'}</div><div class="dialog-actions">${button('닫기','close')}<button class="button primary" data-download="report">예시 HTML 저장</button></div>`);
}
function downloadExample(kind) {
  const report='<!doctype html><html lang="ko"><meta charset="utf-8"><title>Finance 예시 보고서</title><style>body{font-family:system-ui;margin:60px;line-height:1.8}strong{color:#087f6e}</style><h1>Finance 예시 보고서</h1><strong>가상 자료 · 실제 증빙 아님</strong><p>UI 시안의 문서 저장 흐름을 확인하기 위한 파일입니다.</p><p>실제 계좌, 신고 또는 발급 정보가 포함되어 있지 않습니다.</p></html>';
  const history='\uFEFF거래일,내용,금액,잔액\n'+transactions.filter(item=>item.account===state.account).map(item=>`2026.${item.date},${item.title},${item.amount},${item.balance}`).join('\n');
  const blob=new Blob([kind==='report'?report:history],{type:kind==='report'?'text/html;charset=utf-8':'text/csv;charset=utf-8'});
  const url=URL.createObjectURL(blob);
  const link=document.createElement('a');
  link.href=url; link.download=kind==='report'?'finance-sample-report.html':'finance-sample-history.csv';
  document.body.append(link); link.click(); link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast('가상 데이터만 담은 예시 파일을 저장했어요.');
}
function openInvoice(id) {
  const item=invoiceRecords.find(record=>record.id===id)||{name:'예시 문구',date:'2026.09.20',item:'사무용품',supply:80000,tax:8000};
  showDialog('전자세금계산서 상세', `<div class="summary-lines">${[['거래처',item.name],['작성일',item.date],['품목',item.item],['공급가액',money(item.supply)+'원'],['세액',money(item.tax)+'원'],['합계',money(item.supply+item.tax)+'원'],['발급 상태','발급 완료 · 예시'],['승인번호','DEMO · 실제 승인번호 없음']].map(([label,value])=>`<div class="summary-line"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div><div class="dialog-actions">${button('닫기','close')}${state.invoiceDirection==='sales'?`<button class="button primary" data-amend="${id}">수정 초안 작성</button>`:''}</div>`);
}
function openRecord(reference) {
  const [group,id]=reference.split(':');
  const entry=group==='giro'?giroRecords.find(item=>item.id===id):group==='inquiry'?{title:'김하나',meta:'생활비 통장 → 하나은행 · 예시',date:'2026.09.26',amount:800000,status:'이체 완료'}:taxRows(group).find(item=>item.id===id);
  if(!entry) return;
  showDialog(group==='giro'?'고지 자료 상세':group==='inquiry'?'이체 상세':taxLabels[group]+' 상세', `<div class="summary-lines">${[['내용',entry.title],['구분',entry.meta],['일자',entry.date],['금액',money(entry.amount)+'원'],['상태',entry.status]].map(([label,value])=>`<div class="summary-line"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div>${group==='giro'?'<p class="dialog-note">불러온 예시 자료입니다. 은행·지로의 실시간 상태나 실제 납부 완료 여부를 뜻하지 않습니다.</p><div class="dialog-actions"><button class="button secondary" disabled aria-disabled="true">납부하기 · 준비 중</button></div>':`<div class="dialog-actions">${button('확인','close','primary')}</div>`}`);
}
function taxConnection() {
  showDialog('홈택스 연결', `<div class="summary-lines"><div class="summary-line"><span>선택한 대상</span><strong>${businessName()}</strong></div><div class="summary-line"><span>인증서</span><strong>공동인증서 · 예시</strong></div><div class="summary-line"><span>세션</span>${tag('로그인됨 · 예시')}</div></div><p class="dialog-note">서버에 준비된 인증서로 로그인하고, 홈택스 세션을 확인하거나 갱신하는 화면입니다.</p><div class="dialog-actions">${demoAction('로그인 시연','session-demo')}${demoAction('세션 갱신 시연','session-demo',true)}</div>`);
}
document.addEventListener('click',event=>{
  const target=event.target.closest('button');
  if(!target||target.disabled) return;
  if(target.dataset.mode) {changeMode(target.dataset.mode);return;}
  if(target.dataset.record) {openRecord(target.dataset.record);return;}
  if(target.dataset.invoice) {openInvoice(target.dataset.invoice);return;}
  if(target.dataset.report) {showReport(target.dataset.report);return;}
  if(target.dataset.download) {downloadExample(target.dataset.download);return;}
  if(target.dataset.direction) {state.invoiceDirection=target.dataset.direction;render();return;}
  if(target.dataset.amend) {
    state.invoiceDraft={...(invoiceRecords.find(item=>item.id===target.dataset.amend)||invoiceRecords[0]),amend:true};
    changeView('invoiceform'); return;
  }
  if(target.dataset.return) {
    showDialog('접수 결과·제출서식', `<div class="summary-lines"><div class="summary-line"><span>접수 결과</span>${tag('접수 완료 · 예시')}</div><div class="summary-line"><span>접수번호</span><strong>DEMO · 실제 접수번호 없음</strong></div></div><div class="menu-sheet"><button data-report="return">${icon('report')}신고서${icon('arrow')}</button><button data-report="review">${icon('report')}제출 부속서류${icon('arrow')}</button><button data-report="receipt">${icon('report')}접수증${icon('arrow')}</button></div>`);return;
  }
  switch(target.dataset.ui) {
    case 'choose-mode': chooseMode(); break;
    case 'more': moreMenu(); break;
    case 'invoice-new': state.invoiceDraft={}; changeView('invoiceform'); break;
    case 'invoice-issue-demo': {
      const draft=state.preparedInvoice;
      if(!draft||draft.business!==state.business||draft.attempted) return;
      draft.attempted=true;
      showDialog('발급 결과 예시', `<div class="success-symbol">${icon('check')}</div><h3 class="success-title">${draft.count===2?'취소·재발급 2건':'발급 1건'} 완료 · 예시</h3><p class="success-copy">${escapeHtml(draft.buyer)} · ${money(draft.supply+draft.tax)}원<br>실제 세금계산서는 발급되지 않았어요.</p><div class="dialog-actions"><button class="button primary" data-view="invoices">계산서 목록으로</button></div>`); break;
    }
    case 'business-info': showDialog('사용자·사업장 정보', `<div class="summary-lines"><div class="summary-line"><span>선택한 대상</span><strong>${businessName()}</strong></div><div class="summary-line"><span>사업 상태</span><strong>${state.business==='personal'?'개인':'계속사업자'} · 예시</strong></div><div class="summary-line"><span>사업자번호</span><strong>•••-••-•••••</strong></div></div><p class="dialog-note">상단의 조회 대상에서 개인과 사업장을 전환할 수 있어요.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`); break;
    case 'giro-import': toast('가상 고지 자료 3건을 불러왔어요.'); changeView('bills'); break;
    case 'giro-plan': showDialog('요청 준비 예시', `<div class="summary-lines"><div class="summary-line"><span>대상</span><strong>국세 고지 목록</strong></div><div class="summary-line"><span>준비 결과</span>${tag('오프라인 계획')}</div><div class="summary-line"><span>실제 요청</span><strong>전송하지 않음</strong></div></div><p class="dialog-note">현재 CLI는 인증 순서와 조회 요청의 준비를 지원해요. 실제 로그인과 고지 조회는 아직 미구현입니다.</p><div class="dialog-actions"><button class="button secondary" disabled>조회 실행 · 준비 중</button>${button('닫기','close')}</div>`); break;
    case 'giro-probe': showDialog('초기 연결 점검', `<p class="dialog-note">CLI가 지원하는 초기 연결 점검만 수행하는 기능입니다. 로그인이나 납부 성공을 확인하는 기능은 아닙니다. 시안에서는 서버에 접속하지 않아요.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`); break;
    case 'report-capture': showDialog('보고서 저장 예시', `<p class="dialog-note">확보한 보고서 자료를 독립 HTML로 저장하는 흐름입니다. 시안에서는 가상 문서만 저장할 수 있어요.</p><div class="dialog-actions"><button class="button primary" data-download="report">예시 HTML 저장</button>${button('닫기','close')}</div>`); break;
    case 'bank-login': showDialog('하나은행 로그인', `<div class="field"><label for="bank-login-method">로그인 수단</label><select id="bank-login-method"><option>하나인증서</option><option>공동인증서</option></select></div><p class="dialog-note">앱 인증과 서버에 준비된 프로필을 사용하는 로그인 흐름입니다. 실제 암호나 PIN을 입력하지 않습니다.</p><div class="dialog-actions">${demoAction('로그인 시연','session-demo')}${demoAction('연장 시연','session-demo',true)}</div>`); break;
    case 'tax-login': taxConnection(); break;
    case 'session-demo': dialog.close(); toast('예시 접속 상태를 확인했어요. 실제 인증 요청은 하지 않았습니다.'); break;
    case 'giro-status': changeView('girostatus'); break;
    case 'certificate-list': showDialog('보유 인증서 · 예시', `<div class="certificate-list">${[['하나인증서','은행 로그인 · 2029.09.30'],['사업자 공동인증서','홈택스 로그인·세금계산서 · 2027.09.30'],['개인 공동인증서','개인 홈택스 로그인 · 2027.09.30']].map(([name,detail])=>`<div><span class="record-icon">${icon('shield')}</span><span><strong>${name}</strong><small>${detail}</small></span></div>`).join('')}</div><p class="dialog-note">인증서 가져오기·내보내기·발급은 서버 관리 범위입니다. 이 화면에는 표시 정보만 보여줍니다.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`); break;
    case 'local-tools': showDialog('서버에서 관리하는 기능', `<p class="dialog-note">인증서 발급·파일 이전, 런타임 설치, 요청 전문·암호 처리 도구는 서버 관리 기능입니다. 업무 화면의 원격 실행 대상에는 포함하지 않았습니다.</p><p class="dialog-note">미구현 기능과 달리 CLI나 로컬 라이브러리에는 존재하는 기능입니다.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`); break;
  }
});
document.addEventListener('change',event=>{
  if(event.target.id==='business-context') {
    state.business=event.target.value; state.preparedInvoice=null;
    render(); toast(`${businessName()}로 조회 대상을 바꿨어요.`);
  }
  if(event.target.id==='tax-certificate') toast('예시 프로필에서 사용할 인증서를 선택했어요.');
});
document.addEventListener('submit',event=>{
  if(event.target.dataset.filter==='tax') {
    event.preventDefault();
    const fields=new FormData(event.target);
    const filter={from:String(fields.get('from')||''),to:String(fields.get('to')||''),status:String(fields.get('status')||'전체 상태')};
    if(filter.from&&filter.to&&filter.from>filter.to){toast('시작일을 종료일보다 이전으로 선택해 주세요.');return;}
    state.taxFilters={...state.taxFilters,[state.view]:filter};
    render(); toast('예시 자료에 조회 조건을 적용했어요.');return;
  }
  if(event.target.id!=='invoice-form') return;
  event.preventDefault();
  const form=new FormData(event.target);
  const draft={buyer:String(form.get('buyer')),item:String(form.get('item')),date:String(form.get('date')),supply:Number(form.get('supply')),tax:Number(form.get('tax')),settlement:String(form.get('settlement')),business:state.business,attempted:false,count:state.invoiceDraft.amend&&['0','4'].includes(form.get('reason'))?2:1};
  if(!Number.isFinite(draft.supply)||!Number.isFinite(draft.tax)||draft.supply<0||draft.tax<0) return;
  state.preparedInvoice=draft;
  showDialog('발급 전 초안 확인', `<div class="summary-lines">${[['공급자',businessName()],['공급받는 자',draft.buyer],['작성일',draft.date],['품목',draft.item],['공급가액',money(draft.supply)+'원'],['세액',money(draft.tax)+'원'],['합계',money(draft.supply+draft.tax)+'원'],['청구·영수',draft.settlement],['발급 문서 수',draft.count+'건'+(draft.count===2?' · 취소·재발급':'')]].map(([label,value])=>`<div class="summary-line"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div><p class="dialog-note">예시 초안입니다. 아래 버튼은 가상의 발급 완료 화면만 보여줍니다.</p><div class="dialog-actions">${button('다시 입력','close')}${demoAction('발급 결과 화면 보기','invoice-issue-demo',true)}</div>`);
});
