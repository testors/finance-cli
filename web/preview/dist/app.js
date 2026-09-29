/* Finance UI concept. Synthetic records only; no API, cookies, or persistent storage. */
const paths = {
  tax:'<path d="M4 7h16L12 2 4 7Zm2 3v8m6-8v8m6-8v8M3 21h18"/>',
  bill:'<path d="M6 3h12v18l-3-2-3 2-3-2-3 2V3Zm3 5h6m-6 4h6m-6 4h3"/>',
  invoice:'<path d="M5 3h10l4 4v14H5V3Zm10 0v5h4M8 12h8m-8 4h5"/>',
  report:'<path d="M5 3h14v18H5V3Zm4 4h6m-6 4h6m-6 4h6m-6 3h3"/>',
  business:'<path d="M4 21V3h12v18M8 7h4m-4 4h4m-4 4h4m4-7h4v13M2 21h20"/>',
  calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4m10-4v4M3 10h18m-14 4h3m4 0h3"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
  chevrons:'<path d="m9 8 3-3 3 3m-6 8 3 3 3-3"/>',

  accounts: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 9h18m-5 5h2"/>',
  history: '<path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3M8 3v5h8V3H8Zm0 10h6m-6 4h9m1-9 3-3m-3 0h3v3"/>',
  transfer: '<path d="M4 7h15m-4-4 4 4-4 4M20 17H5m4-4-4 4 4 4"/>',
  activity: '<path d="M12 8v5l3 2M3 11a9 9 0 1 1 2 7M3 5v6h6"/>',
  arrow: '<path d="m9 5 7 7-7 7"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M18 18a8 8 0 0 1-13-2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  desktop: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  phone: '<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/>',
};
const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.accounts}</svg>`;
const money = value => new Intl.NumberFormat('ko-KR').format(value);
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const accounts = [
  {id:'daily',name:'생활비 통장',number:'123-••••••-10204',balance:2860420},
  {id:'salary',name:'월급 통장',number:'123-••••••-20816',balance:12000000},
  {id:'reserve',name:'여유자금 통장',number:'123-••••••-30928',balance:10000000},
];
const transactions = [
  {id:'t1',account:'daily',date:'09.30',time:'10:24',title:'동네 식료품점',type:'체크카드',amount:-38600,balance:2860420},
  {id:'t2',account:'daily',date:'09.30',time:'08:10',title:'정기 구독',type:'자동이체',amount:-17880,balance:2899020},
  {id:'t3',account:'daily',date:'09.29',time:'12:41',title:'점심 식사',type:'체크카드',amount:-32000,balance:2916900},
  {id:'t4',account:'daily',date:'09.28',time:'18:32',title:'주말 장보기',type:'체크카드',amount:-96000,balance:2948900},
  {id:'t5',account:'daily',date:'09.27',time:'09:00',title:'관리비',type:'자동이체',amount:-98000,balance:3044900},
  {id:'t6',account:'daily',date:'09.26',time:'14:05',title:'김하나',type:'계좌이체',amount:-800000,balance:3142900},
  {id:'t7',account:'daily',date:'09.25',time:'09:00',title:'9월 급여',type:'입금',amount:3200000,balance:3942900},
  {id:'t8',account:'salary',date:'09.25',time:'09:01',title:'급여 적립',type:'입금',amount:3000000,balance:12000000},
  {id:'t9',account:'reserve',date:'09.25',time:'09:03',title:'여유자금 적립',type:'입금',amount:500000,balance:10000000},
];
let navigation=workspaceNavigation('banking');
const state = {view:'accounts',mode:'banking',lastViews:{banking:'accounts',tax:'taxhome',giro:'bills'},business:'studio',invoiceDirection:'sales',invoiceDraft:{},preparedInvoice:null,account:'daily',period:'week',hidden:false,refreshTime:'10:30',transferAmount:100000};
const main = document.querySelector('#main');
const dialog = document.querySelector('#detail-dialog');
const selected = () => accounts.find(account => account.id === state.account);
const balanceText = amount => state.hidden ? '••••••' : money(amount);
let toastTimer;
function toast(message) { const target=document.querySelector('#toast'); target.textContent=message; target.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>target.classList.remove('show'),3000); }
function navMarkup(mobile=false) {
  const items=mobile?navigation.filter(item=>item.available).slice(0,3):navigation;
  const markup=items.map(item=>`<button class="nav-item ${state.view===item.id?'active':''} ${!item.available?'unavailable':''}" ${item.available?`data-view="${item.id}"`:'disabled aria-disabled="true"'} ${state.view===item.id?'aria-current="page"':''}>${icon(item.icon)}<span>${mobile?item.short:item.name}</span>${!item.available?'<small class="soon-label">준비 중</small>':''}</button>`).join('');
  return markup+(mobile?`<button class="nav-item" data-ui="more" aria-haspopup="dialog">${icon('grid')}<span>전체 메뉴</span></button>`:'');
}
function heading(title,sub,actions='') {return `<div class="page-heading"><div><h1>${title}</h1><p>${sub}</p></div><div class="heading-actions">${actions}</div></div>`;}
function button(label,action,type='secondary',name='') {return `<button class="button ${type}" data-action="${action}">${name?icon(name):''}${label}</button>`;}
function accountCards() {return `<div class="account-grid">${accounts.map(account=>`<button class="account-card ${state.account===account.id?'selected':''}" data-account="${account.id}" aria-pressed="${state.account===account.id}"><div class="account-top"><span class="bank-symbol">H</span><div><h3>${account.name}</h3><p>하나은행 · ${account.number.slice(-5)}</p></div></div>${state.account===account.id?`<span class="account-check">${icon('check')}</span>`:''}<div class="account-balance number">${balanceText(account.balance)}<small>원</small></div><div class="account-last">입출금 · ${account.number}</div></button>`).join('')}</div>`;}
function rows() { return transactions.filter(t=>t.account===state.account && (state.period!=='today'||t.date==='09.30')); }
function transactionTable(full=false) {const current=selected(); const items=rows(); return `<section class="panel ${full?'wide-panel':''}"><div class="panel-heading"><div><h2>${full?'거래 내역':current.name+' 거래 내역'}</h2><div class="meta">${full?current.name+' · ':''}${current.number}</div></div>${!full?'<button class="text-button" data-view="history">전체 보기 '+icon('arrow')+'</button>':''}</div><div class="period-bar"><div class="segmented" aria-label="조회 기간">${[['today','오늘'],['week','1주일'],['month','1개월']].map(([id,label])=>`<button data-period="${id}" class="${state.period===id?'active':''}" aria-pressed="${state.period===id}">${label}</button>`).join('')}</div><span class="date-range">${state.period==='today'?'2026.09.30':state.period==='week'?'2026.09.24 — 09.30':'2026.09.01 — 09.30'}</span></div>${items.length?`<table class="table"><thead><tr><th scope="col">거래일</th><th scope="col">거래 내용</th><th scope="col">거래 금액 / 잔액</th></tr></thead><tbody>${items.map(t=>`<tr class="transaction-click" data-transaction="${t.id}" tabindex="0" aria-label="${t.title} 거래 상세"><td class="date number">${t.date}<div class="transaction-sub">${t.time}</div></td><td><div class="transaction-title">${t.title}</div><div class="transaction-sub">${t.type} · ${t.date}</div></td><td class="transaction-amount number ${t.amount>0?'incoming':''}">${state.hidden?'••••••':(t.amount>0?'+':'−')+money(Math.abs(t.amount))}<span class="balance">잔액 ${balanceText(t.balance)}원</span></td></tr>`).join('')}</tbody></table>`:'<div class="empty-state">선택한 기간에 거래 내역이 없어요.</div>'}</section>`;}
function accountsView() {return heading('내 계좌','2026년 9월 30일 수요일',button('새로 조회','refresh','secondary','refresh'))+`<section class="balance-overview"><div><div class="balance-label">전체 계좌 잔액<button class="icon-button" data-action="privacy" aria-label="${state.hidden?'잔액 표시':'잔액 숨기기'}">${icon('eye')}</button></div><div class="total-balance number">${balanceText(accounts.reduce((sum,a)=>sum+a.balance,0))}<small>원</small></div><div class="balance-meta"><span>하나은행 · 3개 계좌</span><span>${state.refreshTime} 조회</span></div></div><div class="overview-side"><p>필요할 때, 바로 이체하세요.</p><button class="button on-dark" data-view="transfer">이체하기 ${icon('transfer')}</button></div></section>`+accountCards()+`<div class="workspace-grid">${transactionTable()}<div class="side-stack"><section class="panel quick-transfer"><h2>빠른 이체</h2><p>선택한 계좌에서 이체해요.</p><div class="quick-account"><span class="bank-symbol">H</span><div>${selected().name}<small>${selected().number}</small></div></div><button class="button primary" data-view="transfer">이체하기 ${icon('arrow')}</button></section><section class="panel certificate-panel"><div class="certificate-title">${icon('shield')}하나인증서<span class="status-pill">로그인됨</span></div><p>물리 OTP 없이 이체할 수 있어요.<br>인증 상태는 예시로 표시됩니다.</p><button class="text-button" data-view="settings">연결·인증 관리 ${icon('arrow')}</button></section><section class="panel recent-operation"><h3>최근 작업</h3><div class="operation-mini"><span class="tiny-icon">${icon('check')}</span><div><strong>계좌 잔액 조회 완료</strong><p>10:30 · 웹에서 요청</p></div></div><div class="operation-mini"><span class="tiny-icon">${icon('activity')}</span><div><strong>거래 내역 조회 완료</strong><p>09:00 · 에이전트에서 요청</p></div></div></section></div></div>`;}
function historyView() {return heading('거래 내역','계좌별 입출금 내역을 확인하세요.',`<button class="button secondary" data-download="history">예시 CSV 저장</button>`+refreshAction())+accountCards()+transactionTable(true);}
function transferView() {return heading('이체','보내기 전에 받는 분과 금액을 확인하세요.')+`<div class="steps"><span class="active"><b>1</b>정보 입력</span><i></i><span><b>2</b>내용 확인</span><i></i><span><b>3</b>완료</span></div><div class="transfer-layout"><form class="panel form-panel" id="transfer-form"><div class="field"><label for="source-account">어느 계좌에서 보낼까요?</label><select id="source-account" name="source">${accounts.map(a=>`<option value="${a.id}" ${a.id===state.account?'selected':''}>${a.name} · ${money(a.balance)}원</option>`).join('')}</select></div><div class="field"><label for="recipient-account">받는 계좌</label><div class="field-row"><select id="recipient-bank" name="bank" aria-label="받는 은행"><option>하나은행</option><option>국민은행</option><option>신한은행</option></select><input id="recipient-account" name="account" value="123-456789-00001" inputmode="numeric" autocomplete="off" aria-describedby="recipient-help"></div><p class="field-help" id="recipient-help">시안용 예시 계좌예요. 받는 분은 김하나로 표시됩니다.</p></div><div class="field"><label for="transfer-amount">얼마를 보낼까요?</label><div class="amount-input"><input id="transfer-amount" name="amount" value="${money(state.transferAmount)}" inputmode="numeric" autocomplete="off" required><span>원</span></div><div class="amount-presets">${[10000,50000,100000].map(value=>`<button type="button" data-add="${value}">+${money(value/10000)}만</button>`).join('')}<button type="button" data-action="amount-clear">지우기</button></div><p class="field-help">출금 가능 금액 ${money(selected().balance)}원</p></div><div class="form-actions"><button class="button primary" type="submit">이체 내용 확인 ${icon('arrow')}</button><p class="form-error" id="transfer-error" role="alert"></p></div></form><aside class="panel transfer-summary"><h2>이체 요약</h2><div class="summary-lines"><div class="summary-line"><span>출금 계좌</span><strong id="summary-source">${selected().name}</strong></div><div class="summary-line"><span>받는 분</span><strong>김하나 <span class="muted">(예시)</span></strong></div><div class="summary-line"><span>수수료</span><strong>0원</strong></div><div class="summary-line total"><span>보낼 금액</span><strong id="summary-amount">${money(state.transferAmount)}원</strong></div></div><div class="info-block">${icon('shield')} 하나인증서로 로그인한 상태예요.<br>이 시안에서는 실제 이체가 실행되지 않아요.</div></aside></div>`;}
function render() {
  navigation=workspaceNavigation(state.mode);
  document.querySelectorAll('.mode-control').forEach(target=>target.innerHTML=modeControls());
  document.querySelector('.workspace-label').textContent=workspaces[state.mode].service;
  document.querySelector('.main-nav').innerHTML=navMarkup();
  document.querySelector('.common-nav').innerHTML=sharedNavigation.map(item=>`<button class="nav-item ${state.view===item.id?'active':''}" data-view="${item.id}">${icon(item.icon)}<span>${item.name}</span></button>`).join('');
  document.querySelector('.bottom-nav').innerHTML=navMarkup(true);
  document.querySelector('#breadcrumb-mode').textContent=sharedNavigation.some(item=>item.id===state.view)?'공통':workspaces[state.mode].name;
  const title=navigationForAll().find(item=>item.id===state.view)?.name||(state.view==='invoiceform'?'계산서 작성':'Finance');
  document.querySelector('#breadcrumb-title').textContent=title;
  document.querySelector('#preview-stage').dataset.workspace=state.mode;
  const views={accounts:accountsView,history:historyView,transfer:transferView,...expandedViews};
  main.innerHTML=contextPicker()+views[state.view]();
  document.title=`Finance — ${title}`;
}

function changeView(view) {
  const entry=navigationForAll().find(item=>item.id===view);
  if((!entry&&view!=='invoiceform')||entry?.available===false) return;
  const nextMode=Object.keys(workspaces).find(mode=>workspaces[mode].items.some(item=>item[0]===view))||(view==='invoiceform'?'tax':null);
  if(nextMode) {state.mode=nextMode;state.lastViews[nextMode]=view;}
  state.view=view;
  if(dialog.open) dialog.close();
  render();window.scrollTo({top:0,behavior:'instant'});document.querySelector('.main-shell').scrollTo({top:0,behavior:'instant'});main.focus({preventScroll:true});
}
function showDialog(title,body) {document.querySelector('#dialog-content').innerHTML=`<div class="dialog-header"><h2 id="dialog-title">${title}</h2><button class="icon-button" data-action="close" aria-label="닫기">${icon('close')}</button></div><div class="dialog-body">${body}</div>`;if(!dialog.open)dialog.showModal();}
function showTransaction(id) {const t=transactions.find(item=>item.id===id);if(!t)return;showDialog('거래 상세',`<div class="summary-lines"><div class="summary-line"><span>거래 내용</span><strong>${t.title}</strong></div><div class="summary-line"><span>거래 일시</span><strong>2026.${t.date} ${t.time}</strong></div><div class="summary-line"><span>거래 구분</span><strong>${t.type}</strong></div><div class="summary-line total"><span>거래 금액</span><strong>${t.amount>0?'+':'−'}${money(Math.abs(t.amount))}원</strong></div></div><p class="dialog-note">가상 데이터로 구성한 거래 상세 시안입니다.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`);}
document.addEventListener('click',event=>{const target=event.target.closest('button,a,tr[data-transaction]');if(!target)return;if(target.dataset.view){event.preventDefault();changeView(target.dataset.view);return;}if(target.dataset.account){state.account=target.dataset.account;render();return;}if(target.dataset.period){state.period=target.dataset.period;render();return;}if(target.dataset.transaction){showTransaction(target.dataset.transaction);return;}if(target.dataset.size){document.querySelector('#preview-stage').classList.toggle('phone',target.dataset.size==='mobile');document.querySelectorAll('[data-size]').forEach(button=>{button.classList.toggle('active',button===target);button.setAttribute('aria-pressed',String(button===target));});return;}if(target.dataset.add){updateAmount(state.transferAmount+Number(target.dataset.add));return;}switch(target.dataset.action){case'privacy':state.hidden=!state.hidden;render();break;case'refresh':state.refreshTime=new Date().toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit',hour12:false});render();toast('예시 데이터의 조회 시각을 갱신했어요.');break;case'close':dialog.close();break;case'amount-clear':updateAmount(0);break;case'extend':toast('로그인 연장 동작의 미리보기입니다.');break;case'revoke':showDialog('예시 접속 해제',`<p class="dialog-note">Android 휴대폰의 접속을 해제하는 확인 화면입니다. 실제 접속에는 영향을 주지 않아요.</p><div class="dialog-actions">${button('돌아가기','close')}${button('해제 확인','demo-revoke','primary')}</div>`);break;case'demo-revoke':dialog.close();toast('예시 접속 해제를 확인했어요.');break;case'check-result':showDialog('이체 결과 확인',`<div class="summary-lines"><div class="summary-line"><span>받는 분</span><strong>김하나</strong></div><div class="summary-line"><span>보낸 금액</span><strong>100,000원</strong></div><div class="summary-line"><span>상태</span><span class="status-pill warning">결과 미확인</span></div></div><p class="dialog-note">은행 응답을 받지 못했을 때의 예시입니다. 같은 이체를 다시 보내지 않고 기존 작업의 결과를 확인합니다.</p><div class="dialog-actions">${button('닫기','close')}${button('결과 조회 시연','demo-result','primary')}</div>`);break;case'demo-result':showDialog('확인된 이체 결과',`<div class="success-symbol">${icon('check')}</div><h3 class="success-title">이체 완료 · 예시</h3><p class="success-copy">기존 이체의 성공 결과를 확인했어요.<br>실제 은행 조회는 하지 않았습니다.</p><div class="dialog-actions">${button('확인','close','primary')}</div>`);break;case'demo-send':target.disabled=true;showDialog('이체 결과',`<div class="success-symbol">${icon('check')}</div><h3 class="success-title">이체 완료 · 예시</h3><p class="success-copy">김하나님에게 ${money(state.transferAmount)}원<br>실제 금액은 이동하지 않았어요.</p><div class="dialog-actions">${button('계좌로 돌아가기','back-accounts','primary')}</div>`);break;case'back-accounts':dialog.close();changeView('accounts');break;}});
function updateAmount(value) {state.transferAmount=Math.min(Math.max(Number(value)||0,0),9999999999);const input=document.querySelector('#transfer-amount');if(input)input.value=money(state.transferAmount);const summary=document.querySelector('#summary-amount');if(summary)summary.textContent=money(state.transferAmount)+'원';}
document.addEventListener('input',event=>{if(event.target.id==='transfer-amount')updateAmount(event.target.value.replace(/[^0-9]/g,''));});
document.addEventListener('change',event=>{if(event.target.id==='source-account'){state.account=event.target.value;render();}});
document.addEventListener('keydown',event=>{if(event.target.matches('tr[data-transaction]')&&(event.key==='Enter'||event.key===' ')){event.preventDefault();showTransaction(event.target.dataset.transaction);}});
document.addEventListener('submit',event=>{if(event.target.id!=='transfer-form')return;event.preventDefault();const form=new FormData(event.target);const account=String(form.get('account'));const amount=state.transferAmount;const error=document.querySelector('#transfer-error');if(account.replace(/\D/g,'').length<10){error.textContent='예시 계좌번호를 10자리 이상 입력해 주세요.';return;}if(!amount||amount>selected().balance){error.textContent='출금 가능한 금액 안에서 보낼 금액을 입력해 주세요.';return;}showDialog('이 내용으로 보낼까요?',`<div class="summary-lines"><div class="summary-line"><span>받는 분</span><strong>김하나 <span class="muted">(예시)</span></strong></div><div class="summary-line"><span>받는 계좌</span><strong>${escapeHtml(form.get('bank'))}<br>${escapeHtml(account)}</strong></div><div class="summary-line"><span>출금 계좌</span><strong>${selected().name}</strong></div><div class="summary-line"><span>수수료</span><strong>0원</strong></div><div class="summary-line total"><span>보낼 금액</span><strong>${money(amount)}원</strong></div></div><p class="dialog-note">UI 시안입니다. 아래 버튼은 완료 화면만 보여주며 실제 이체는 실행하지 않습니다.</p><div class="dialog-actions">${button('다시 입력','close')}${button('이체 완료 화면 보기','demo-send','primary')}</div>`);});
dialog.addEventListener('click',event=>{if(event.target===dialog){const rect=dialog.getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)dialog.close();}});
render();
