// Query a real filing, open its original report, then save each requested view.
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {BusinessRuntime} from './business.mjs';
import {writeReportSource} from './report_source.mjs';
import {saveReport} from './report.mjs';

export async function writeReportIndex(output, documents) {
  const escape=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const rows=documents.map((d,i)=>`<tr><td>${i+1}</td><td>${d.artifact.saved
    ? `<a href="${escape(d.artifact.file)}">${escape(d.form?.frmlNm || '접수증')}</a>`
    : escape(d.form?.frmlNm || '접수증')}</td><td>${d.artifact.page_count ?? '—'}</td><td>${d.artifact.complete ? '완전' : '확인 필요'}</td></tr>`).join('');
  const html='<!doctype html><html lang="ko"><meta charset="utf-8"><title>저장한 보고서</title>'+
    '<style>body{font-family:sans-serif;max-width:1000px;margin:32px auto;padding:0 16px}table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}a{color:#125db0}</style>'+
    '<h1>저장한 보고서</h1><p>각 문서는 이미지가 포함된 독립 HTML입니다.</p><table><thead><tr><th>번호</th><th>서식</th><th>페이지</th><th>파일 완전성</th></tr></thead><tbody>'+rows+'</tbody></table></html>';
  await fs.writeFile(path.join(output,'index.html'),html,{mode:0o600,flag:'wx'});
}

export async function runReturnReport(config, dependencies = {}) {
  if (!Number.isSafeInteger(Math.ceil(config.timeout*1000)) || config.timeout<=0) throw new Error('Invalid timeout');
  await fs.mkdir(config.output,{mode:0o700});
  const runtime=new BusinessRuntime(config,dependencies);
  const documents=[];
  let query,selected,forms=[],branch='no_action',reason='report_unobserved',complete=false,record;
  const noNavigation=since=>{
    const failed=runtime.services.slice(since).findLast(s=>s.response_observed && s.branch==='failure');
    if (failed) {branch='failure';reason='original_report_preparation_failure';}
    else {reason='report_navigation_unobserved';runtime.warnings.push('요청한 보고서의 서비스 탐색을 확인하지 못했습니다.');}
  };
  const store=async(request,form,batch)=>{
    const name='document-'+String(documents.length+1).padStart(3,'0');
    const directory=path.join(config.output,name);
    await fs.mkdir(directory,{mode:0o700});
    const capture=await writeReportSource(runtime,request,path.join(directory,'source'),query,dependencies);
    const report=await saveReport({capture,output:path.join(directory,'report'),timeout:config.timeout},
      {...dependencies,jar:runtime.page.jar});
    documents.push({form,batch,capture:path.relative(config.output,capture),
      result:path.join(name,'report','result.json'),...report,
      artifact:{...report.artifact,...(report.artifact.saved ? {file:path.join(name,'report',report.artifact.file)} : {})}});
    runtime.warnings.push(...report.warnings);
    // Explicit failures of a later document remain failures; previous files stay.
    if (report.branch!=='no_action' || branch!=='success') branch=report.branch;
    reason=report.reason;
    return report.branch==='success' && report.render_complete;
  };
  try {
    await runtime.open();
    if (!runtime.ready) reason=runtime.unavailable().reason;
    else {
      query=await runtime.returns(config.query_source || 'list',{returnId:config.return_id});
      if (query.branch!=='success') {branch=query.branch;reason=query.reason;}
      else {
        selected=runtime.selectedReturn(query);
        if (!selected) reason=config.return_id===undefined ? 'no_return_selected' : 'requested_return_not_found';
        else {
          const kind=config.operation==='receipt' ? 'receipt' : 'detail';
          let since=runtime.services.length;
          let request=config.query_source==='status'
            ? await runtime.prepareReportFromStatus(selected,kind,{disclose:config.disclose})
            : await runtime.prepareReportRequest(kind,{disclose:config.disclose});
          if (!request) noNavigation(since);
          else if (kind==='receipt') complete=await store(request,undefined,1);
          else {
            forms=runtime.reportForms();
            const requested=config.form_code===undefined ? (config.all_forms ? forms : forms.slice(0,1))
              : forms.filter(form=>form.frmlCd==config.form_code);
            if (!requested.length) reason='requested_form_not_found';
            else {
              complete=true;
              for (const form of requested) {
                since=runtime.services.length;
                if (form!==forms[0]) request=await runtime.selectReportForm(form.frmlCd);
                if (!request) {noNavigation(since);complete=false;break;}
                // Only the original's data-page forms use this page-info VO.
                const info=structuredClone(runtime.window.pageInfoVO_Z34);
                if (!await store(request,form,1)) {complete=false;break;}
                if (form.ldgrRptDataPageTrtYn==='Y') {
                  const size=Number(info?.pageSize),total=Number(info?.totalCount);
                  if (!Number.isFinite(size)||size<=0||!Number.isFinite(total)||total<0) {
                    complete=false;
                    runtime.warnings.push('서비스 자료 묶음 정보를 해석하지 못했습니다. 저장한 성공 문서는 보존합니다.');
                    break;
                  }
                  for(let page=2;page<=Math.ceil(total/size);page++) {
                    since=runtime.services.length;
                    request=await runtime.nextReportPage(page);
                    if (!request) {noNavigation(since);complete=false;break;}
                    if (!await store(request,form,page)) {complete=false;break;}
                  }
                  if (!complete) break;
                }
              }
            }
          }
        }
      }
    }
  } catch(error) {
    dependencies.onError?.(error);
    complete=false;
    runtime.warnings.push('보고서 연결 또는 저장 중 오류가 있습니다. 관찰한 서비스 판정과 저장 파일을 보존합니다.');
  } finally {
    try {
      if (documents.length) {
        try {await writeReportIndex(config.output,documents);}
        catch {runtime.warnings.push('보고서 목록 HTML을 저장하지 못했습니다. 개별 파일과 서비스 판정은 보존합니다.');}
      }
      const result={branch,reason,data:{query,selected,forms,documents},
        collection:{requested_all_forms:Boolean(config.all_forms),complete,
          artifacts_complete:complete && documents.every(d=>d.artifact.complete)}};
      record=runtime.page ? runtime.record(result) : {...result,warnings:runtime.warnings};
      record.scope='browserless_return_report';
      await fs.writeFile(path.join(config.output,'result.json'),JSON.stringify(record,null,2),{mode:0o600,flag:'wx'});
    } finally {runtime.close();}
  }
  return {scope:record.scope,branch,reason,collection:record.collection,document_count:documents.length,
    page_count:documents.reduce((n,d)=>n+(d.artifact.page_count||0),0),
    image_count:documents.reduce((n,d)=>n+(d.artifact.image_count||0),0),warnings:record.warnings};
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    let input='';for await(const chunk of process.stdin)input+=chunk;
    const {warnings,...summary}=await runReturnReport(JSON.parse(input));
    for(const warning of warnings)process.stderr.write('warning: '+warning+'\n');
    process.stdout.write(JSON.stringify({...summary,warning_count:warnings.length})+'\n');
    process.exitCode=summary.branch==='success' ? 0 : summary.branch==='failure' ? 1 : 3;
  } catch(error) {
    process.stderr.write('error: 신고 보고서 입력 또는 저장 경로 오류 ('+error.constructor.name+')\n');process.exitCode=2;
  }
}
