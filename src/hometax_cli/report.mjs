// Original ClipReport viewer + standalone HTML containing its own SVG pages.
// Android code, a browser executable and disabled PDF export are not used.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {loadDOM,USER_AGENT} from './browserless.mjs';
import {reportImage} from './report_image.mjs';

const pause = ms=>new Promise(resolve=>setTimeout(resolve,ms));
const hash = bytes=>createHash('sha256').update(bytes).digest('hex');

export async function saveReport(config, dependencies = {}) {
  const timeout = Math.ceil(config.timeout*1000);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw new Error('Invalid timeout');
  const source = JSON.parse(await fs.readFile(config.capture,'utf8'));
  const metadata = source.data.source;
  const html = await fs.readFile(path.join(path.dirname(config.capture),metadata.file));
  if (hash(html) !== metadata.sha256) throw new Error('Captured source hash changed');
  await fs.mkdir(config.output,{mode:0o700});
  const {JSDOM,VirtualConsole,CookieJar} = loadDOM();
  const jar = dependencies.jar || CookieJar.deserializeSync(source.cookie_jar);
  const events=[],exchanges=[],warnings=[],issues=[],imageBindings=new WeakMap();
  const pageDocuments=new Map();
  let dom,report,pending=0,changedAt=Date.now(),keyBranch='no_action',generationBranch='no_action';
  let branch='no_action',reason='original_report_unobserved',renderComplete=false,terminal=false,documentRendererInvoked=false;
  let artifact={saved:false,complete:false};
  const observeFailure = why=>{
    // An explicit original failure is different from a local export warning.
    branch='failure';reason=why;terminal=true;
  };
  const observeObject = (window,text)=>{
    let value=window.objectCall(window.ClipStrTrim(text));
    if (typeof value==='string') value=window.objectCall(value);
    return value;
  };
  const virtualConsole=new VirtualConsole();
  virtualConsole.on('jsdomError',error=>{
    issues.push(error.type||'runtime');dependencies.onError?.(error);
  });
  const until = async predicate=>{
    const deadline=Date.now()+timeout;
    while(Date.now()<deadline) {if(predicate())return true;await pause(25);}
    return false;
  };
  try {
    dom=new JSDOM(html.toString('utf8'),{
      url:metadata.url,cookieJar:jar,runScripts:'dangerously',virtualConsole,
      resources:{...dependencies.resources,userAgent:USER_AGENT},
      beforeParse(window) {
        // OtherSystemActivity's separate WebView has no JS opener.
        if (!('opener' in window)) window.opener=null;
        if (!window.SVGAElement) window.SVGAElement=window.SVGElement;
        const open=window.XMLHttpRequest.prototype.open;
        const send=window.XMLHttpRequest.prototype.send;
        const requests=new WeakMap();
        window.XMLHttpRequest.prototype.open=function(method,url){
          requests.set(this,{method,url:new URL(url,window.location.href).href});
          return open.apply(this,arguments);
        };
        window.XMLHttpRequest.prototype.send=function(body){
          const request={...requests.get(this),body:body==null ? undefined : String(body)};
          exchanges.push(request);pending++;
          let finished=false;
          const finish=()=>{if(!finished){finished=true;pending--;changedAt=Date.now();}};
          this.addEventListener('loadend',()=>{
            try {request.status=this.status;request.response=this.responseText;}
            catch {warnings.push('일부 전송 기록을 읽지 못했습니다.');}
            finish();
          },{once:true});
          try {return send.apply(this,arguments);}catch(error){finish();throw error;}
        };
        window.document.addEventListener('DOMContentLoaded',()=>{
          if (!window.Report) return;
          const handler=window.ReportEventHandler;
          window.ReportEventHandler=function(code){
            events.push(code);
            if (code===200) {
              if (branch!=='failure') {branch='success';reason='original_report_end';}
              renderComplete=true;terminal=true;
            }
            if ([30,32,40,60].includes(code)) observeFailure('original_report_event');
            return handler?.apply(this,arguments);
          };
          const check=window.Report.prototype.checkReportCreate;
          window.Report.prototype.checkReportCreate=function(){
            report=this;
            try {
              const value=observeObject(window,this.m_reportKey);
              keyBranch=value.status ? 'success' : 'failure';
              if (!value.status) observeFailure('original_report_key_failure');
            } catch {warnings.push('보고서 키 판정을 관찰하지 못했습니다.');}
            return check.apply(this,arguments);
          };
          const count=window.resultPageCountText;
          window.resultPageCountText=function(text){
            try {
              const value=observeObject(window,text);
              generationBranch=value.status ? 'success' : 'failure';
              if (!value.status) observeFailure('original_report_generation_failure');
            } catch {warnings.push('보고서 생성 상태 판정을 관찰하지 못했습니다.');}
            return count.apply(this,arguments);
          };
          const paint=window.Report.prototype.paintReportJson;
          window.Report.prototype.paintReportJson=function(text){
            documentRendererInvoked=true;
            let value;
            try {
              value=window.jQuery.parseJSON(text).resValue;
              if (!value.status) observeFailure('original_document_failure');
              else if (value.event==200 && branch!=='failure') {branch='success';reason='original_document_success';}
              else if (value.event==404) {reason='original_document_not_found';terminal=true;}
            } catch {warnings.push('문서 응답 판정을 관찰하지 못했습니다.');}
            try {
              const result=paint.apply(this,arguments);
              if (value?.status && value.event==200 && !this.m_saveJsonDoc) {
                const decoded=window.mCR_Base64.decode(value.viewData).replace(/\+/g,' ');
                pageDocuments.set(Number(this.beforePageIndex),JSON.parse(decoded));
              }
              return result;
            }
            catch(error){terminal=true;warnings.push('서비스 렌더링 후속 처리 오류가 있습니다. 관찰한 판정은 유지합니다.');throw error;}
          };
          const image=window.mCR_ServerImageCallSVG;
          window.mCR_ServerImageCallSVG=function(renderer,control,imageId,element){
            imageBindings.set(element,{renderer,imageId});
            return image.apply(this,arguments);
          };
        },true);
        dependencies.beforeParse?.(window);
      },
    });
    if (!await until(()=>terminal)) warnings.push('서비스 보고서 완료를 관찰 시간 안에 확인하지 못했습니다.');
    if (!await until(()=>pending===0 && Date.now()-changedAt>=100))
      warnings.push('보고서 후속 이미지 수신이 관찰 시간 안에 끝나지 않았습니다.');
    if (renderComplete && !report?.m_saveJsonDoc && pageDocuments.size && branch==='success') {
      // The detail viewer requests numeric pageMethod values. Leave its
      // all-page flag untouched and use the original next-page API.
      for(let index=1;index<Number(report.m_pageCount);index++) {
        terminal=false;
        report.nextPage();
        if (!await until(()=>pageDocuments.has(index) || terminal) || !pageDocuments.has(index)) {
          warnings.push('서비스 다음 페이지 표시가 완료되지 않았습니다. 받은 페이지를 보존합니다.');break;
        }
        if (!await until(()=>pending===0 && Date.now()-changedAt>=100)) {
          warnings.push('페이지의 후속 이미지 수신이 관찰 시간 안에 끝나지 않았습니다.');break;
        }
        if (branch==='failure') break;
      }
    }
    if (renderComplete && (report?.m_saveJsonDoc || pageDocuments.size)) {
      const w=dom.window;
      // Same reader and print-mode SVG exporter as mRe_clientMakePrintHTMLView.
      const rendered=[];
      const chunks=report.m_saveJsonDoc
        ? [{document:report.m_saveJsonDoc,pageList:report.m_saveJsonDocPageList}]
        : [...pageDocuments.entries()].sort((a,b)=>a[0]-b[0]).map(([,value])=>value);
      for(const chunk of chunks) {
        const reader=new w.documentReader();
        const document=reader.documentReaderFromJSON(chunk.document,report.servletPath,report.m_uid);
        for(const page of chunk.pageList) document.addPage(reader.readDocumentPage(page));
        for(let i=0;i<document.getPageListLength();i++) {
          const target=w.document.createElement('div');
          const renderer=new w.mCR_exportSVG(document,true);
          renderer.setPostParam(report.m_postParam ? report.m_postParam.getParam() : null);
          const svg=renderer.exportPage(i,null,target);
          rendered.push({svg,width:renderer.objPageStyle.width,height:renderer.objPageStyle.height});
        }
      }
      if (!await until(()=>pending===0 && Date.now()-changedAt>=100))
        warnings.push('추가 페이지의 이미지 수신이 관찰 시간 안에 끝나지 않았습니다.');
      const output=new JSDOM('<!doctype html><html lang="ko"><head><meta charset="utf-8"><title></title></head><body></body></html>');
      try {
        const d=output.window.document;d.title=report.m_strFileName || '보고서';
        const style=d.createElement('style');
        style.textContent='body{margin:0;background:#eee}.page{background:white;margin:12px auto;width:max-content;break-after:page}.page:last-child{break-after:auto}svg{display:block}@media print{body{background:white}.page{margin:0}}';
        d.head.append(style);
        let missingImages=0,invalidImages=0,imageCount=0,externalReferences=0;
        for(const [index,page] of rendered.entries()) {
          const section=d.createElement('section');section.className='page';section.style.page='sheet'+index;
          style.textContent+=`@page sheet${index}{size:${page.width/100}cm ${page.height/100}cm;margin:0}`;
          const clone=page.svg.cloneNode(true);
          const originals=[...page.svg.querySelectorAll('image')];
          const copies=[...clone.querySelectorAll('image')];
          for(let i=0;i<copies.length;i++) {
            imageCount++;
            const binding=imageBindings.get(originals[i]);
            if (binding) {
              // Original AJAX checks status and caches image bytes. Browser
              // Image sniffs JPEG as well as PNG despite its PNG data-URI label.
              const cached=w.m_reportHashMap[binding.renderer.objDocument.reportKey]?.getProperty(binding.imageId);
              if (typeof cached==='string') {
                let mime='image/png';
                try {mime=reportImage(Buffer.from(cached,'base64')).mime;}catch {}
                copies[i].setAttributeNS('http://www.w3.org/1999/xlink','xlink:href','data:'+mime+';base64,'+cached);
              }
            }
            const href=copies[i].getAttribute('href')||copies[i].getAttributeNS('http://www.w3.org/1999/xlink','href');
            if (!href?.startsWith('data:image/')) missingImages++;
            else if (/^data:image\/(png|jpeg);base64,/.test(href)) {
              try {reportImage(Buffer.from(href.slice(href.indexOf(',')+1),'base64'));}
              catch {invalidImages++;}
            }
          }
          // Archive graphics, not the viewer's UI event handlers or session.
          for(const node of [clone,...clone.querySelectorAll('*')]) {
            for(const attribute of [...node.attributes]) {
              if (attribute.name.toLowerCase().startsWith('on')) node.removeAttributeNode(attribute);
              else if (['href','xlink:href','src'].includes(attribute.name) && attribute.value &&
                  !attribute.value.startsWith('#') && !attribute.value.startsWith('data:')) externalReferences++;
              else if (/url\(\s*['"]?(?:https?:|\/)/i.test(attribute.value)) externalReferences++;
            }
          }
          externalReferences+=clone.querySelectorAll('script,iframe,object,embed').length;
          section.append(d.importNode(clone,true));d.body.append(section);
        }
        const bytes=Buffer.from(output.serialize());
        const filename='report.html';
        await fs.writeFile(path.join(config.output,filename),bytes,{mode:0o600,flag:'wx'});
        artifact={saved:true,file:filename,format:'html-svg',page_count:rendered.length,image_count:imageCount,
          missing_images:missingImages,invalid_images:invalidImages,external_references:externalReferences,bytes:bytes.length,sha256:hash(bytes),
          complete:rendered.length===Number(report.m_pageCount) && missingImages===0 && invalidImages===0 && externalReferences===0};
        if (!artifact.complete) warnings.push('서비스 성공과 별도로, 독립 파일의 페이지·이미지 완전성을 확인하지 못했습니다.');
      } finally {output.window.close();}
    }
  } catch(error) {
    dependencies.onError?.(error);
    warnings.push('보고서 처리 또는 파일 저장 중 오류가 있습니다. 관찰한 서비스 판정은 유지합니다.');
  } finally {
    try {
      if (issues.length) warnings.push('서비스 뷰어 실행 중 경고가 있습니다. 서비스 판정과 구분해 기록했습니다.');
      if (branch==='success' && !artifact.saved) warnings.push('서비스 성공을 확인했지만 독립 파일은 저장되지 않았습니다.');
      await fs.writeFile(path.join(config.output,'result.json'),JSON.stringify({
        ...source,scope:'browserless_report',source_capture:config.capture,branch,reason,report_branch:branch,
        returned_scripts_executed:true,document_renderer_executed:documentRendererInvoked,
        key_branch:keyBranch,generation_branch:generationBranch,render_complete:renderComplete,
        page_mode:report?.m_saveJsonDoc ? 'all' : pageDocuments.size ? 'individual' : 'unobserved',
        observed_page_count:report?.m_saveJsonDocPageList?.length ?? pageDocuments.size,
        artifact,report_events:events,exchanges,runtime_issues:issues,warnings,cookie_jar:jar.serializeSync(),
      },null,2),{mode:0o600,flag:'wx'});
    } finally {dom?.window.close();}
  }
  return {scope:'browserless_report',branch,reason,render_complete:renderComplete,artifact,warnings};
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    let input='';for await(const chunk of process.stdin)input+=chunk;
    const result=await saveReport(JSON.parse(input));
    for(const warning of result.warnings)process.stderr.write('warning: '+warning+'\n');
    const {warnings,...summary}=result;
    process.stdout.write(JSON.stringify({...summary,warning_count:warnings.length})+'\n');
    process.exitCode=result.branch==='success' ? 0 : result.branch==='failure' ? 1 : 3;
  } catch(error) {
    process.stderr.write('error: 보고서 입력 또는 저장 경로 오류 ('+error.constructor.name+')\n');process.exitCode=2;
  }
}
