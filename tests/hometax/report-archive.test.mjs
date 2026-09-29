import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {saveReport} from '../../src/hometax_cli/report.mjs';
import {loadDOM} from '../../src/hometax_cli/browserless.mjs';
import {png,jpg} from './report-fixture.mjs';

// A synthetic viewer supplies SVG and service events; no service resources or
// sockets are used. The archive subprocess uses the CLI's Python interpreter.
function viewer(bytes, accepted=true) {
  return `<html><head><script>
function ClipStrTrim(s){return s.trim()}
function objectCall(s){return JSON.parse(s)}
function ReportEventHandler(){}
function Report(){
  this.m_reportKey='{"status":${accepted}}'; this.m_pageCount=1;
  this.m_saveJsonDoc={}; this.m_saveJsonDocPageList=[{}];
  this.checkReportCreate(); ReportEventHandler(${accepted ? 200 : 30});
}
Report.prototype.checkReportCreate=function(){};
Report.prototype.paintReportJson=function(){};
function documentReader(){}
documentReader.prototype.documentReaderFromJSON=function(){return {addPage(){},getPageListLength(){return 1}}};
documentReader.prototype.readDocumentPage=function(p){return p};
function mCR_exportSVG(){this.objPageStyle={width:2100,height:2970}}
mCR_exportSVG.prototype.setPostParam=function(){};
mCR_exportSVG.prototype.exportPage=function(){
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('xmlns','http://www.w3.org/2000/svg');
  svg.setAttribute('xmlns:xlink','http://www.w3.org/1999/xlink');
  const image=document.createElementNS('http://www.w3.org/2000/svg','image');
  image.setAttributeNS('http://www.w3.org/1999/xlink','xlink:href','data:image/png;base64,${bytes}');
  svg.append(image);return svg;
};
</script></head><body onload="new Report()"></body></html>`;
}

for (const sample of ['png','jpeg','invalid','write-failure','service-failure']) {
  test('Python report archive: '+sample, async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(),'finance-report-'));
    try {
      const {CookieJar} = loadDOM();
      const html = viewer(sample==='jpeg' ? jpg : sample==='invalid' ? 'INVALID_PNG' : png,
        sample!=='service-failure');
      await fs.writeFile(path.join(directory,'viewer.html'),html);
      const capture = path.join(directory,'capture.json');
      await fs.writeFile(capture,JSON.stringify({cookie_jar:new CookieJar().serializeSync(),
        data:{source:{file:'viewer.html',url:'https://example.invalid/viewer',
          sha256:createHash('sha256').update(html).digest('hex')}}}));
      const output = path.join(directory,'output');
      const result = await saveReport({capture,output,timeout:2},{beforeParse(window){
        if (sample==='write-failure') window.addEventListener('load',()=>
          writeFileSync(path.join(output,'report.html'),'existing',{mode:0o600}));
      }});
      const saved = JSON.parse(await fs.readFile(path.join(output,'result.json'),'utf8'));
      assert.equal(result.branch,sample==='service-failure' ? 'failure' : 'success');
      assert.equal(saved.branch,result.branch);
      if (sample==='service-failure' || sample==='write-failure') {
        assert.equal(saved.artifact.saved,false);
        if (sample==='write-failure') {
          assert.ok(saved.warnings.length>0);
          assert.equal(await fs.readFile(path.join(output,'report.html'),'utf8'),'existing');
        }
      } else {
        assert.equal(saved.artifact.saved,true);
        assert.equal(saved.artifact.complete,sample!=='invalid',JSON.stringify(saved.artifact));
        assert.equal(saved.artifact.invalid_images,sample==='invalid' ? 1 : 0);
        const artifact = await fs.readFile(path.join(output,'report.html'),'utf8');
        if (sample==='jpeg') assert.ok(artifact.includes('data:image/jpeg;base64,'+jpg));
        const document = new (loadDOM().JSDOM)(artifact);
        try {
          assert.match(document.window.document.querySelector('image').getAttributeNS(
            'http://www.w3.org/1999/xlink','href'), /^data:image\//);
        } finally {document.window.close();}
        assert.equal((await fs.stat(path.join(output,'report.html'))).mode&0o777,0o600);
      }
    } finally {await fs.rm(directory,{recursive:true,force:true});}
  });
}
