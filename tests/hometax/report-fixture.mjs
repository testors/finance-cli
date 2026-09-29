// Synthetic ClipReport wire data, based on documentReader's public source.
import {PNG} from 'pngjs';
import jpeg from 'jpeg-js';
export const png=PNG.sync.write({width:1,height:1,data:Buffer.from([10,20,30,255])}).toString('base64');
export const jpg=jpeg.encode({width:1,height:1,data:Buffer.from([10,20,30,255])},90).data.toString('base64');
export function documentFixture() {
  const styles={a:[[0,2100,2970,0,0,0,0,0,1,0]],b:[[0,0]],
    c:[[0,16777215,0,16777215,0,16777215,16777215]],d:[[0,0,0]],e:[],f:[],g:[],h:[],
    i:[Array(13).fill(true)],j:[[2,0,0,0,100,0]],k:[]};
  const pages=Array.from({length:2},(_,index)=>({a:0,b:index,
    c:[{a:'SYNTHETIC_IMAGE_'+index,b:96,c:96,d:3,f:1,g:1,h:false}],
    d:[{a:'0,0,0,2100,2970,0,0',b:[[[0,'10,10,210,210,0,0,0,0,1,1,0',
      {a:'SYNTHETIC_IMAGE_'+index+',3,0,0'},[],{a:'0,,,null,0,0'},'FIXTURE',false]]],c:false,d:'null'}],
    e:null,f:null}));
  return {document:{a:'5.0',b:'SYNTHETIC_REPORT',c:'',d:'',e:'',f:'',g:styles,
    h:2,i:2,j:[],k:false,l:[],o:[{b:0,d:'report'}]},pageList:pages};
}
