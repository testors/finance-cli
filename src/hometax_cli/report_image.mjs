// Browser Image decoders sniff the bytes even when the original viewer labels
// its cached JPEG as data:image/png. Preserve the source bytes in the archive.
import runtimeRequire from './runtime_require.cjs';
const {PNG} = runtimeRequire('pngjs');
const jpeg = runtimeRequire('jpeg-js');

export function reportImage(bytes) {
  if (bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) {
    const image=PNG.sync.read(bytes);
    return {mime:'image/png',width:image.width,height:image.height};
  }
  if (bytes[0]===0xff && bytes[1]===0xd8) {
    const image=jpeg.decode(bytes,{useTArray:true});
    return {mime:'image/jpeg',width:image.width,height:image.height};
  }
  throw new Error('Unrecognized report image format');
}
