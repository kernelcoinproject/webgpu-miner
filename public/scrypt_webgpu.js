// Bitcoin-style scrypt (N=1024, r=1, p=1) in a WebGPU compute kernel.
// Each invocation handles one nonce and stores its 128 KiB ROMix table in a
// scratch storage buffer. This is a correctness-first implementation.
const SCRYPT_WEBGPU_SHADER = /* wgsl */ `
const K: array<u32,64> = array<u32,64>(
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
);
const IV: array<u32,8> = array<u32,8>(0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u);
fn rotr(x:u32,n:u32)->u32 { return (x>>n)|(x<<(32u-n)); }
fn rotl(x:u32,n:u32)->u32 { return (x<<n)|(x>>(32u-n)); }
fn bswap(x:u32)->u32 { return ((x&0xffu)<<24u)|((x&0xff00u)<<8u)|((x&0xff0000u)>>8u)|((x&0xff000000u)>>24u); }
fn compress(s:array<u32,8>, block:array<u32,16>)->array<u32,8> {
  var w:array<u32,64>; for(var i=0u;i<16u;i++){w[i]=block[i];}
  for(var i=16u;i<64u;i++){let x=w[i-15u];let y=w[i-2u];let a=rotr(x,7u)^rotr(x,18u)^(x>>3u);let b=rotr(y,17u)^rotr(y,19u)^(y>>10u);w[i]=w[i-16u]+a+w[i-7u]+b;}
  var a=s[0];var b=s[1];var c=s[2];var d=s[3];var e=s[4];var f=s[5];var g=s[6];var h=s[7];
  for(var i=0u;i<64u;i++){let s1=rotr(e,6u)^rotr(e,11u)^rotr(e,25u);let ch=(e&f)^((~e)&g);let t1=h+s1+ch+K[i]+w[i];let s0=rotr(a,2u)^rotr(a,13u)^rotr(a,22u);let maj=(a&b)^(a&c)^(b&c);let t2=s0+maj;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  return array<u32,8>(s[0]+a,s[1]+b,s[2]+c,s[3]+d,s[4]+e,s[5]+f,s[6]+g,s[7]+h);
}
fn sha_header(h:array<u32,20>)->array<u32,8>{
  var b0:array<u32,16>;for(var i=0u;i<16u;i++){b0[i]=bswap(h[i]);}
  var s=compress(IV,b0);var b1:array<u32,16>;
  for(var i=0u;i<4u;i++){b1[i]=bswap(h[i+16u]);}b1[4]=0x80000000u;
  for(var i=5u;i<15u;i++){b1[i]=0u;}b1[15]=640u;
  return compress(s,b1);
}
fn hmac_header(prefix_i:array<u32,8>,prefix_o:array<u32,8>,h:array<u32,20>,ctr:u32)->array<u32,8>{
  var b0:array<u32,16>;for(var i=0u;i<16u;i++){b0[i]=bswap(h[i]);}
  var s=compress(prefix_i,b0);var b1:array<u32,16>;
  for(var i=0u;i<4u;i++){b1[i]=bswap(h[i+16u]);}b1[4]=ctr;b1[5]=0x80000000u;
  for(var i=6u;i<15u;i++){b1[i]=0u;}b1[15]=1184u;
  let inner=compress(s,b1);var outer:array<u32,16>;
  for(var i=0u;i<8u;i++){outer[i]=inner[i];}outer[8]=0x80000000u;
  for(var i=9u;i<15u;i++){outer[i]=0u;}outer[15]=768u;
  return compress(prefix_o,outer);
}
fn hmac_b(prefix_i:array<u32,8>,prefix_o:array<u32,8>,b:array<u32,32>)->array<u32,8>{
  var m0:array<u32,16>;var m1:array<u32,16>;
  for(var i=0u;i<16u;i++){m0[i]=bswap(b[i]);m1[i]=bswap(b[i+16u]);}
  var s=compress(prefix_i,m0);s=compress(s,m1);var m2:array<u32,16>;
  m2[0]=1u;m2[1]=0x80000000u;for(var i=2u;i<15u;i++){m2[i]=0u;}m2[15]=1568u;
  let inner=compress(s,m2);var outer:array<u32,16>;
  for(var i=0u;i<8u;i++){outer[i]=inner[i];}outer[8]=0x80000000u;
  for(var i=9u;i<15u;i++){outer[i]=0u;}outer[15]=768u;
  return compress(prefix_o,outer);
}
fn salsa8(input:array<u32,16>)->array<u32,16>{
  var x=input;
  for(var r=0u;r<4u;r++){
    x[4]=x[4]^rotl(x[0]+x[12],7u);x[8]=x[8]^rotl(x[4]+x[0],9u);x[12]=x[12]^rotl(x[8]+x[4],13u);x[0]=x[0]^rotl(x[12]+x[8],18u);
    x[9]=x[9]^rotl(x[5]+x[1],7u);x[13]=x[13]^rotl(x[9]+x[5],9u);x[1]=x[1]^rotl(x[13]+x[9],13u);x[5]=x[5]^rotl(x[1]+x[13],18u);
    x[14]=x[14]^rotl(x[10]+x[6],7u);x[2]=x[2]^rotl(x[14]+x[10],9u);x[6]=x[6]^rotl(x[2]+x[14],13u);x[10]=x[10]^rotl(x[6]+x[2],18u);
    x[3]=x[3]^rotl(x[15]+x[11],7u);x[7]=x[7]^rotl(x[3]+x[15],9u);x[11]=x[11]^rotl(x[7]+x[3],13u);x[15]=x[15]^rotl(x[11]+x[7],18u);
    x[1]=x[1]^rotl(x[0]+x[3],7u);x[2]=x[2]^rotl(x[1]+x[0],9u);x[3]=x[3]^rotl(x[2]+x[1],13u);x[0]=x[0]^rotl(x[3]+x[2],18u);
    x[6]=x[6]^rotl(x[5]+x[4],7u);x[7]=x[7]^rotl(x[6]+x[5],9u);x[4]=x[4]^rotl(x[7]+x[6],13u);x[5]=x[5]^rotl(x[4]+x[7],18u);
    x[11]=x[11]^rotl(x[10]+x[9],7u);x[8]=x[8]^rotl(x[11]+x[10],9u);x[9]=x[9]^rotl(x[8]+x[11],13u);x[10]=x[10]^rotl(x[9]+x[8],18u);
    x[12]=x[12]^rotl(x[15]+x[14],7u);x[13]=x[13]^rotl(x[12]+x[15],9u);x[14]=x[14]^rotl(x[13]+x[12],13u);x[15]=x[15]^rotl(x[14]+x[13],18u);
  }
  var out:array<u32,16>;for(var i=0u;i<16u;i++){out[i]=x[i]+input[i];}return out;
}
fn blockmix(input:array<u32,32>)->array<u32,32>{
  var x:array<u32,16>;var t:array<u32,16>;
  for(var i=0u;i<16u;i++){x[i]=input[i+16u];t[i]=x[i]^input[i];}
  let y0=salsa8(t);for(var i=0u;i<16u;i++){t[i]=y0[i]^input[i+16u];}
  let y1=salsa8(t);var out:array<u32,32>;
  for(var i=0u;i<16u;i++){out[i]=y0[i];out[i+16u]=y1[i];}return out;
}
@group(0) @binding(0) var<storage,read> header_words:array<u32>;
@group(0) @binding(1) var<storage,read> target_words:array<u32>;
@group(0) @binding(2) var<storage,read_write> result:array<atomic<u32>>;
@group(0) @binding(3) var<storage,read_write> scratch:array<u32>;
struct Params{start_nonce:u32,count:u32,};@group(0) @binding(4) var<uniform> params:Params;
@compute @workgroup_size(64)
fn mine_scrypt(@builtin(global_invocation_id) gid:vec3<u32>){
  if(gid.x>=params.count||atomicLoad(&result[0])!=0u){return;}
  let nonce=params.start_nonce+gid.x;var h:array<u32,20>;
  for(var i=0u;i<19u;i++){h[i]=header_words[i];}h[19]=nonce;
  let key_hash=sha_header(h);var ipad:array<u32,16>;var opad:array<u32,16>;
  for(var i=0u;i<16u;i++){var k=0u;if(i<8u){k=key_hash[i];}ipad[i]=k^0x36363636u;opad[i]=k^0x5c5c5c5cu;}
  let prefix_i=compress(IV,ipad);let prefix_o=compress(IV,opad);
  var b:array<u32,32>;
  for(var block=0u;block<4u;block++){let digest=hmac_header(prefix_i,prefix_o,h,block+1u);for(var j=0u;j<8u;j++){b[block*8u+j]=bswap(digest[j]);}}
  let base=gid.x*32768u;var x=b;
  for(var i=0u;i<1024u;i++){for(var j=0u;j<32u;j++){scratch[base+i*32u+j]=x[j];}x=blockmix(x);}
  for(var i=0u;i<1024u;i++){let j=x[16u]&1023u;for(var k=0u;k<32u;k++){x[k]=x[k]^scratch[base+j*32u+k];}x=blockmix(x);}
  let digest=hmac_b(prefix_i,prefix_o,x);var less=false;var decided=false;
  for(var j=0u;j<8u;j++){let word=bswap(digest[7u-j]);if(!decided&&word<target_words[j]){less=true;decided=true;}if(!decided&&word>target_words[j]){decided=true;}}
  if(less){let claim=atomicCompareExchangeWeak(&result[0],0u,1u);if(claim.exchanged){atomicStore(&result[1],nonce);for(var i=0u;i<8u;i++){atomicStore(&result[i+2u],digest[7u-i]);}}}
}
`;

const SCRYPT_WEBGPU_PARAMS = '';
async function createScryptWebGpuMiner() {
    if (!navigator.gpu) throw new Error('WebGPU is unavailable in this browser. Open the page on localhost and use a WebGPU-capable browser.');
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) throw new Error('No WebGPU adapter was found.');
    const device = await adapter.requestDevice();
    const shader = device.createShaderModule({ code: SCRYPT_WEBGPU_PARAMS + SCRYPT_WEBGPU_SHADER });
    const info = await shader.getCompilationInfo();
    const errors = info.messages.filter(message => message.type === 'error');
    if (errors.length) { device.destroy(); throw new Error(errors.map(m => `${m.lineNum}:${m.linePos} ${m.message}`).join('\n')); }
    const pipeline = await device.createComputePipelineAsync({ layout: 'auto', compute: { module: shader, entryPoint: 'mine_scrypt' } });
    // Each nonce needs 128 KiB of ROMix scratch. Keep mobile allocations modest.
    const maxByBinding = Math.floor((device.limits.maxStorageBufferBindingSize || 128 * 1024 * 1024) / (32768 * 4));
    const batchSize = Math.max(1, Math.min(256, maxByBinding));
    const headerBuffer = device.createBuffer({ size: 19*4, usage: GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_DST });
    const targetBuffer = device.createBuffer({ size: 32*4, usage: GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_DST });
    const resultBuffer = device.createBuffer({ size: 40, usage: GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_SRC|GPUBufferUsage.COPY_DST });
    const readBuffer = device.createBuffer({ size: 40, usage: GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST });
    const scratchBuffer = device.createBuffer({ size: batchSize*32768*4, usage: GPUBufferUsage.STORAGE });
    const paramsBuffer = device.createBuffer({ size: 8, usage: GPUBufferUsage.UNIFORM|GPUBufferUsage.COPY_DST });
    const bindGroup = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [headerBuffer,targetBuffer,resultBuffer,scratchBuffer,paramsBuffer].map((buffer,binding)=>({binding,resource:{buffer}})) });
    const head = new Uint32Array(19); const headView = new DataView(head.buffer); const targetWords = new Uint32Array(8);
    const zero = new Uint32Array(10); const result = new Uint32Array(10); let closed=false;
    return {
        async mineBatch(baseHeader,target,startNonce) {
            if(closed) throw new Error('WebGPU scrypt miner is closed.');
            for(let i=0;i<19;i++) headView.setUint32(i*4,(baseHeader[i*4]|(baseHeader[i*4+1]<<8)|(baseHeader[i*4+2]<<16)|(baseHeader[i*4+3]<<24))>>>0,true);
            for(let i=0;i<8;i++) targetWords[i]=((target[i*4]<<24)|(target[i*4+1]<<16)|(target[i*4+2]<<8)|target[i*4+3])>>>0;
            device.queue.writeBuffer(headerBuffer,0,head); device.queue.writeBuffer(targetBuffer,0,targetWords); device.queue.writeBuffer(resultBuffer,0,zero);
            device.queue.writeBuffer(paramsBuffer,0,new Uint32Array([startNonce>>>0,batchSize]));
            const encoder=device.createCommandEncoder();const pass=encoder.beginComputePass();pass.setPipeline(pipeline);pass.setBindGroup(0,bindGroup);pass.dispatchWorkgroups(Math.ceil(batchSize/64));pass.end();encoder.copyBufferToBuffer(resultBuffer,0,readBuffer,0,40);device.queue.submit([encoder.finish()]);
            await readBuffer.mapAsync(GPUMapMode.READ);result.set(new Uint32Array(readBuffer.getMappedRange()));readBuffer.unmap();
            return result[0]?{nonce:result[1],hash:new Uint8Array(result.buffer.slice(8,40)),checked:batchSize}:{nonce:null,hash:null,checked:batchSize};
        },
        close(){closed=true;device.destroy();}
    };
}
