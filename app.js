
  "use strict";

  // Generated from the MIT-licensed lookup tables in FrontierTM/Pantegnos.
  const LOOKUP_DATA_B64 = "__LOOKUP_DATA_B64__";
  const SHIFT = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11];
  const SUPPORTED = ["vless://", "vmess://", "trojan://", "ss://"];
  let current = null;
  let pendingFile = null;
  let fileJob = 0;
  let previewIndex = null;
  let previewReturnFocus = null;

  function whiteboxBlock(input, lastTable=WB.last) {
    let state = SHIFT.map(i => input[i]);
    const mid = new Uint8Array(16);
    for (let col = 0; col < 4; col++) {
      const base = col * 4;
      const t0 = WB.ty[base][state[base]] >>> 0;
      const t1 = WB.ty[base+1][state[base+1]] >>> 0;
      const t2 = WB.ty[base+2][state[base+2]] >>> 0;
      const t3 = WB.ty[base+3][state[base+3]] >>> 0;
      for (let row = 0; row < 4; row++) {
        const idx = col * 24 + row * 6;
        const hiShift = 28 - row * 8, loShift = 24 - row * 8;
        const x1h = WB.xor[idx][(t0 >>> hiShift) & 15][(t1 >>> hiShift) & 15];
        const x2h = WB.xor[idx+1][(t2 >>> hiShift) & 15][(t3 >>> hiShift) & 15];
        const hi = WB.xor[idx+4][x1h][x2h];
        const x1l = WB.xor[idx+2][(t0 >>> loShift) & 15][(t1 >>> loShift) & 15];
        const x2l = WB.xor[idx+3][(t2 >>> loShift) & 15][(t3 >>> loShift) & 15];
        const lo = WB.xor[idx+5][x1l][x2l];
        mid[base+row] = ((hi << 4) | lo) & 255;
      }
    }
    state = new Uint8Array(16);
    for (let col = 0; col < 4; col++) {
      const base = col * 4;
      const t0 = WB.mbl[base][mid[base]] >>> 0;
      const t1 = WB.mbl[base+1][mid[base+1]] >>> 0;
      const t2 = WB.mbl[base+2][mid[base+2]] >>> 0;
      const t3 = WB.mbl[base+3][mid[base+3]] >>> 0;
      for (let row = 0; row < 4; row++) {
        const idx = col * 24 + row * 6;
        const hiShift = 28 - row * 8, loShift = 24 - row * 8;
        const x1h = WB.xor[idx][(t0 >>> hiShift) & 15][(t1 >>> hiShift) & 15];
        const x2h = WB.xor[idx+1][(t2 >>> hiShift) & 15][(t3 >>> hiShift) & 15];
        const hi = WB.xor[idx+4][x1h][x2h];
        const x1l = WB.xor[idx+2][(t0 >>> loShift) & 15][(t1 >>> loShift) & 15];
        const x2l = WB.xor[idx+3][(t2 >>> loShift) & 15][(t3 >>> loShift) & 15];
        const lo = WB.xor[idx+5][x1l][x2l];
        state[base+row] = ((hi << 4) | lo) & 255;
      }
    }
    const shifted = SHIFT.map(i => state[i]);
    return Uint8Array.from(shifted, (value, i) => lastTable[i][value]);
  }

  function increment(counter) {
    for (let i = 15; i >= 0; i--) {
      counter[i] = (counter[i] + 1) & 255;
      if (counter[i] !== 0) return;
    }
  }

  function decryptPayload(raw) {
    if (raw.length <= 16) throw new Error("The encrypted block is too short.");
    const counter = raw.slice(0, 16), ciphertext = raw.slice(16), out = new Uint8Array(ciphertext.length);
    for (let offset = 0; offset < ciphertext.length; offset += 16) {
      const key = whiteboxBlock(counter);
      increment(counter);
      const length = Math.min(16, ciphertext.length - offset);
      for (let i = 0; i < length; i++) out[offset+i] = ciphertext[offset+i] ^ key[i];
    }
    return out;
  }

  function decodeToken(token) {
    const clean = token.replace(/\s+/g, "");
    if (!clean) throw new Error("The data block is empty.");
    if (clean.length % 2 === 0 && /^[0-9a-f]+$/i.test(clean)) {
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i*2, i*2+2), 16);
      return bytes;
    }
    let b64 = clean.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - b64.length % 4) % 4);
    let binary;
    try { binary = atob(b64); } catch (_) { throw new Error("Invalid Base64 data."); }
    return Uint8Array.from(binary, ch => ch.charCodeAt(0));
  }

  function decodeBase64(value) {
    let text=String(value||"").replace(/\s+/g,"").replace(/-/g,"+").replace(/_/g,"/");
    text += "=".repeat((4-text.length%4)%4);
    let binary;
    try { binary=atob(text); } catch (_) { throw new Error("Invalid Base64 data in the NPVS header."); }
    return Uint8Array.from(binary,ch=>ch.charCodeAt(0));
  }

  function concatBytes(...parts) {
    const length=parts.reduce((sum,part)=>sum+part.length,0), out=new Uint8Array(length);
    let offset=0; for(const part of parts){out.set(part,offset);offset+=part.length;} return out;
  }

  const readU32BE=(bytes,offset)=>(((bytes[offset]*0x1000000)+(bytes[offset+1]<<16)+(bytes[offset+2]<<8)+bytes[offset+3])>>>0);
  const readU32LE=(bytes,offset)=>((bytes[offset]|(bytes[offset+1]<<8)|(bytes[offset+2]<<16)|(bytes[offset+3]<<24))>>>0);
  function writeU32LE(bytes,offset,value){bytes[offset]=value&255;bytes[offset+1]=(value>>>8)&255;bytes[offset+2]=(value>>>16)&255;bytes[offset+3]=(value>>>24)&255;}
  const rotl32=(value,bits)=>((value<<bits)|(value>>>(32-bits)))>>>0;

  function chachaQuarter(state,a,b,c,d) {
    state[a]=(state[a]+state[b])>>>0;state[d]=rotl32(state[d]^state[a],16);
    state[c]=(state[c]+state[d])>>>0;state[b]=rotl32(state[b]^state[c],12);
    state[a]=(state[a]+state[b])>>>0;state[d]=rotl32(state[d]^state[a],8);
    state[c]=(state[c]+state[d])>>>0;state[b]=rotl32(state[b]^state[c],7);
  }

  function chachaBlock(key,counter,nonce) {
    if(key.length!==32||nonce.length!==12)throw new Error("The NPVS key or nonce has an invalid length.");
    const initial=new Uint32Array(16), state=new Uint32Array(16);
    initial.set([0x61707865,0x3320646e,0x79622d32,0x6b206574]);
    for(let i=0;i<8;i++)initial[4+i]=readU32LE(key,i*4);
    initial[12]=counter>>>0;for(let i=0;i<3;i++)initial[13+i]=readU32LE(nonce,i*4);
    state.set(initial);
    for(let i=0;i<10;i++){
      chachaQuarter(state,0,4,8,12);chachaQuarter(state,1,5,9,13);chachaQuarter(state,2,6,10,14);chachaQuarter(state,3,7,11,15);
      chachaQuarter(state,0,5,10,15);chachaQuarter(state,1,6,11,12);chachaQuarter(state,2,7,8,13);chachaQuarter(state,3,4,9,14);
    }
    const out=new Uint8Array(64);for(let i=0;i<16;i++)writeU32LE(out,i*4,(state[i]+initial[i])>>>0);return out;
  }

  function chachaXor(key,nonce,input,counter=1) {
    const out=new Uint8Array(input.length);
    for(let offset=0;offset<input.length;offset+=64){
      const stream=chachaBlock(key,counter++,nonce), length=Math.min(64,input.length-offset);
      for(let i=0;i<length;i++)out[offset+i]=input[offset+i]^stream[i];
    }
    return out;
  }

  function littleBigInt(bytes) {
    let value=0n;for(let i=bytes.length-1;i>=0;i--)value=(value<<8n)|BigInt(bytes[i]);return value;
  }

  function poly1305(message,oneTimeKey) {
    const P=(1n<<130n)-5n, MASK128=(1n<<128n)-1n;
    const r=littleBigInt(oneTimeKey.slice(0,16))&0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s=littleBigInt(oneTimeKey.slice(16,32));let acc=0n;
    for(let offset=0;offset<message.length;offset+=16){
      const block=message.slice(offset,Math.min(offset+16,message.length));
      acc=((acc+littleBigInt(block)+(1n<<BigInt(block.length*8)))*r)%P;
    }
    let tag=(acc+s)&MASK128;const out=new Uint8Array(16);
    for(let i=0;i<16;i++){out[i]=Number(tag&255n);tag>>=8n;}return out;
  }

  function lengthBlock(aadLength,cipherLength) {
    const out=new Uint8Array(16);let a=BigInt(aadLength),c=BigInt(cipherLength);
    for(let i=0;i<8;i++){out[i]=Number(a&255n);a>>=8n;out[8+i]=Number(c&255n);c>>=8n;}return out;
  }

  function chachaTag(key,nonce,ciphertext,aad) {
    const padA=new Uint8Array((16-aad.length%16)%16), padC=new Uint8Array((16-ciphertext.length%16)%16);
    const macData=concatBytes(aad,padA,ciphertext,padC,lengthBlock(aad.length,ciphertext.length));
    return poly1305(macData,chachaBlock(key,0,nonce).slice(0,32));
  }

  function chachaOpen(key,nonce,cipherAndTag,aad) {
    if(cipherAndTag.length<16)throw new Error("The encrypted NPVS payload is incomplete.");
    const ciphertext=cipherAndTag.slice(0,-16), supplied=cipherAndTag.slice(-16), expected=chachaTag(key,nonce,ciphertext,aad);
    let difference=0;for(let i=0;i<16;i++)difference|=supplied[i]^expected[i];
    if(difference!==0)throw new Error("NPVS authentication failed.");
    return chachaXor(key,nonce,ciphertext,1);
  }

  function decodeNpvSentinelText(text) {
    let changed=false;
    const decoded=text.replace(/npvs1:([A-Za-z0-9+/_=-]+)/g,(whole,token)=>{
      try{const value=new TextDecoder("utf-8",{fatal:true}).decode(decodeBase64(token));changed=true;return value;}catch(_){return whole;}
    });
    return {decoded,changed};
  }

  function decodeNpvSentinels(value,depth=0) {
    if(depth>64)return value;
    if(typeof value==="string"){
      const result=decodeNpvSentinelText(value);
      if(!result.changed)return value;
      const trimmed=result.decoded.trim(), isNestedJson=(trimmed.startsWith("{")&&trimmed.endsWith("}"))||(trimmed.startsWith("[")&&trimmed.endsWith("]"));
      if(isNestedJson){try{return decodeNpvSentinels(JSON.parse(trimmed),depth+1);}catch(_){} }
      return result.decoded;
    }
    if(Array.isArray(value))return value.map(item=>decodeNpvSentinels(item,depth+1));
    if(value&&typeof value==="object"){
      for(const key of Object.keys(value))value[key]=decodeNpvSentinels(value[key],depth+1);
    }
    return value;
  }


  // Compact NPVS v5 decoding is adapted from Pantegnos (FrontierTM, 2026),
  // commit 20808af33e1b518c566f2d25cfa58ab4ed93aa2f, under AGPL-3.0.
  // NPVS v6 recipient binding was independently traced in the supplied APK
  // and verified with a fresh user export addressed to a known test key.
  // The complete source and third-party license are included in this HTML.
  const UTF8 = new TextEncoder();
  const strictUtf8 = bytes => new TextDecoder("utf-8", {fatal:true}).decode(bytes);
  const readU16BE = (bytes, off) => (bytes[off] << 8) | bytes[off+1];
  const be16 = n => Uint8Array.of(n >>> 8, n & 255);
  const be32 = n => Uint8Array.of(n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255);
  const isEnabled = value => value === true || value === 1 || /^(true|1|yes)$/i.test(String(value));
  let gen2Tables = null;
  let wbLastV2 = null;

  function npvError(message, code="INVALID_FILE") {
    const error = new Error(message); error.code = code; return error;
  }

  let WB = null;
  let lookupTablesPromise = null;
  const LOOKUP_BYTES = 815104;

  async function inflateLookupTables() {
    const packed=decodeBase64(LOOKUP_DATA_B64);
    let raw,decoder;
    try { if (typeof DecompressionStream==="function") decoder=new DecompressionStream("deflate"); } catch (_) {}
    if (decoder) {
      const reader=new Blob([packed]).stream().pipeThrough(decoder).getReader(),chunks=[];
      let size=0;
      try {
        for (;;) {
          const {done,value}=await reader.read();
          if (done) break;
          size+=value.length;
          if (size>LOOKUP_BYTES) { await reader.cancel();throw new Error("Lookup data is larger than expected."); }
          chunks.push(value);
        }
        raw=concatBytes(...chunks);
      } finally { reader.releaseLock(); }
    } else {
      raw=NpvInflate.unzlibSync(packed);
    }
    if (raw.length!==LOOKUP_BYTES) throw new Error("Lookup data is incomplete.");
    let a=1,b=0;
    for (let start=0;start<raw.length;start+=5552) {
      const end=Math.min(start+5552,raw.length);
      for (let i=start;i<end;i++) { a+=raw[i];b+=a; }
      a%=65521;b%=65521;
    }
    if (((b<<16|a)>>>0)!==readU32BE(packed,packed.length-4)) throw new Error("Lookup data checksum mismatch.");
    return raw;
  }

  function ensureLookupTables() {
    if (!lookupTablesPromise) {
      lookupTablesPromise=inflateLookupTables().then(raw=>{
        let off=0;
        const words=()=>Array.from({length:16},()=>{
          const row=new Uint32Array(256);
          for (let i=0;i<256;i++,off+=4) row[i]=readU32BE(raw,off);
          return row;
        });
        const ty=words(),mbl=words();
        const xor=Array.from({length:96},()=>Array.from({length:16},()=>{
          const row=raw.subarray(off,off+16);off+=16;return row;
        }));
        const lastRows=()=>Array.from({length:16},()=>{
          const row=raw.subarray(off,off+256);off+=256;return row;
        });
        const last=lastRows();
        wbLastV2=lastRows();
        gen2Tables=raw.subarray(off);
        WB={ty,mbl,xor,last};
      }).catch(error=>{
        lookupTablesPromise=null;WB=null;wbLastV2=null;gen2Tables=null;
        throw npvError("The embedded lookup data could not be loaded. Download the HTML again and retry.","LOOKUP_DATA_ERROR");
      });
    }
    return lookupTablesPromise;
  }

  function getGen2Tables() {
    if (!gen2Tables) throw npvError("The lookup tables have not finished loading.","LOOKUP_DATA_ERROR");
    return gen2Tables;
  }

  function getWbLastV2() {
    if (!wbLastV2) throw npvError("The lookup tables have not finished loading.","LOOKUP_DATA_ERROR");
    return wbLastV2;
  }

  function gen2Mix(tables, block, column, values) {
    const out = new Uint8Array(4), base = block + column*0x1800;
    const at = (table, a, b) => tables[base + table*256 + a*16 + b];
    for (let row=0; row<4; row++) {
      const hi=28-row*8, lo=24-row*8, t=row*6;
      const h1=at(t, values[0]>>>hi&15, values[1]>>>hi&15);
      const h2=at(t+1, values[2]>>>hi&15, values[3]>>>hi&15);
      const l1=at(t+2, values[0]>>>lo&15, values[1]>>>lo&15);
      const l2=at(t+3, values[2]>>>lo&15, values[3]>>>lo&15);
      out[row]=(at(t+4,h1,h2)<<4)|at(t+5,l1,l2);
    }
    return out;
  }

  function gen2A16(salt) {
    if (salt.length !== 16) throw npvError("The NPVS v5 salt must be 16 bytes.");
    const tables=getGen2Tables(); let state=salt.slice();
    for (let round=0; round<13; round++) {
      const block=round*57344;
      state=Uint8Array.from(SHIFT, i=>state[i]);
      for (let column=0; column<4; column++) {
        for (const half of [0x6000,0xa000]) {
          const base=block+half+column*0x1000, start=column*4;
          const values=Array.from({length:4}, (_,i)=>readU32BE(tables,base+i*0x400+state[start+i]*4));
          state.set(gen2Mix(tables,block,column,values),start);
        }
      }
    }
    return Uint8Array.from(SHIFT, (i,index)=>tables[13*57344+index*256+state[i]]);
  }

  async function hkdf256(ikm,salt,info) {
    if (!globalThis.crypto?.subtle) throw npvError("Web Crypto is required. Open this HTML in a recent Chrome, Edge or Firefox browser.");
    const key=await crypto.subtle.importKey("raw",ikm,"HKDF",false,["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt,info},key,256));
  }

  async function passphraseKey(passphrase,salt,iters) {
    if (!passphrase) throw npvError("This NPVS file requires a passphrase. Enter it and click Decrypt File.","PASSPHRASE_REQUIRED");
    if (!globalThis.crypto?.subtle) throw npvError("Web Crypto is required. Open this HTML in a recent Chrome, Edge or Firefox browser.");
    const key=await crypto.subtle.importKey("raw",UTF8.encode(passphrase),"PBKDF2",false,["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:iters},key,256));
  }

  const P256_P=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const P256_B=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

  function bigEndianInteger(bytes) {
    let n=0n;for(const byte of bytes)n=(n<<8n)|BigInt(byte);return n;
  }

  function expandP256Point(point) {
    if(point.length!==33||![2,3].includes(point[0]))throw npvError("The NPVS P-256 public key is invalid.");
    const x=bigEndianInteger(point.subarray(1));
    if(x>=P256_P)throw npvError("The NPVS P-256 public key is outside the curve.");
    const rhs=((x*x%P256_P*x-3n*x+P256_B)%P256_P+P256_P)%P256_P;
    let y=1n,base=rhs,power=(P256_P+1n)>>2n;
    while(power){if(power&1n)y=y*base%P256_P;base=base*base%P256_P;power>>=1n;}
    if(y*y%P256_P!==rhs)throw npvError("The NPVS P-256 public key is not on the curve.");
    if(Number(y&1n)!==(point[0]&1))y=P256_P-y;
    const raw=new Uint8Array(65);raw[0]=4;raw.set(point.subarray(1),1);
    for(let i=64;i>=33;i--){raw[i]=Number(y&255n);y>>=8n;}
    return raw;
  }

  function sameBytes(a,b) {
    if(a.length!==b.length)return false;
    let difference=0;for(let i=0;i<a.length;i++)difference|=a[i]^b[i];return difference===0;
  }

  async function readRecipientPrivateKey(text) {
    if(!globalThis.crypto?.subtle)throw npvError("Web Crypto is required. Open this HTML in a recent Chrome, Edge or Firefox browser.");
    let value=String(text||"").trim();
    if(value.length>65536)throw npvError("The private key file exceeds the 64 KB limit.","INVALID_PRIVATE_KEY");
    let encoded;
    try {
      if(value.startsWith("{")){
        const data=JSON.parse(value);
        value=data.private_key_pkcs8_pem||data.private_key_scalar_base64url||"";
        if(typeof value!=="string"||!value)throw new Error("missing private key");
      }
      const pem=value.match(/^-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----\s*$/);
      if(pem)encoded=decodeBase64(pem[1]);
      else {
        const scalar=/^[0-9a-f]{64}$/i.test(value)?Uint8Array.from(value.match(/../g),v=>parseInt(v,16)):decodeBase64(value);
        if(scalar.length===33&&[2,3].includes(scalar[0]))throw npvError("That is a public key. Load the matching private-key JSON or PEM file instead.","INVALID_PRIVATE_KEY");
        if(scalar.length!==32)throw new Error("private scalar size");
        // PKCS#8 containing a SEC1 P-256 scalar; Web Crypto derives its public point.
        encoded=concatBytes(Uint8Array.of(0x30,0x41,2,1,0,0x30,0x13,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7,4,0x27,0x30,0x25,2,1,1,4,0x20),scalar);
        scalar.fill(0);
      }
      const temporary=await crypto.subtle.importKey("pkcs8",encoded,{name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
      const jwk=await crypto.subtle.exportKey("jwk",temporary),x=decodeBase64(jwk.x),y=decodeBase64(jwk.y);
      const publicKey=concatBytes(Uint8Array.of(2|(y[31]&1)),x);
      const key=await crypto.subtle.importKey("jwk",jwk,{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
      return {key,publicKey};
    } catch(error) {
      if(error.code==="INVALID_PRIVATE_KEY")throw error;
      throw npvError("A P-256 private key is required. Load the recipient key JSON / PKCS#8 PEM file, or paste its 32-byte Base64url private key.","INVALID_PRIVATE_KEY");
    } finally { if(encoded)encoded.fill(0); }
  }

  async function verifyCompactSignature(e) {
    try {
      const key=await crypto.subtle.importKey("raw",expandP256Point(e.creator),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
      if(!await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,e.signature,e.signedData))throw new Error("signature mismatch");
    } catch(_) { throw npvError("The NPVS file signature could not be verified. The file may be damaged or modified.","AUTHENTICATION_FAILED"); }
  }

  async function unwrapCompactRecipient(e,keyText) {
    if(!String(keyText||"").trim())throw npvError(`NPVS v${e.version} detected: recipient protection (${e.recipients} recipient(s), ${e.rows.length} encrypted records). Load the matching recipient private-key JSON / PEM file, or paste its private key. A text passphrase cannot unlock this file.`,"RECIPIENT_KEY_REQUIRED");
    const identity=await readRecipientPrivateKey(keyText),fingerprint=await sha256(identity.publicKey);
    const recipient=e.recipientEntries.find(item=>sameBytes(item.fingerprint,fingerprint));
    if(!recipient)throw npvError("This private key does not match a recipient of this file. Export the file for its matching public key.","RECIPIENT_MISMATCH");
    if(e.version===6)await verifyCompactSignature(e);
    let shared,kek,masked,mix,pad;
    try {
      const wrap=recipient.wrap;
      const peer=await crypto.subtle.importKey("raw",expandP256Point(wrap.subarray(0,33)),{name:"ECDH",namedCurve:"P-256"},false,[]);
      shared=new Uint8Array(await crypto.subtle.deriveBits({name:"ECDH",public:peer},identity.key,256));
      kek=await hkdf256(shared,fingerprint,concatBytes(UTF8.encode("NPVS-v1-wrap"),e.configId));
      const aes=await crypto.subtle.importKey("raw",kek,"AES-GCM",false,["decrypt"]);
      masked=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:wrap.subarray(33,45),additionalData:fingerprint,tagLength:128},aes,wrap.subarray(45)));
      if(masked.length!==32)throw new Error("recipient key size");
      if(e.version===6){
        await ensureLookupTables();
        mix=await sha256(concatBytes(UTF8.encode("npvtunnel/appkey/v2 "),gen2A16(e.binding),e.configId));
        pad=await hkdf256(mix,e.binding,concatBytes(UTF8.encode("NPVS-v6/recipient-binding"),e.configId));
        for(let i=0;i<32;i++)masked[i]^=pad[i];
      }
      return masked.slice();
    } catch(error) {
      if(error.code==="LOOKUP_DATA_ERROR")throw error;
      throw npvError("The NPVS recipient key could not be authenticated. Check the private key and file.","AUTHENTICATION_FAILED");
    } finally { for(const secret of [shared,kek,masked,mix,pad])if(secret)secret.fill(0); }
  }


  function parseNpfBody(body) {
    if (body.length < 70 || body[0]!==78 || body[1]!==80 || body[2]!==70 || body[3]!==1)
      throw npvError("The compact NPVS body is not a supported NPF v1 record list.");
    const count=readU16BE(body,36), rows=[], seen=new Set(); let off=38;
    if (!count) throw npvError("The compact NPVS body contains no encrypted records.");
    for (let i=0;i<count;i++) {
      if (off+6>body.length-32) throw npvError("The NPVS record header is truncated.");
      const seq=readU16BE(body,off),flags=readU16BE(body,off+2),length=readU16BE(body,off+4);
      if (length<16||off+6+length>body.length-32) throw npvError("The NPVS encrypted record length is invalid.");
      if (seen.has(seq)) throw npvError("The NPVS file contains a duplicate encrypted record number.");
      seen.add(seq); rows.push({seq,flags,blob:body.subarray(off+6,off+6+length)}); off+=6+length;
    }
    if (off+32!==body.length) throw npvError("The NPVS record count or trailing body length is invalid.");
    return {contentId:body.subarray(4,36),rows};
  }

  function parseNpvsCompact(bytes) {
    const version=bytes[4], headerLength=readU32BE(bytes,5), headerEnd=9+headerLength;
    if (![5,6].includes(version)) throw npvError(`NPVS version ${version} is not supported.`);
    if (headerLength<57 || headerEnd+16+64>bytes.length) throw npvError("The compact NPVS header length is invalid.");
    const header=bytes.subarray(9,headerEnd);
    if (header[0]!==1) throw npvError(`Compact NPVS header version ${header[0]} is not supported.`);
    const method=header[50],recipients=readU16BE(header,51);
    if (![0,1,2].includes(method)) throw npvError(`NPVS unlock method ${method} is not supported.`);
    if (recipients>1024 || (method===0&&!recipients)) throw npvError("The NPVS recipient count is invalid.");
    // Both versions use 125-byte recipient entries. v6 adds one 16-byte
    // binding salt after the entire list, including multi-recipient files.
    const recipientEntries=[],seenRecipients=new Set();
    let off=53,iters=0,salt=null,wrap=null,binding=null;
    for(let i=0;i<recipients;i++){
      if(off+125>header.length)throw npvError("The compact NPVS recipient list is truncated.");
      const fingerprint=header.subarray(off,off+32),id=bytesToBase64(fingerprint);
      if(seenRecipients.has(id))throw npvError("The NPVS file contains a duplicate recipient fingerprint.");
      seenRecipients.add(id);recipientEntries.push({fingerprint,wrap:header.subarray(off+32,off+125)});off+=125;
    }
    if(version===6){
      if(!recipients||off+16>header.length)throw npvError("The NPVS v6 recipient binding is missing.");
      binding=header.subarray(off,off+16);off+=16;
    }
    if (off+4>header.length) throw npvError("The compact NPVS recipient list is truncated.");
    if (method===1) {
      if (off+84>header.length) throw npvError("The NPVS passphrase block is truncated.");
      iters=readU32BE(header,off);
      if (iters<1||iters>10000000) throw npvError("The NPVS PBKDF2 iteration count is invalid.");
      salt=header.subarray(off+4,off+20); wrap=header.subarray(off+20,off+80); off+=80;
    } else if (method===2) {
      if (off+82>header.length || readU16BE(header,off)!==2) throw npvError("The NPVS AppKey block is invalid.");
      salt=header.subarray(off+2,off+18); wrap=header.subarray(off+18,off+78); off+=78;
    }
    if (off+4>header.length) throw npvError("The NPVS sealed metadata length is missing.");
    const metaLength=readU32BE(header,off);
    if (metaLength<16||off+4+metaLength!==header.length) throw npvError("The NPVS sealed metadata length is invalid.");
    const nonce=bytes.subarray(headerEnd,headerEnd+12), bodyLength=readU32BE(bytes,headerEnd+12),bodyStart=headerEnd+16;
    if (bodyLength<70||bodyStart+bodyLength+64!==bytes.length) throw npvError("The NPVS encrypted body or signature length is invalid.");
    const records=parseNpfBody(bytes.subarray(bodyStart,bodyStart+bodyLength));
    return {kind:"compact",version,header,prefix:header.subarray(0,off),configId:header.subarray(1,17),creator:header.subarray(17,50),
      method,recipients,recipientEntries,binding,iters,salt,wrap,nonce,metaBlob:header.subarray(off+4),
      signedData:bytes.subarray(0,-64),signature:bytes.subarray(-64),...records};
  }

  function compactFieldText(bytes) {
    const text=strictUtf8(bytes).trim();
    if (text.startsWith('"')) { try { const value=JSON.parse(text); if (typeof value==="string") return value; } catch (_) {} }
    return text;
  }

  function substituteCompactFields(value,fields,depth=0) {
    if (depth>64) throw npvError("The NPVS configuration nesting is too deep.");
    if (typeof value==="number") {
      if (!Number.isInteger(value)||value<0||value>=65535||!fields.has(value)) throw npvError("The NPVS configuration references a missing encrypted record.");
      return decodeNpvSentinels(compactFieldText(fields.get(value)));
    }
    if (Array.isArray(value)) return value.map(item=>substituteCompactFields(item,fields,depth+1));
    if (value&&typeof value==="object") {
      const out=Object.create(null);
      for (const [key,item] of Object.entries(value)) out[key]=substituteCompactFields(item,fields,depth+1);
      return out;
    }
    return value;
  }

  async function decodeNpvsCompact(envelope,passphrase) {
    const e=envelope;
    let dek,kdk;
    if(e.method===0)dek=await unwrapCompactRecipient(e,passphrase);
    else {
      if(e.method===1&&!passphrase)await passphraseKey(passphrase,e.salt,e.iters);
      if(e.version===6)await verifyCompactSignature(e);
      if(e.method===2)kdk=await sha256(concatBytes(UTF8.encode("npvtunnel/appkey/v2 "),gen2A16(e.salt),e.configId));
      else kdk=await passphraseKey(passphrase,e.salt,e.iters);
      try { dek=chachaOpen(kdk,e.wrap.subarray(0,12),e.wrap.subarray(12),e.salt); }
      catch (_) { throw npvError(e.method===1?"The NPVS passphrase is incorrect, or the encrypted key is damaged.":`The NPVS v${e.version} AppKey could not be authenticated.`,e.method===1?"WRONG_PASSPHRASE":"AUTHENTICATION_FAILED"); }
      finally { if(kdk)kdk.fill(0); }
    }
    try {
    if (dek.length!==32) throw npvError("The unwrapped NPVS content key has an invalid length.");
    const metaKey=await hkdf256(dek,e.nonce,UTF8.encode("NPVS-v5/metadata"));
    let metadata;
    try { metadata=JSON.parse(strictUtf8(chachaOpen(metaKey,e.nonce,e.metaBlob,e.prefix))); }
    catch (_) { throw npvError("The NPVS sealed metadata could not be authenticated or decoded.","AUTHENTICATION_FAILED"); }
    const fields=new Map();
    for (const row of e.rows) {
      if (row.flags!==0) throw npvError(`NPVS record flags ${row.flags} are not supported.`);
      const seq=be16(row.seq),key=await hkdf256(dek,e.contentId,concatBytes(UTF8.encode("NPV-fields-v1/field/"),seq));
      const aad=concatBytes(UTF8.encode("NPV-fields-v1/record/"),e.contentId,seq,be32(row.blob.length-16));
      try { fields.set(row.seq,chachaOpen(key,new Uint8Array(12),row.blob,aad)); }
      catch (_) { throw npvError(`NPVS encrypted record ${row.seq} failed authentication. No partial result was exported.`,"AUTHENTICATION_FAILED"); }
    }
    const table=fields.get(65535);
    if (!table) throw npvError("The NPVS configuration reference table is missing.");
    let spec;
    try { spec=JSON.parse(strictUtf8(table)); } catch (_) { throw npvError("The NPVS configuration reference table is not valid JSON."); }
    if (!spec||!Array.isArray(spec.configs)) throw npvError("The NPVS reference table does not contain a configuration list.");
    const data={configs:substituteCompactFields(spec.configs,fields)};
    return {header:`NPVS v${e.version}`,payloadIndex:null,methodLabel:["P-256 recipient + ChaCha20","PBKDF2 + ChaCha20","AppKey v2 + ChaCha20"][e.method],data,metadata};
    } finally { if(dek)dek.fill(0); }
  }

  function envelopeInfo(e) {
    if (e.kind==="compact") return {format:`NPVS v${e.version}`,unlock:["Recipient private key","Passphrase (PBKDF2)","Application key"][e.method],
      records:String(e.rows.length),note:e.method===0?"Load the matching recipient private-key JSON / PEM file, or paste its private key, then click Decrypt File. A public key alone cannot unlock it.":
        e.method===1?"Enter the creator's exact passphrase, then click Decrypt File.":"The application key is included; no text passphrase is needed."};
    const h=e.header;
    return {format:`NPVS v${e.version}`,unlock:h.appKey?"Application key":h.passphrase?"Passphrase (PBKDF2)":Array.isArray(h.recipients)&&h.recipients.length?"Recipient private key":"Unknown",
      records:"—",note:h.appKey?"No text passphrase is needed.":h.passphrase?"Enter the creator's exact passphrase, then click Decrypt File.":"The required recipient-key unlock method is not implemented."};
  }

  function showFileInfo(info) {
    document.getElementById("fileInfo").hidden=false;
    document.getElementById("detectedFormat").textContent=info.format;
    document.getElementById("detectedUnlock").textContent=info.unlock;
    document.getElementById("detectedRecords").textContent=info.records;
    document.getElementById("detectedState").textContent="Encrypted";
    document.getElementById("fileInfoNote").textContent=info.note;
  }

  function parseNpvsEnvelope(bytes) {
    if (bytes.length<89) throw npvError("The NPVS file is too short or incomplete.");
    if (String.fromCharCode(...bytes.subarray(0,4))!=="NPVS") throw npvError("The NPVS signature was not found.");
    if (bytes[4]===5||bytes[4]===6) return parseNpvsCompact(bytes);
    if (bytes[4]>1) throw npvError(`NPVS version ${bytes[4]} is not supported.`);
    const headerLength=readU32BE(bytes,5),headerEnd=9+headerLength;
    if (headerLength<2||headerEnd+16+64>bytes.length) throw npvError("The NPVS header length is invalid.");
    const headerRaw=bytes.subarray(9,headerEnd); let header;
    try { header=JSON.parse(strictUtf8(headerRaw)); } catch (_) { throw npvError("The NPVS JSON header is corrupted."); }
    if (!header||typeof header!=="object"||Array.isArray(header)) throw npvError("The NPVS JSON header must be an object.");
    const nonce=bytes.subarray(headerEnd,headerEnd+12),bodyLength=readU32BE(bytes,headerEnd+12),bodyStart=headerEnd+16;
    if (bodyLength<16||bodyStart+bodyLength+64>bytes.length) throw npvError("The encrypted NPVS payload length is invalid.");
    return {kind:"json",version:bytes[4],header,headerRaw,nonce,body:bytes.subarray(bodyStart,bodyStart+bodyLength)};
  }

  async function sha256(bytes) {
    if(!globalThis.crypto?.subtle)throw new Error("This browser does not provide the Web Crypto support required for NPVS files.");
    return new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
  }

  async function unwrapNpvsKey(envelope,passphrase) {
    const h=envelope.header;
    if (h.appKey) {
      const a=h.appKey;
      if (a.kdf!=="wbaes-ctr-sha256"||a.keyId!==1) throw npvError("This NPVS AppKey method is not supported.");
      const salt=decodeBase64(a.salt),wrap=decodeBase64(a.wrap);
      if (salt.length!==16||wrap.length!==60) throw npvError("The NPVS AppKey structure is invalid.");
      for (const table of [WB.last,getWbLastV2()]) {
        const kdk=await sha256(concatBytes(UTF8.encode("npvtunnel/appkey/v1 "),whiteboxBlock(salt,table)));
        try { return {key:chachaOpen(kdk,wrap.subarray(0,12),wrap.subarray(12),salt),method:"AppKey + ChaCha20"}; } catch (_) {}
      }
      throw npvError("The NPVS AppKey could not be authenticated.","AUTHENTICATION_FAILED");
    }
    if (h.passphrase) {
      const p=h.passphrase;
      if (p.kdf!=="pbkdf2-hmac-sha256") throw npvError("This NPVS key-derivation method is not supported.");
      if (!Number.isInteger(p.iters)||p.iters<1||p.iters>10000000) throw npvError("The NPVS PBKDF2 iteration count is invalid.");
      const salt=decodeBase64(p.salt),wrap=decodeBase64(p.wrap);
      if (salt.length!==16||wrap.length!==60) throw npvError("The NPVS wrapped passphrase key structure is invalid.");
      const derived=await passphraseKey(passphrase,salt,p.iters);
      try { return {key:chachaOpen(derived,wrap.subarray(0,12),wrap.subarray(12),salt),method:"PBKDF2 + ChaCha20"}; }
      catch (_) { throw npvError("The NPVS passphrase is incorrect, or the file is damaged.","WRONG_PASSPHRASE"); }
    }
    if (Array.isArray(h.recipients)&&h.recipients.length) throw npvError("This NPVS file is recipient-protected. Recipient-private-key decryption is not implemented; a text passphrase cannot unlock it.","RECIPIENT_KEY_REQUIRED");
    throw npvError("The key-unwrapping method used by this NPVS file is not recognized.");
  }

  async function decodeNpvs(bytes,passphrase,envelope=parseNpvsEnvelope(bytes)) {
    if (envelope.kind==="compact") return decodeNpvsCompact(envelope,passphrase);
    const unwrapped=await unwrapNpvsKey(envelope,passphrase);
    let plaintext;
    try{plaintext=chachaOpen(unwrapped.key,envelope.nonce,envelope.body,envelope.headerRaw);}catch(_){throw new Error("The NPVS payload could not be decrypted. Check the key and file.");}
    let text;
    try{text=new TextDecoder("utf-8",{fatal:true}).decode(plaintext);}catch(_){throw new Error("The decrypted NPVS output is not valid UTF-8 text.");}
    let data;
    try{data=JSON.parse(text);}catch(_){
      const fallback=decodeNpvSentinelText(text);
      try{data=JSON.parse(fallback.decoded);}catch(_){throw new Error("The NPVS payload was decrypted, but it does not contain valid JSON.");}
    }
    data=decodeNpvSentinels(data);
    return {header:`NPVS v${envelope.version}`,payloadIndex:null,methodLabel:unwrapped.method,data,metadata:envelope.header};
  }

  function jsonScore(value) {
    let score = value && typeof value === "object" ? 100 : 0;
    const weights = {v2rayProfile:120, v2rayJson:100, outbounds:100, streamSettings:30, lockConfig:10};
    function walk(node, depth) {
      if (!node || typeof node !== "object" || depth > 20) return;
      if (Array.isArray(node)) { score += Math.min(node.length, 20); node.slice(0,1000).forEach(x => walk(x,depth+1)); return; }
      Object.entries(node).forEach(([k,v]) => { score += weights[k] || 0; walk(v,depth+1); });
    }
    walk(value, 0);
    return score;
  }

  function decodeLegacyContainer(text) {
    const match = text.match(/^\s*(NPVTSUB1|NPVT1)\s*/);
    if (!match) throw new Error("An NPVT1 or NPVTSUB1 header was not found.");
    const body = text.slice(match[0].length).trim();
    if (!body) throw new Error("The file does not contain any data.");
    const candidates = [];
    body.split(",").forEach((token, index) => {
      try {
        const raw = decodeToken(token);
        if (raw.length <= 16) return;
        const plain = decryptPayload(raw);
        const decoded = new TextDecoder("utf-8", {fatal:true}).decode(plain);
        const value = JSON.parse(decoded);
        candidates.push({score:jsonScore(value), index, value});
      } catch (_) {}
    });
    if (!candidates.length) throw new Error("No decryptable JSON was found. The file may be incomplete or use an unsupported format version.");
    candidates.sort((a,b) => b.score-a.score || a.index-b.index);
    return {header:match[1],payloadIndex:candidates[0].index,methodLabel:`Whitebox CTR · #${candidates[0].index+1}`,data:candidates[0].value};
  }

  async function decodeContainer(bytes,passphrase,onInspect) {
    if (bytes.length>=4&&bytes[0]===78&&bytes[1]===80&&bytes[2]===86&&bytes[3]===83) {
      const envelope=parseNpvsEnvelope(bytes);
      if (onInspect) onInspect(envelopeInfo(envelope));
      if ((envelope.kind==="json"&&envelope.header.appKey)||
          (envelope.kind==="compact"&&envelope.method===2)) await ensureLookupTables();
      return decodeNpvs(bytes,passphrase,envelope);
    }
    const text=new TextDecoder("utf-8").decode(bytes).trimStart();
    if (text.startsWith("NPVO1")) {
      let data;
      try { data=JSON.parse(text.slice(5).trim()); } catch (_) { throw npvError("The open NPVO1 payload is not valid JSON."); }
      if (!data||!Array.isArray(data.configs)||!data.configs.length) throw npvError("The open NPVO1 file contains no configuration list.");
      return {header:"NPVO1",payloadIndex:null,methodLabel:"Open export",data:decodeNpvSentinels(data)};
    }
    if (/^(NPVT1|NPVTSUB1)/.test(text)) await ensureLookupTables();
    return decodeLegacyContainer(text);
  }

  function parseJsonish(value) {
    if (value && typeof value === "object") return value;
    if (typeof value !== "string" || !/^[\s]*[\[{]/.test(value)) return null;
    try { return JSON.parse(value); } catch (_) { return null; }
  }

  function nameOf(config, fallback="") {
    for (const key of ["remarks","name","ps","tag"]) {
      if (typeof config?.[key] === "string" && config[key].trim()) return config[key].trim();
    }
    return fallback.trim() || "V2Ray config";
  }

  function collectConfigs(root) {
    const configs = [], links = [], seenConfig = new Set(), seenLink = new Set(), visited = new WeakSet();
    function addConfig(value, fallback) {
      const parsed = parseJsonish(value);
      if (!parsed || Array.isArray(parsed) || !Array.isArray(parsed.outbounds)) return;
      const canonical = JSON.stringify(parsed);
      if (seenConfig.has(canonical)) return;
      seenConfig.add(canonical);
      configs.push({name:nameOf(parsed, fallback), config:parsed});
    }
    function addProfile(value,fallback,address="") {
      if(!value||typeof value!=="object"||Array.isArray(value))return;
      const embedded=[value.v2rayJson,value.config].some(item=>{const parsed=parseJsonish(item);return parsed&&!Array.isArray(parsed)&&Array.isArray(parsed.outbounds);});
      if(embedded)return;
      if (!value.server&&!value.address&&address) value={...value,server:address};
      const name=nameOf(value,fallback), link=profileLink(value,name);if(!link)return;
      const canonical="profile:"+JSON.stringify(value);if(seenConfig.has(canonical))return;
      seenConfig.add(canonical);configs.push({name,config:value,directLinks:[link]});
    }
    function walk(value, inherited="", depth=0, inheritedAddress="") {
      if (depth > 40 || value == null) return;
      if (typeof value === "string") {
        const trimmed = value.trim();
        if (SUPPORTED.some(s => trimmed.toLowerCase().startsWith(s)) && !seenLink.has(trimmed)) { seenLink.add(trimmed); links.push(trimmed); }
        return;
      }
      if (typeof value !== "object" || visited.has(value)) return;
      visited.add(value);
      if (Array.isArray(value)) { value.forEach(v => walk(v,inherited,depth+1,inheritedAddress)); return; }
      let local = inherited;
      for (const key of ["name","remarks","ps"]) if (typeof value[key] === "string" && value[key].trim()) { local=value[key].trim(); break; }
      addConfig(value, local);
      const localAddress=typeof value.address==="string"?value.address:inheritedAddress;
      addProfile(value, local, localAddress);
      if (value.v2rayProfile && typeof value.v2rayProfile === "object") {
        addConfig(value.v2rayProfile.v2rayJson, local);
        addConfig(value.v2rayProfile.config, local);
      }
      addConfig(value.v2rayJson, local);
      Object.values(value).forEach(child => {
        const parsed = parseJsonish(child);
        walk(parsed && typeof child === "string" ? parsed : child, local, depth+1,localAddress);
      });
    }
    walk(root);
    return {configs, existingLinks:links};
  }

  const first = (obj, ...keys) => { for (const k of keys) { const v=obj?.[k]; if (v !== undefined && v !== null && v !== "" && (!Array.isArray(v) || v.length)) return v; } return ""; };
  const uriHost = value => { const s=String(value || "").trim(); return s.includes(":") && !(s.startsWith("[")&&s.endsWith("]")) ? `[${s}]` : s; };
  const query = pairs => pairs.filter(([,v]) => v !== undefined && v !== null && v !== "" && (!Array.isArray(v)||v.length)).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join("&");

  function transport(stream) {
    const network=String(stream.network || "tcp").toLowerCase(), q=[["type",network]], details={host:"",path:"",headerType:"none"};
    let s, host, path;
    if (network === "ws") {
      s=stream.wsSettings||{}; host=first(s,"host")||first(s.headers||{},"Host","host"); path=s.path||""; q.push(["path",path],["host",host]); Object.assign(details,{host,path});
    } else if (network === "grpc") {
      s=stream.grpcSettings||{}; path=s.serviceName||""; q.push(["serviceName",path]); if(s.multiMode)q.push(["mode","multi"]); details.path=path;
    } else if (network === "xhttp" || network === "splithttp") {
      s=stream.xhttpSettings||stream.splitHttpSettings||{}; host=s.host||""; path=s.path||""; q.push(["path",path],["host",host],["mode",s.mode||""],["extra",s.extra?JSON.stringify(s.extra):""]); Object.assign(details,{host,path});
    } else if (network === "httpupgrade") {
      s=stream.httpupgradeSettings||stream.httpUpgradeSettings||{}; host=s.host||""; path=s.path||""; q.push(["path",path],["host",host]); Object.assign(details,{host,path});
    } else if (network === "http" || network === "h2") {
      s=stream.httpSettings||stream.h2Settings||{}; host=Array.isArray(s.host)?(s.host[0]||""):(s.host||""); path=s.path||""; q.push(["path",path],["host",host]); Object.assign(details,{host,path});
    } else if (network === "kcp") {
      s=stream.kcpSettings||{}; details.headerType=s.header?.type||"none"; q.push(["headerType",details.headerType],["seed",s.seed||""]);
    } else if (network === "quic") {
      s=stream.quicSettings||{}; details.headerType=s.header?.type||"none"; q.push(["quicSecurity",s.security||"none"],["key",s.key||""],["headerType",details.headerType]);
    } else if (network === "tcp") {
      s=stream.tcpSettings||{}; details.headerType=s.header?.type||"none"; host=first(s.header?.request?.headers||{},"Host","host"); if(Array.isArray(host))host=host[0]||""; details.host=host; q.push(["headerType",details.headerType],["host",host]);
    }
    return {network,q,details};
  }

  function streamInfo(stream={}) {
    const out=transport(stream), security=String(stream.security||"none").toLowerCase(); out.q.push(["security",security]);
    if (security === "tls") {
      const s=stream.tlsSettings||{}, alpn=Array.isArray(s.alpn)?s.alpn.join(","):(s.alpn||"");
      out.q.push(["sni",s.serverName||""],["fp",s.fingerprint||""],["alpn",alpn],["allowInsecure",isEnabled(s.allowInsecure)?"1":""],["ech",s.echConfigList||""]);
      Object.assign(out.details,{sni:s.serverName||"",fp:s.fingerprint||"",alpn});
    } else if (security === "reality") {
      const s=stream.realitySettings||{}; out.q.push(["sni",s.serverName||""],["fp",s.fingerprint||""],["pbk",s.publicKey||""],["sid",s.shortId||""],["spx",s.spiderX||""]);
      Object.assign(out.details,{sni:s.serverName||"",fp:s.fingerprint||""});
    }
    return {...out,security};
  }

  function bytesToBase64(bytes) { let binary=""; const step=0x8000; for(let i=0;i<bytes.length;i+=step)binary+=String.fromCharCode(...bytes.subarray(i,i+step)); return btoa(binary); }
  const utf8Base64 = value => bytesToBase64(new TextEncoder().encode(value));

  function profileStream(profile={}) {
    const network=String(profile.network||"tcp").toLowerCase(), security=String(profile.security||"none").toLowerCase(), q=[["type",network],["security",security]];
    if(network==="ws")q.push(["path",profile.path||""],["host",profile.host||""]);
    else if(network==="grpc")q.push(["serviceName",profile.serviceName||profile.path||""],["authority",profile.authority||""],["mode",profile.mode||""]);
    else if(network==="xhttp"||network==="splithttp")q.push(["path",profile.path||""],["host",profile.host||""],["mode",profile.xhttpMode||profile.mode||""],["extra",typeof profile.xhttpExtra==="object"?JSON.stringify(profile.xhttpExtra):profile.xhttpExtra||""]);
    else if(network==="httpupgrade")q.push(["path",profile.path||""],["host",profile.host||""]);
    else if(network==="http"||network==="h2")q.push(["path",profile.path||""],["host",profile.host||""]);
    else q.push(["headerType",profile.headerType||"none"],["seed",profile.seed||""]);
    if(security==="tls"||security==="reality")q.push(["sni",profile.sni||""],["fp",profile.fingerPrint||profile.fingerprint||""],["alpn",profile.alpn||""],["allowInsecure",isEnabled(first(profile,"tlsAllowInsecure","insecure"))?"1":""],["ech",profile.echConfigList||""]);
    if(security==="reality")q.push(["pbk",profile.publicKey||""],["sid",profile.shortId||""],["spx",profile.spiderX||""]);
    return {network,security,q};
  }

  function profileLink(profile,name) {
    const type=Number(profile.configType), protocol=({1:"vmess",3:"shadowsocks",5:"vless",6:"trojan"})[type];
    const address=String(profile.server||profile.address||"").trim(), port=Number(profile.serverPort||profile.port), password=String(profile.password||"");
    if(!protocol||!address||!Number.isInteger(port)||port<1||port>65535||!password)return null;
    const stream=profileStream(profile);
    if(protocol==="vmess"){
      const payload={v:"2",ps:name,add:address,port:String(port),id:password,aid:String(profile.alterId||0),scy:String(profile.method||"auto"),net:stream.network,type:String(profile.headerType||"none"),host:String(profile.host||profile.authority||""),path:String(profile.path||profile.serviceName||""),tls:["tls","reality"].includes(stream.security)?"tls":"",sni:String(profile.sni||""),alpn:String(profile.alpn||""),fp:String(profile.fingerPrint||profile.fingerprint||"")};
      return {uri:"vmess://"+utf8Base64(JSON.stringify(payload)),protocol,address,port,transport:stream.network,security:stream.security};
    }
    if(protocol==="vless"){
      const q=[...stream.q,["encryption",profile.method||"none"],["flow",profile.flow||""],["packetEncoding",profile.packetEncoding||""]];
      return {uri:`vless://${encodeURIComponent(password)}@${uriHost(address)}:${port}?${query(q)}#${encodeURIComponent(name)}`,protocol,address,port,transport:stream.network,security:stream.security};
    }
    if(protocol==="trojan"){
      const q=[...stream.q,["flow",profile.flow||""]];
      return {uri:`trojan://${encodeURIComponent(password)}@${uriHost(address)}:${port}?${query(q)}#${encodeURIComponent(name)}`,protocol,address,port,transport:stream.network,security:stream.security};
    }
    const method=String(profile.method||"");if(!method)return null;
    const auth=utf8Base64(`${method}:${password}`).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
    return {uri:`ss://${auth}@${uriHost(address)}:${port}#${encodeURIComponent(name)}`,protocol,address,port,transport:"tcp",security:"none"};
  }

  function outboundLink(outbound, name) {
    const protocol=String(outbound.protocol||"").toLowerCase(), settings=outbound.settings||{}, stream=streamInfo(outbound.streamSettings||{});
    if (protocol === "vless" || protocol === "vmess") {
      const server=settings.vnext?.[0], user=server?.users?.[0]; if(!server||!user||!server.address||!server.port||!user.id)return null;
      if (protocol === "vless") {
        const q=[...stream.q,["encryption",user.encryption||"none"],["flow",user.flow||""],["packetEncoding",settings.packetEncoding||""]];
        return {uri:`vless://${encodeURIComponent(user.id)}@${uriHost(server.address)}:${server.port}?${query(q)}#${encodeURIComponent(name)}`,protocol,address:String(server.address),port:server.port,transport:stream.network,security:stream.security};
      }
      const d=stream.details, payload={v:"2",ps:name,add:String(server.address),port:String(server.port),id:String(user.id),aid:String(user.alterId||0),scy:String(user.security||"auto"),net:stream.network,type:String(d.headerType||"none"),host:String(d.host||""),path:String(d.path||""),tls:["tls","reality"].includes(stream.security)?"tls":"",sni:String(d.sni||""),alpn:String(d.alpn||""),fp:String(d.fp||"")};
      return {uri:"vmess://"+utf8Base64(JSON.stringify(payload)),protocol,address:String(server.address),port:server.port,transport:stream.network,security:stream.security};
    }
    if (protocol === "trojan") {
      const server=settings.servers?.[0]; if(!server||!server.address||!server.port||!server.password)return null;
      const q=[...stream.q,["flow",server.flow||""]];
      return {uri:`trojan://${encodeURIComponent(server.password)}@${uriHost(server.address)}:${server.port}?${query(q)}#${encodeURIComponent(name)}`,protocol,address:String(server.address),port:server.port,transport:stream.network,security:stream.security};
    }
    if (protocol === "shadowsocks") {
      const server=settings.servers?.[0]; if(!server||!server.address||!server.port||!server.method||!server.password)return null;
      const auth=utf8Base64(`${server.method}:${server.password}`).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
      return {uri:`ss://${auth}@${uriHost(server.address)}:${server.port}#${encodeURIComponent(name)}`,protocol,address:String(server.address),port:server.port,transport:"tcp",security:"none"};
    }
    return null;
  }

  function extract(decoded) {
    const found=collectConfigs(decoded.data), records=[], all=[], seen=new Set();
    found.configs.forEach(item => {
      const links=[...(item.directLinks||[])];
      (item.config.outbounds||[]).forEach(ob => { const x=outboundLink(ob,item.name); if(x&&!links.some(y=>y.uri===x.uri))links.push(x); });
      records.push({...item,links});
      links.forEach(x=>{if(!seen.has(x.uri)){seen.add(x.uri);all.push(x);}});
    });
    found.existingLinks.forEach(uri=>{if(!seen.has(uri)){seen.add(uri);all.push({uri,protocol:uri.split(":",1)[0],address:"",port:"",transport:"",security:""});}});
    return {decoded,records,links:all};
  }

  function formatNumber(value) { return new Intl.NumberFormat("en-US",{useGrouping:false}).format(value); }
  function safeName(value, fallback="config") { return (String(value||"").normalize("NFKC").replace(/[<>:"/\\|?*\x00-\x1f]/g,"_").replace(/\s+/g," ").trim().replace(/[. ]+$/g,"").slice(0,100)||fallback); }
  function setStatus(text, type="busy") { const el=document.getElementById("status"); el.className=`status show ${type==="error"?"error":type==="ok"?"ok":""}`; el.replaceChildren(); if(type==="busy"){const s=document.createElement("span");s.className="spinner";el.append(s);} const t=document.createElement("span");t.textContent=text;el.append(t); }
  function toast(text) { const el=document.getElementById("toast"); el.textContent=text; el.classList.add("show"); clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.classList.remove("show"),1800); }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (_) { const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.opacity="0"; document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
  }
  function download(name, text, type="text/plain;charset=utf-8") { const url=URL.createObjectURL(new Blob([text],{type})), a=document.createElement("a"); a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000); }

  function getPreviewRecord() {
    return current && Number.isInteger(previewIndex) ? current.result.records[previewIndex] : null;
  }

  function openPreview(index, returnFocus) {
    if(!current || !current.result.records[index])return;
    const record=current.result.records[index], links=record.links.map(item=>item.uri);
    previewIndex=index;previewReturnFocus=returnFocus||document.activeElement;
    document.getElementById("modalTitle").textContent=record.name||`Configuration ${index+1}`;
    document.getElementById("modalLinks").textContent=links.length?links.join("\n\n"):"No import link was generated for this configuration.";
    document.getElementById("modalJson").textContent=JSON.stringify(record.config,null,2);
    document.getElementById("copyModalLinks").disabled=!links.length;
    document.getElementById("configModal").hidden=false;
    document.body.style.overflow="hidden";
    document.getElementById("closeModal").focus();
  }

  function closePreview() {
    const modal=document.getElementById("configModal");
    if(modal.hidden)return;
    modal.hidden=true;document.body.style.overflow="";previewIndex=null;
    if(previewReturnFocus?.isConnected)previewReturnFocus.focus();
    previewReturnFocus=null;
  }

  function getFullJson() {
    if (!current) return "";
    if (current.prettyJson===undefined) current.prettyJson=JSON.stringify(current.result.decoded.data,null,2);
    return current.prettyJson;
  }

  function render(file, result) {
    current={file,result};
    document.getElementById("results").classList.add("show");
    document.getElementById("configCount").textContent=formatNumber(result.records.length);
    document.getElementById("linkCount").textContent=formatNumber(result.links.length);
    document.getElementById("headerType").textContent=result.decoded.header;
    document.getElementById("payloadIndex").textContent=result.decoded.methodLabel||"—";
    document.getElementById("sourceName").textContent=file.name;
    document.getElementById("rawJson").textContent=document.getElementById("jsonDetails").open?getFullJson():"";
    ["copyAll","downloadLinks","downloadSubscription"].forEach(id=>document.getElementById(id).disabled=!result.links.length);
    const tbody=document.getElementById("rows"); tbody.replaceChildren();
    if (!result.records.length) { const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=7;td.className="empty";td.textContent="The JSON was decrypted, but no supported outbound configurations were found.";tr.append(td);tbody.append(tr);return; }
    const fragment=document.createDocumentFragment();
    result.records.forEach((record,index)=>{
      const firstLink=record.links[0]||{}, tr=document.createElement("tr");
      const values=[formatNumber(index+1),record.name,record.links.map(x=>x.protocol).join(", ")||"—",firstLink.address?`${firstLink.address}:${firstLink.port}`:"—",firstLink.transport||"—",firstLink.security||"—"];
      values.forEach((value,i)=>{const td=document.createElement("td");td.textContent=value;if(i===1)td.className="name-cell";if(i===2){td.textContent="";const p=document.createElement("span");p.className="pill";p.textContent=value;td.append(p);}if(i===3)td.className="endpoint";if(i===5){td.textContent="";const p=document.createElement("span");p.className="pill sec";p.textContent=value;td.append(p);}tr.append(td);});
      const actions=document.createElement("td"),wrap=document.createElement("div");wrap.className="row-actions";
      const view=document.createElement("button");view.className="btn mini";view.textContent="View";view.dataset.view=String(index);
      const copy=document.createElement("button");copy.className="btn mini";copy.textContent="Copy Link";copy.disabled=!record.links.length;copy.dataset.copy=String(index);
      const save=document.createElement("button");save.className="btn mini";save.textContent="JSON";save.dataset.save=String(index);
      wrap.append(view,copy,save);actions.append(wrap);tr.append(actions);fragment.append(tr);
    });
    tbody.append(fragment);
  }

  async function processFile(file) {
    const job=++fileJob;
    pendingFile=file; current=null; closePreview();
    const retry=document.getElementById("retryDecrypt"),drop=document.getElementById("dropZone");
    retry.disabled=true;drop.classList.add("busy");
    document.getElementById("results").classList.remove("show");
    document.getElementById("fileInfo").hidden=true;
    document.getElementById("rawJson").textContent="";
    document.getElementById("rows").replaceChildren();
    setStatus("Reading the file and extracting configurations…");
    try {
      if (file.size>128*1024*1024) throw npvError("The file exceeds the 128 MB safety limit.");
      const bytes=new Uint8Array(await file.arrayBuffer());
      if (job!==fileJob) return;
      const passphrase=document.getElementById("npvsKey").value;
      const decoded=await decodeContainer(bytes,passphrase,info=>{if(job===fileJob)showFileInfo(info);});
      if (job!==fileJob) return;
      const result=extract(decoded);render(file,result);
      if (!document.getElementById("fileInfo").hidden) document.getElementById("detectedState").textContent="Opened";
      const action=decoded.header==="NPVO1"?"Read":"Decrypted";
      setStatus(`${action} successfully. Extracted ${formatNumber(result.records.length)} V2Ray configuration(s) and ${formatNumber(result.links.length)} link(s).${result.links.length?"":" Full JSON is available below."}`,"ok");
    } catch (error) {
      if (job!==fileJob) return;
      current=null;setStatus(error?.message||String(error),"error");
      if (!document.getElementById("fileInfo").hidden) document.getElementById("detectedState").textContent=error.code==="RECIPIENT_KEY_REQUIRED"?"Recipient locked":error.code==="RECIPIENT_MISMATCH"?"Key mismatch":error.code==="UNSUPPORTED_CRYPTO"?"Inspection only":"Not opened";
      if (["PASSPHRASE_REQUIRED","WRONG_PASSPHRASE","RECIPIENT_KEY_REQUIRED","INVALID_PRIVATE_KEY","RECIPIENT_MISMATCH"].includes(error.code)) document.getElementById("npvsKey").focus();
    } finally {
      if (job===fileJob) { drop.classList.remove("busy");retry.disabled=false; }
    }
  }

  document.getElementById("jsonDetails").addEventListener("toggle",()=>{
    if (current&&document.getElementById("jsonDetails").open) document.getElementById("rawJson").textContent=getFullJson();
  });

  let keyFileJob=0;
  document.getElementById("npvsKey").addEventListener("input",()=>{keyFileJob++;});
  document.getElementById("loadPrivateKey").addEventListener("click",()=>document.getElementById("keyFileInput").click());
  document.getElementById("keyFileInput").addEventListener("change",async event=>{
    const file=event.target.files[0];event.target.value="";if(!file)return;
    const job=++keyFileJob;
    try {
      if(file.size>65536)throw npvError("The private key file exceeds the 64 KB limit.","INVALID_PRIVATE_KEY");
      let text=await file.text();
      await readRecipientPrivateKey(text);
      if(job!==keyFileJob)return;
      if(text.trim().startsWith("{")){
        const data=JSON.parse(text);text=data.private_key_scalar_base64url||data.private_key_pkcs8_pem;
      }
      const field=document.getElementById("npvsKey");field.value=text.trim();field.type="password";
      document.getElementById("toggleKey").textContent="Show";
      if(pendingFile)await processFile(pendingFile);else toast("Private key loaded. Choose an NPVS file.");
    } catch(error) {
      if(job!==keyFileJob)return;
      fileJob++;current=null;closePreview();
      document.getElementById("results").classList.remove("show");
      document.getElementById("rows").replaceChildren();document.getElementById("rawJson").textContent="";
      if(!document.getElementById("fileInfo").hidden)document.getElementById("detectedState").textContent="Not opened";
      document.getElementById("retryDecrypt").disabled=!pendingFile;
      document.getElementById("dropZone").classList.remove("busy");
      setStatus(error.message||"The private key file could not be read.","error");
    }
  });

  const drop=document.getElementById("dropZone"), input=document.getElementById("fileInput");
  drop.addEventListener("click",()=>input.click());
  drop.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();input.click();}});
  input.addEventListener("change",()=>{if(input.files[0])processFile(input.files[0]);input.value="";});
  ["dragenter","dragover"].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();drop.classList.add("drag");}));
  ["dragleave","drop"].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();drop.classList.remove("drag");}));
  drop.addEventListener("drop",e=>{const file=e.dataTransfer.files[0];if(file)processFile(file);});

  document.getElementById("retryDecrypt").addEventListener("click",()=>{if(pendingFile)processFile(pendingFile);});
  document.getElementById("npvsKey").addEventListener("keydown",e=>{if(e.key==="Enter"&&pendingFile){e.preventDefault();processFile(pendingFile);}});
  document.getElementById("toggleKey").addEventListener("click",()=>{const field=document.getElementById("npvsKey"),button=document.getElementById("toggleKey"),show=field.type==="password";field.type=show?"text":"password";button.textContent=show?"Hide":"Show";field.focus();});

  document.getElementById("rows").addEventListener("click",async e=>{
    const button=e.target.closest("button");if(!button||!current)return;
    if(button.dataset.view!==undefined)openPreview(Number(button.dataset.view),button);
    if(button.dataset.copy!==undefined){const record=current.result.records[Number(button.dataset.copy)];await copyText(record.links.map(x=>x.uri).join("\n"));toast("Link copied");}
    if(button.dataset.save!==undefined){const record=current.result.records[Number(button.dataset.save)];download(`${String(Number(button.dataset.save)+1).padStart(3,"0")}_${safeName(record.name)}.json`,JSON.stringify(record.config,null,2)+"\n","application/json;charset=utf-8");}
  });
  document.getElementById("closeModal").addEventListener("click",closePreview);
  document.getElementById("configModal").addEventListener("click",e=>{if(e.target===e.currentTarget)closePreview();});
  document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!document.getElementById("configModal").hidden)closePreview();});
  document.getElementById("copyModalLinks").addEventListener("click",async()=>{const record=getPreviewRecord();if(!record||!record.links.length)return;await copyText(record.links.map(item=>item.uri).join("\n"));toast("Link(s) copied");});
  document.getElementById("copyModalJson").addEventListener("click",async()=>{const record=getPreviewRecord();if(!record)return;await copyText(JSON.stringify(record.config,null,2));toast("JSON copied");});
  document.getElementById("downloadModalJson").addEventListener("click",()=>{const record=getPreviewRecord();if(!record)return;download(`${String(previewIndex+1).padStart(3,"0")}_${safeName(record.name)}.json`,JSON.stringify(record.config,null,2)+"\n","application/json;charset=utf-8");});
  document.getElementById("copyAll").addEventListener("click",async()=>{if(!current)return;await copyText(current.result.links.map(x=>x.uri).join("\n"));toast("All links copied");});
  document.getElementById("downloadLinks").addEventListener("click",()=>{if(!current)return;download(`${safeName(current.file.name.replace(/\.(?:npvt|npvs)$/i,""))}.links.txt`,current.result.links.map(x=>x.uri).join("\n")+"\n");});
  document.getElementById("downloadSubscription").addEventListener("click",()=>{if(!current)return;const text=current.result.links.map(x=>x.uri).join("\n")+"\n";download(`${safeName(current.file.name.replace(/\.(?:npvt|npvs)$/i,""))}.subscription.txt`,utf8Base64(text)+"\n");});
  document.getElementById("downloadJson").addEventListener("click",()=>{if(!current)return;download(`${safeName(current.file.name.replace(/\.(?:npvt|npvs)$/i,""))}.decrypted.json`,getFullJson()+"\n","application/json;charset=utf-8");});
  
