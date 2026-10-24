const fs=require('node:fs'),path=require('node:path'),zlib=require('node:zlib');
const esbuild=require('esbuild'),terser=require('terser');
(async()=>{
 const bundle=await esbuild.build({entryPoints:[path.join(__dirname,'inflate-entry.js')],bundle:true,write:false,minify:true,format:'iife',globalName:'NpvInflate',platform:'browser',target:'es2020',legalComments:'none'});
 const tables=zlib.deflateSync(fs.readFileSync(path.join(__dirname,'lookups.raw')),{level:9}).toString('base64');
 const app=fs.readFileSync(path.join(__dirname,'app.js'),'utf8').replace('__LOOKUP_DATA_B64__',tables);
 const core=await terser.minify(app,{ecma:2020,toplevel:false,compress:{passes:2},mangle:{toplevel:false},format:{comments:false,ascii_only:false,inline_script:true}});
 let html=fs.readFileSync(path.join(__dirname,'template.html'),'utf8');
 html=html.replace(/<style>([\s\S]*?)<\/style>/,(_,css)=>'<style>'+esbuild.transformSync(css,{loader:'css',minify:true,legalComments:'none'}).code.trim()+'</style>');
 html=html.replace('__INFLATER_BUNDLE__',()=>bundle.outputFiles[0].text).replace('__APPLICATION_BUNDLE__',()=>core.code);
 const dir=path.join(__dirname,'dist');fs.mkdirSync(dir,{recursive:true});
 const destination=path.join(dir,'NPV-V2Ray-Extractor-v2.5.0.html');fs.writeFileSync(destination,html);fs.writeFileSync(path.join(__dirname,'index.html'),html);console.log(destination);
})().catch(e=>{console.error(e);process.exitCode=1;});
