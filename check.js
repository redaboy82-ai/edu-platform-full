const fs=require('fs'),vm=require('vm');
new vm.Script(fs.readFileSync('/mnt/data/edu-final-work/server.js','utf8'));
const h=fs.readFileSync('/mnt/data/edu-final-work/public/index.html','utf8');
const scripts=[...h.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]);
for(let i=0;i<scripts.length;i++) new vm.Script(scripts[i]);
console.log('server and UI syntax OK');
