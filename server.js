const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const GAMES_DIR = path.join(ROOT, 'games');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(ROOT, 'public');
fs.mkdirSync(DATA_DIR, {recursive:true});
fs.mkdirSync(GAMES_DIR, {recursive:true});

const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    const actual = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(actual,'hex'));
  } catch { return false; }
}
function uid(prefix='id') { return `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`; }
function code(prefix='P') { return `${prefix}-${Math.random().toString(36).slice(2,7).toUpperCase()}`; }
function cleanPhone(v) { return String(v||'').replace(/[^0-9]/g,'').replace(/^00/,''); }
function readDB(){
  try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); }
  catch {
    const adminPassword = process.env.ADMIN_PASSWORD || '135790          ';
    const db = {settings:{schoolName:'منصّة الدروس', autoWhatsApp:true}, classes:[], students:[], videos:[], games:[], results:[], admin:{id:'admin',username:process.env.ADMIN_USERNAME||'admin',passwordHash:hashPassword(adminPassword)}};
    writeDB(db); return db;
  }
}
function writeDB(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2), 'utf8'); }
let db = readDB();

function json(res,status,obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Content-Length':Buffer.byteLength(body)});
  res.end(body);
}
function text(res,status,body,type='text/plain; charset=utf-8'){
  res.writeHead(status, {'Content-Type':type,'Cache-Control':'no-store','Content-Length':Buffer.byteLength(body)}); res.end(body);
}
async function body(req){
  return await new Promise((resolve,reject)=>{
    let data=''; req.on('data',c=>{ if(data.length<15*1024*1024) data+=c; }); req.on('end',()=>resolve(data)); req.on('error',reject);
  });
}
function auth(req){
  const token = (req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  const session = token && sessions.get(token);
  if(!session) return null;
  if(session.expires < Date.now()){sessions.delete(token); return null;}
  session.expires = Date.now()+8*60*60*1000;
  return session;
}
function requireRole(req,res,roles){
  const a=auth(req); if(!a || !roles.includes(a.role)){json(res,401,{error:'غير مصرح'});return null;} return a;
}
function studentPublic(st, teacher=false){const base={id:st.id,name:st.name,username:st.username,classId:st.classId,phone:st.phone||'',parentName:st.parentName||'',parentPhone:st.parentPhone||'',parentCode:st.parentCode,permissions:st.permissions||{video:true,game:true}};if(teacher){base.initialPassword=st.initialPassword||'';base.initialParentPassword=st.initialParentPassword||'';}return base;}
function classPublic(c){return {...c};}
function gamePublic(g){return {id:g.id,title:g.title,classId:g.classId,description:g.description||'',filename:g.filename||''};}
function resultPublic(r){return {...r};}

async function handle(req,res){
  const url = new URL(req.url, `http://${req.headers.host||'localhost'}`);
  const pathname=url.pathname;
  if(req.method==='GET' && pathname==='/api/health') return json(res,200,{ok:true});
  if(req.method==='GET' && pathname==='/') return serveFile(path.join(PUBLIC_DIR,'index.html'),res);
  if(req.method==='GET' && pathname.startsWith('/assets/')) return serveFile(path.join(PUBLIC_DIR,pathname.slice(8)),res);
  if(req.method==='GET' && pathname.startsWith('/game/')){
    const id=path.basename(pathname);
    const g=db.games.find(x=>x.id===id); if(!g) return text(res,404,'اللعبة غير موجودة');
    const f=path.join(GAMES_DIR,g.filename); if(!fs.existsSync(f)) return text(res,404,'ملف اللعبة غير موجود');
    return serveFile(f,res,'text/html; charset=utf-8',false);
  }
  if(req.method==='POST' && pathname==='/api/login'){
    const b=JSON.parse(await body(req)||'{}'); const role=b.role; const username=String(b.username||'').trim(); const password=String(b.password||'');
    let user=null;
    if(role==='teacher'){
      if(username===db.admin.username && verifyPassword(password,db.admin.passwordHash)) user={id:db.admin.id,role:'teacher',name:'المعلم / الإدارة'};
    } else if(role==='student'){
      user=db.students.find(s=>s.username===username && verifyPassword(password,s.passwordHash)); if(user) user={id:user.id,role:'student',name:user.name};
    } else if(role==='parent'){
      user=db.students.find(s=>s.parentCode===username && verifyPassword(password,s.parentPasswordHash)); if(user) user={id:user.id,role:'parent',name:safeParentName(user)};
    }
    if(!user) return json(res,401,{error:'بيانات الدخول غير صحيحة'});
    const token=crypto.randomBytes(32).toString('hex'); sessions.set(token,{...user,expires:Date.now()+8*60*60*1000});
    return json(res,200,{token,user});
  }
  if(req.method==='POST' && pathname==='/api/logout'){
    const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); if(token)sessions.delete(token); return json(res,200,{ok:true});
  }
  if(req.method==='GET' && pathname==='/api/me'){
    const a=auth(req); if(!a)return json(res,401,{error:'انتهت الجلسة'}); return json(res,200,{user:a});
  }
  if(req.method==='POST' && pathname==='/api/admin/password'){if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.password||String(b.password).length<6)return json(res,400,{error:'كلمة المرور يجب أن تكون 6 أحرف على الأقل'});db.admin.passwordHash=hashPassword(b.password);db.admin.passwordChangedAt=Date.now();writeDB(db);return json(res,200,{ok:true});}
  if(req.method==='GET' && pathname==='/api/teacher/dashboard'){
    if(!requireRole(req,res,['teacher']))return; return json(res,200,{settings:db.settings,classes:db.classes.map(classPublic),students:db.students.map(x=>studentPublic(x,true)),videos:(db.videos||[]),games:db.games.map(gamePublic),results:db.results.map(resultPublic).reverse()});
  }
  if(req.method==='POST' && pathname==='/api/classes'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.name)return json(res,400,{error:'اسم الصف مطلوب'}); const c={id:uid('class'),name:String(b.name).trim(),subject:String(b.subject||'').trim(),createdAt:Date.now()}; db.classes.push(c);writeDB(db);return json(res,201,{class:c});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/classes/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname); const c=db.classes.find(x=>x.id===id);if(!c)return json(res,404,{error:'الصف غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(c,{name:String(b.name||c.name).trim(),subject:String(b.subject??c.subject).trim()});writeDB(db);return json(res,200,{class:c});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/classes/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);db.classes=db.classes.filter(x=>x.id!==id);db.students.forEach(s=>{if(s.classId===id)s.classId=''});writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='POST' && pathname==='/api/students'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.name||!b.classId||!b.parentPhone)return json(res,400,{error:'أكمل اسم الطالب والصف ورقم ولي الأمر'}); if(!db.classes.some(c=>c.id===b.classId))return json(res,400,{error:'الصف غير موجود'});
    let username=String(b.username||'').trim()||`student_${Math.random().toString(36).slice(2,7)}`; while(db.students.some(s=>s.username===username))username+=Math.floor(Math.random()*9);
    let password=String(b.password||'').trim()||Math.random().toString(36).slice(2,8); const parentPassword=String(b.parentPassword||'').trim()||Math.random().toString(36).slice(2,8);
    const st={id:uid('student'),name:String(b.name).trim(),classId:b.classId,phone:cleanPhone(b.phone),parentName:String(b.parentName||'').trim(),parentPhone:cleanPhone(b.parentPhone),username,passwordHash:hashPassword(password),parentCode:code('P'),parentPasswordHash:hashPassword(parentPassword),initialPassword:password,initialParentPassword:parentPassword,permissions:{video:true,game:true},createdAt:Date.now()};db.students.push(st);writeDB(db);return json(res,201,{student:studentPublic(st),credentials:{username,password,parentCode:st.parentCode,parentPassword}});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/students/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);const st=db.students.find(x=>x.id===id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(st,{name:String(b.name??st.name).trim(),classId:b.classId??st.classId,phone:cleanPhone(b.phone??st.phone),parentName:String(b.parentName??st.parentName).trim(),parentPhone:cleanPhone(b.parentPhone??st.parentPhone)});if(b.password){st.passwordHash=hashPassword(b.password);st.initialPassword=b.password;}if(b.parentPassword){st.parentPasswordHash=hashPassword(b.parentPassword);st.initialParentPassword=b.parentPassword;}writeDB(db);return json(res,200,{student:studentPublic(st)});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/students/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);db.students=db.students.filter(x=>x.id!==id);db.results=db.results.filter(x=>x.studentId!==id);writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='PATCH' && pathname.match(/^\/api\/students\/[^/]+\/permissions$/)){
    if(!requireRole(req,res,['teacher']))return; const id=pathname.split('/')[3];const st=db.students.find(x=>x.id===id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const b=JSON.parse(await body(req)||'{}');st.permissions={...st.permissions,...b};writeDB(db);return json(res,200,{student:studentPublic(st)});
  }
  if(req.method==='POST' && pathname==='/api/videos'){if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.title||!b.url||!b.classId)return json(res,400,{error:'أكمل عنوان الفيديو والرابط والصف'});const v={id:uid('video'),title:String(b.title).trim(),url:String(b.url).trim(),classId:b.classId,description:String(b.description||'').trim(),createdAt:Date.now()};db.videos=db.videos||[];db.videos.push(v);writeDB(db);return json(res,201,{video:v});}
  if(req.method==='PUT' && pathname.startsWith('/api/videos/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);db.videos=db.videos||[];const v=db.videos.find(x=>x.id===id);if(!v)return json(res,404,{error:'الفيديو غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(v,{title:String(b.title||v.title).trim(),url:String(b.url||v.url).trim(),classId:b.classId||v.classId,description:String(b.description??v.description).trim()});writeDB(db);return json(res,200,{video:v});}
  if(req.method==='DELETE' && pathname.startsWith('/api/videos/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);db.videos=(db.videos||[]).filter(x=>x.id!==id);writeDB(db);return json(res,200,{ok:true});}
  if(req.method==='POST' && pathname==='/api/games'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.title||!b.classId||!b.html)return json(res,400,{error:'اسم اللعبة والصف وملف HTML مطلوبة'});if(Buffer.byteLength(b.html,'utf8')>12*1024*1024)return json(res,400,{error:'حجم اللعبة أكبر من 12MB'});
    const id=uid('game'),filename=id+'.html';fs.writeFileSync(path.join(GAMES_DIR,filename),String(b.html),'utf8');const g={id,title:String(b.title).trim(),classId:b.classId,description:String(b.description||'').trim(),filename,createdAt:Date.now()};db.games.push(g);writeDB(db);return json(res,201,{game:gamePublic(g)});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/games/')){
    if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const g=db.games.find(x=>x.id===id);if(!g)return json(res,404,{error:'اللعبة غير موجودة'});const b=JSON.parse(await body(req)||'{}');Object.assign(g,{title:String(b.title??g.title).trim(),classId:b.classId??g.classId,description:String(b.description??g.description).trim()});if(b.html){if(Buffer.byteLength(b.html,'utf8')>12*1024*1024)return json(res,400,{error:'حجم اللعبة أكبر من 12MB'});fs.writeFileSync(path.join(GAMES_DIR,g.filename),String(b.html),'utf8');}writeDB(db);return json(res,200,{game:gamePublic(g)});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/games/')){
    if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const g=db.games.find(x=>x.id===id);if(g){try{fs.unlinkSync(path.join(GAMES_DIR,g.filename))}catch{}}db.games=db.games.filter(x=>x.id!==id);writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='GET' && pathname==='/api/student/me'){
    const a=requireRole(req,res,['student']);if(!a)return;const st=db.students.find(x=>x.id===a.id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const games=db.games.filter(g=>g.classId===st.classId&&st.permissions?.game);const videos=(db.videos||[]).filter(v=>v.classId===st.classId&&st.permissions?.video);const results=db.results.filter(r=>r.studentId===st.id).reverse();return json(res,200,{student:studentPublic(st),class:classPublic(db.classes.find(c=>c.id===st.classId)||{name:'بدون صف'}),games:games.map(gamePublic),videos,results});
  }
  if(req.method==='GET' && pathname==='/api/parent/me'){
    const a=requireRole(req,res,['parent']);if(!a)return;const st=db.students.find(x=>x.id===a.id);const games=db.games.filter(g=>g.classId===st.classId);const results=db.results.filter(r=>r.studentId===st.id).reverse();return json(res,200,{student:studentPublic(st),class:classPublic(db.classes.find(c=>c.id===st.classId)||{name:'بدون صف'}),games:games.map(gamePublic),results});
  }
  if(req.method==='POST' && pathname==='/api/results'){
    const a=requireRole(req,res,['student','teacher']);if(!a)return;const b=JSON.parse(await body(req)||'{}');const stId=a.role==='student'?a.id:b.studentId;const st=db.students.find(x=>x.id===stId);const g=db.games.find(x=>x.id===b.gameId);if(!st||!g)return json(res,400,{error:'الطالب أو اللعبة غير موجود'});let score=Number(b.score),total=Number(b.total);if(!Number.isFinite(score)||!Number.isFinite(total)||total<=0)return json(res,400,{error:'النتيجة غير صالحة'});score=Math.max(0,Math.min(total,score));const pct=Math.round(score/total*100);const r={id:uid('result'),studentId:st.id,studentName:st.name,gameId:g.id,gameTitle:g.title,score,total,percentage:pct,parentPhone:st.parentPhone,parentName:st.parentName,createdAt:Date.now(),notified:false};db.results.push(r);writeDB(db);const notify=await sendWhatsAppIfConfigured(st,r);return json(res,201,{result:r,whatsapp:notify});
  }
  if(req.method==='POST' && pathname.startsWith('/api/results/') && pathname.endsWith('/notify')){
    if(!requireRole(req,res,['teacher','parent']))return;const id=pathname.split('/')[3];const r=db.results.find(x=>x.id===id);if(!r)return json(res,404,{error:'النتيجة غير موجودة'});const st=db.students.find(x=>x.id===r.studentId);const out=await sendWhatsAppIfConfigured(st,r);return json(res,200,{whatsapp:out});
  }
  if(req.method==='GET' && pathname==='/api/export'){
    if(!requireRole(req,res,['teacher']))return; return json(res,200,{version:1,exportedAt:new Date().toISOString(),db:{...db,admin:{username:db.admin.username}}});
  }
  if(req.method==='POST' && pathname==='/api/import'){
    if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.db||!Array.isArray(b.db.classes)||!Array.isArray(b.db.students))return json(res,400,{error:'ملف النسخة الاحتياطية غير صالح'});db={...db,...b.db,admin:db.admin,videos:Array.isArray(b.db.videos)?b.db.videos:(db.videos||[])};writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='PATCH' && pathname==='/api/settings'){
    if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');db.settings={...db.settings,...b};writeDB(db);return json(res,200,{settings:db.settings});
  }
  return json(res,404,{error:'المسار غير موجود'});
}
function safeParentName(st){return st.parentName||'ولي الأمر';}
async function sendWhatsAppIfConfigured(st,r){
  const msg=`السلام عليكم،\nتم الانتهاء من اللعبة التعليمية "${r.gameTitle}" للطالب ${r.studentName}.\nالدرجة: ${r.score} من ${r.total}\nالنسبة: ${r.percentage}%\nمع تمنياتنا بالتوفيق.`;
  const phone=cleanPhone(st?.parentPhone);
  const manual=`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  const token=process.env.WHATSAPP_TOKEN; const phoneNumberId=process.env.WHATSAPP_PHONE_NUMBER_ID; const apiVersion=process.env.WHATSAPP_API_VERSION||'v23.0';
  if(!token||!phoneNumberId||!phone){ return {mode:'manual',url:manual,message:'تم تجهيز رسالة واتساب. للإرسال الآلي ضع بيانات WhatsApp Cloud API في متغيرات البيئة.'}; }
  try{
    const url=`https://graph.facebook.com/${apiVersion}/${phoneNumberId}/messages`;
    const payload={messaging_product:'whatsapp',to:phone,type:'text',text:{body:msg}};
    const resp=await fetch(url,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await resp.json();
    if(!resp.ok) return {mode:'manual',url:manual,message:'تعذر الإرسال الآلي، استخدم الرابط الجاهز.',error:data};
    r.notified=true;r.notifiedAt=Date.now();writeDB(db);return {mode:'automatic',message:'تم إرسال إشعار واتساب تلقائياً.'};
  }catch(e){return {mode:'manual',url:manual,message:'تعذر الاتصال بخدمة واتساب، استخدم الرابط الجاهز.',error:e.message};}
}
function serveFile(file,res,type=null,cache=true){if(!fs.existsSync(file))return text(res,404,'Not found');const ext=path.extname(file).toLowerCase();const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8'};const data=fs.readFileSync(file);res.writeHead(200,{'Content-Type':type||types[ext]||'application/octet-stream','Cache-Control':cache?'public, max-age=300':'no-store','Content-Length':data.length});res.end(data)}

const server=http.createServer((req,res)=>handle(req,res).catch(e=>{console.error(e);json(res,500,{error:'حدث خطأ في الخادم'})}));
server.listen(PORT,()=>console.log(`Edu Platform running on http://localhost:${PORT}`));
