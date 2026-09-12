// أداة طوارئ لإعادة ضبط اسم مستخدم/كلمة مرور المعلم مباشرة، تُستخدم من جهاز الخادم فقط
// (عندما لا يكون إرسال واتساب مضبوطًا، أو عند فقدان الوصول لرقم الاستعادة).
//
// الاستخدام من داخل مجلد المشروع على الخادم:
//   node reset-admin.js <اسم_مستخدم_جديد> <كلمة_مرور_جديدة>
//
// إذا كان الخادم يستخدم متغير DATA_DIR (كما في render.yaml)، شغّل الأمر بنفس المتغير حتى يعدّل نفس الملف الذي يقرأه الخادم فعليًا، مثال:
//   DATA_DIR=/var/data node reset-admin.js redaawad كلمةسرجديدة
//
// يجب إيقاف الخادم أو إعادة تشغيله بعد التنفيذ حتى تُقرأ البيانات المحدثة.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const [, , newUsername, newPassword] = process.argv;

if (!newUsername || !newPassword) {
  console.error('الاستخدام: node reset-admin.js <اسم_مستخدم_جديد> <كلمة_مرور_جديدة>');
  process.exit(1);
}
if (newUsername.length < 3 || /\s/.test(newUsername)) {
  console.error('اسم المستخدم يجب أن يكون 3 أحرف على الأقل وبدون مسافات.');
  process.exit(1);
}
if (newPassword.length < 6) {
  console.error('كلمة المرور يجب أن تكون 6 أحرف على الأقل.');
  process.exit(1);
}

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DB_FILE)) {
  console.error('لم يتم العثور على ملف قاعدة البيانات في: ' + DB_FILE);
  console.error('تأكد من ضبط نفس متغير DATA_DIR المستخدم عند تشغيل الخادم.');
  process.exit(1);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
if (!db.admin) {
  console.error('لا يوجد حساب معلم في قاعدة البيانات.');
  process.exit(1);
}

db.admin.username = newUsername;
db.admin.passwordHash = hashPassword(newPassword);
db.admin.passwordChangedAt = Date.now();
db.admin.usernameChangedAt = Date.now();
db.admin.resetCode = null;

fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');

console.log('تم تحديث بيانات دخول المعلم بنجاح.');
console.log('اسم المستخدم الجديد: ' + newUsername);
console.log('أعد تشغيل الخادم إن كان يعمل حاليًا حتى تُطبَّق البيانات الجديدة.');
