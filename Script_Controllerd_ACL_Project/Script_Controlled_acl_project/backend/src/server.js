import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'naan-mudhalvan-demo-secret-change-me';
const db = new Database('acl.db');

db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT UNIQUE NOT NULL, first_name TEXT, last_name TEXT, email TEXT, password_hash TEXT NOT NULL, branch TEXT DEFAULT 'EEE');
CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT);
CREATE TABLE IF NOT EXISTS user_roles(user_id INTEGER, role_id INTEGER, PRIMARY KEY(user_id,role_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS institution_details(id INTEGER PRIMARY KEY AUTOINCREMENT, roll_number TEXT UNIQUE NOT NULL, student_name TEXT, faculty_name TEXT, branch TEXT CHECK(branch IN ('ECE','EEE','CSE')), email TEXT, phone TEXT, description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const roleDefs=[['bb1','Read EEE records'],['bb2','Create institution records'],['bb3','Write institution records'],['bb4','Delete institution records']];
for(const [name,description] of roleDefs) db.prepare('INSERT OR IGNORE INTO roles(name,description) VALUES(?,?)').run(name,description);
const adminPass=bcrypt.hashSync('admin123',10), eeePass=bcrypt.hashSync('eee123',10), viewerPass=bcrypt.hashSync('viewer123',10);
db.prepare(`INSERT OR IGNORE INTO users(user_id,first_name,last_name,email,password_hash,branch) VALUES('admin','System','Administrator','admin@demo.local',?,'EEE')`).run(adminPass);
db.prepare(`INSERT OR IGNORE INTO users(user_id,first_name,last_name,email,password_hash,branch) VALUES('eeeuser','EEE','User','eeeuser@gmail.com',?,'EEE')`).run(eeePass);
db.prepare(`INSERT OR IGNORE INTO users(user_id,first_name,last_name,email,password_hash,branch) VALUES('viewer','Basic','Viewer','viewer@demo.local',?,'CSE')`).run(viewerPass);
const eee=db.prepare("SELECT id FROM users WHERE user_id='eeeuser'").get();
const admin=db.prepare("SELECT id FROM users WHERE user_id='admin'").get();
const viewer=db.prepare("SELECT id FROM users WHERE user_id='viewer'").get();
for(const r of ['bb1','bb2','bb3','bb4']) db.prepare('INSERT OR IGNORE INTO user_roles(user_id,role_id) SELECT ?,id FROM roles WHERE name=?').run(eee.id,r);
for(const r of ['bb1','bb2','bb3','bb4']) db.prepare('INSERT OR IGNORE INTO user_roles(user_id,role_id) SELECT ?,id FROM roles WHERE name=?').run(admin.id,r);
const count=db.prepare('SELECT COUNT(*) c FROM institution_details').get().c;
if(!count){const ins=db.prepare('INSERT INTO institution_details(roll_number,student_name,faculty_name,branch,email,phone,description) VALUES(?,?,?,?,?,?,?)');
[['STU-1001','Arun Kumar','Dr. Meena','EEE','arun@example.com','9876543210','Power systems student'],['STU-1002','Priya S','Dr. Kumar','EEE','priya@example.com','9876543211','Embedded systems interest'],['STU-1003','Rahul V','Dr. Devi','ECE','rahul@example.com','9876543212','Communication systems student'],['STU-1004','Nisha R','Dr. Balan','CSE','nisha@example.com','9876543213','Data engineering student'],['STU-1005','Karthik M','Dr. Meena','EEE','karthik@example.com','9876543214','Industrial automation student']].forEach(x=>ins.run(...x));}

app.use(cors()); app.use(express.json()); app.use(morgan('dev'));
function getUser(req,res,next){const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({message:'Authentication required'}); try{const p=jwt.verify(h.slice(7),JWT_SECRET); const u=db.prepare('SELECT id,user_id,first_name,last_name,email,branch FROM users WHERE id=?').get(p.id); if(!u) throw new Error(); u.roles=db.prepare('SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?').all(u.id).map(x=>x.name); u.isAdmin=u.user_id==='admin'; req.user=u; next();}catch(e){res.status(401).json({message:'Invalid or expired token'});}}
function can(req,operation){if(req.user.isAdmin) return true; const roles=req.user.roles; if(operation==='read') return roles.includes('bb1'); if(operation==='create') return roles.includes('bb2'); if(operation==='write') return roles.includes('bb3'); if(operation==='delete') return roles.includes('bb4'); return false;}
function aclMessage(op){return `ACL denied: your account does not have permission to ${op} institution records.`;}

app.get('/', (req, res) => res.redirect('http://localhost:5173'));
app.post('/api/auth/login',(req,res)=>{const {user_id,password}=req.body||{}; const u=db.prepare('SELECT * FROM users WHERE user_id=?').get(user_id); if(!u||!bcrypt.compareSync(password||'',u.password_hash)) return res.status(401).json({message:'Invalid user ID or password'}); const token=jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'8h'}); res.json({token,user:{id:u.id,user_id:u.user_id,first_name:u.first_name,last_name:u.last_name,email:u.email,branch:u.branch}});});
app.get('/api/auth/me',getUser,(req,res)=>res.json({user:req.user}));
app.get('/api/roles',getUser,(req,res)=>res.json(db.prepare('SELECT name,description FROM roles ORDER BY name').all()));
app.get('/api/records',getUser,(req,res)=>{if(!can(req,'read')) return res.status(403).json({message:aclMessage('read')}); const rows=req.user.isAdmin?db.prepare('SELECT * FROM institution_details ORDER BY id DESC').all():db.prepare("SELECT * FROM institution_details WHERE branch='EEE' ORDER BY id DESC").all(); res.json({records:rows,scope:req.user.isAdmin?'ALL BRANCHES':'EEE ONLY'});});
app.post('/api/records',getUser,(req,res)=>{if(!can(req,'create')) return res.status(403).json({message:aclMessage('create')}); const x=req.body||{}; if(!x.student_name||!x.faculty_name||!x.branch||!x.email) return res.status(400).json({message:'Student name, faculty name, branch and email are required'}); const roll=x.roll_number||`STU-${Date.now().toString().slice(-6)}`; try{const info=db.prepare('INSERT INTO institution_details(roll_number,student_name,faculty_name,branch,email,phone,description) VALUES(?,?,?,?,?,?,?)').run(roll,x.student_name,x.faculty_name,x.branch,x.email,x.phone||'',x.description||''); res.status(201).json({record:db.prepare('SELECT * FROM institution_details WHERE id=?').get(info.lastInsertRowid)});}catch(e){res.status(400).json({message:'Could not create record. Roll number may already exist.'});}});
app.put('/api/records/:id',getUser,(req,res)=>{if(!can(req,'write')) return res.status(403).json({message:aclMessage('write')}); const old=db.prepare('SELECT * FROM institution_details WHERE id=?').get(req.params.id); if(!old) return res.status(404).json({message:'Record not found'}); if(!req.user.isAdmin && old.branch!=='EEE') return res.status(403).json({message:'Field-level ACL: only EEE records can be modified by bb3 users'}); const x=req.body||{}; db.prepare('UPDATE institution_details SET student_name=?,faculty_name=?,branch=?,email=?,phone=?,description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(x.student_name, x.faculty_name, x.branch, x.email, x.phone||'', x.description||'', req.params.id); res.json({record:db.prepare('SELECT * FROM institution_details WHERE id=?').get(req.params.id)});});
app.delete('/api/records/:id',getUser,(req,res)=>{if(!can(req,'delete')) return res.status(403).json({message:aclMessage('delete')}); const old=db.prepare('SELECT * FROM institution_details WHERE id=?').get(req.params.id); if(!old) return res.status(404).json({message:'Record not found'}); if(!req.user.isAdmin && old.branch!=='EEE') return res.status(403).json({message:'Field-level ACL: only EEE records can be deleted by bb4 users'}); db.prepare('DELETE FROM institution_details WHERE id=?').run(req.params.id); res.json({message:'Record deleted'});});
app.get('/api/dashboard',getUser,(req,res)=>{const total=db.prepare('SELECT COUNT(*) c FROM institution_details').get().c; const branches=db.prepare('SELECT branch,COUNT(*) count FROM institution_details GROUP BY branch').all(); res.json({total,branches,permissions:{read:can(req,'read'),create:can(req,'create'),write:can(req,'write'),delete:can(req,'delete')}})});
app.listen(PORT,()=>console.log(`ACL backend running on http://localhost:${PORT}`));
