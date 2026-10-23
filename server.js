// API de ativação de demonstração: persiste dados em disco, exige HTTPS na hospedagem.
const http=require('http'),fs=require('fs'),crypto=require('crypto');
const PORT=Number(process.env.PORT||3000),SECRET=process.env.JWT_SECRET;
if(!SECRET||SECRET.length<32)throw Error('Configure JWT_SECRET com pelo menos 32 caracteres');
const DB=process.env.DB_PATH||'users.json';let users={};try{users=JSON.parse(fs.readFileSync(DB,'utf8'))}catch{}
function save(){fs.writeFileSync(DB,JSON.stringify(users,null,2),{mode:0o600})}
function b64(o){return Buffer.from(JSON.stringify(o)).toString('base64url')}
function sign(payload){let a=b64({alg:'HS256',typ:'JWT'}),b=b64(payload);return a+'.'+b+'.'+crypto.createHmac('sha256',SECRET).update(a+'.'+b).digest('base64url')}
function verify(token){try{let [a,b,c]=token.split('.');let expected=crypto.createHmac('sha256',SECRET).update(a+'.'+b).digest();let received=Buffer.from(c,'base64url');if(received.length!==expected.length||!crypto.timingSafeEqual(received,expected))return null;let p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch{return null}}
function hash(pass,salt){return crypto.scryptSync(pass,salt,64).toString('hex')}
function send(res,code,obj){res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(obj))}
const maintenance=process.env.MAINTENANCE==='true';
http.createServer((req,res)=>{if(req.method==='OPTIONS'){res.writeHead(204,{'Allow':'GET,POST,OPTIONS'});return res.end()}
 const path=new URL(req.url,'http://localhost').pathname;
 if(req.method==='GET'&&path==='/api/status')return send(res,200,{online:true,maintenance,service:'Vitorioso Auxílios',gameIntegration:false});
 let data='';req.on('data',x=>{data+=x;if(data.length>8192)req.destroy()});req.on('end',()=>{let body={};try{body=JSON.parse(data||'{}')}catch{return send(res,400,{error:'JSON inválido'})}
 if(req.method==='POST'&&path==='/api/register'){
 let email=String(body.email||'').trim().toLowerCase(),password=String(body.password||'');if(!/^\S+@\S+\.\S+$/.test(email)||password.length<12)return send(res,400,{error:'Email válido e senha com 12+ caracteres'});
 if(users[email])return send(res,409,{error:'Conta existente'});let salt=crypto.randomBytes(16).toString('hex');users[email]={salt,hash:hash(password,salt),active:true,createdAt:new Date().toISOString()};save();return send(res,201,{ok:true});}
 if(req.method==='POST'&&path==='/api/login'){
 let email=String(body.email||'').trim().toLowerCase(),password=String(body.password||''),u=users[email];if(!u||!u.active||hash(password,u.salt)!==u.hash)return send(res,401,{error:'Credenciais inválidas'});
 return send(res,200,{token:sign({sub:email,exp:Date.now()+3600000}),expiresIn:3600});}
 if(req.method==='GET'&&path==='/api/me'){let token=(req.headers.authorization||'').replace(/^Bearer /,'');let p=verify(token);if(!p||!users[p.sub]||!users[p.sub].active)return send(res,401,{error:'Não autorizado'});return send(res,200,{active:true,maintenance});}
 return send(res,404,{error:'Rota não encontrada'});
 });}).listen(PORT,()=>console.log('API na porta',PORT));
