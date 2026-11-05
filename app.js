const K='wms.v1';
let S={p:[],w:[{id:'w1',kode:'GD-UTAMA',nama:'Gudang Utama'}],s:{},m:[]};
try{const r=localStorage.getItem(K);if(r)S=JSON.parse(r)}catch(e){}
const $=q=>document.querySelector(q);
const RL={admin:'Kepala Gudang',staf:'Staf Gudang',lihat:'Hanya Lihat'};
const TABS={admin:['ring','trx','exp','opn','krt','rst','lap','prd','gdg','usr','akn'],staf:['ring','trx','exp','opn','krt','rst','lap','akn'],lihat:['ring','krt','rst','lap','akn']};
let ME=null,AE='',UM=null,UE={},fails=0,lockUntil=0,lastAct=Date.now();const SK='wms.sess';
const isA=()=>!!ME&&ME.role=='admin',canW=()=>!!ME&&ME.role!='lihat';
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
async function hsh(pw,salt){
 try{const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
  const b=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:120000,hash:'SHA-256'},k,256);return'p:'+hex(b)}catch(e){}
 let h1=0xdeadbeef,h2=0x41c6ce57;const t=salt+pw;for(let i=0;i<t.length;i++){const c=t.charCodeAt(i);h1=Math.imul(h1^c,2654435761);h2=Math.imul(h2^c,1597334677)}
 h1=Math.imul(h1^(h1>>>16),2246822507)^Math.imul(h2^(h2>>>13),3266489909);h2=Math.imul(h2^(h2>>>16),2246822507)^Math.imul(h1^(h1>>>13),3266489909);
 return'f:'+(4294967296*(2097151&h2)+(h1>>>0)).toString(16)}
async function chk(u,pw){const h=await hsh(pw,u.salt);return h==u.hash||(!!u.hf&&h==u.hf)}
const UREG=/^[a-z0-9._-]{3,30}$/,UERR='Username 3-30 karakter: huruf kecil, angka, titik, minus, atau garis bawah';
function login(u){ME=u;try{sessionStorage.setItem(SK,u.id)}catch(e){}tab='ring';msg=null;UM=null;UE={};AE='';fails=0;lastAct=Date.now();toast('Selamat datang, '+u.nama)}
function logout(note){ME=null;AS=null;UM=null;UE={};try{sessionStorage.removeItem(SK)}catch(e){}AE=note||''}
async function authForm(f,d){
 if(f=='setup'){
  if(S.u.length)return;
  const user=d.user.trim().toLowerCase(),nama=d.nama.trim();
  if(!nama){AE='Nama lengkap wajib diisi';return}
  if(!UREG.test(user)){AE=UERR;return}
  if(d.pw.length<6){AE='Kata sandi minimal 6 karakter';return}
  if(d.pw!==d.pw2){AE='Ulangi kata sandi tidak sama';return}
  const salt=uid()+uid(),u={id:uid(),user,nama,role:'admin',salt,hash:await hsh(d.pw,salt)};
  S.u.push(u);if(!save()){S.u.pop();AE='Gagal menyimpan akun';return}
  login(u);
 }else if(f=='login'){
  const now=Date.now();if(now<lockUntil){AE=`Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((lockUntil-now)/1000)} detik`;return}
  const u=S.u.find(x=>x.user==d.user.trim().toLowerCase());
  const ok=u&&(await chk(u,d.pw));
  if(!ok){fails++;if(fails>=5){lockUntil=Date.now()+30000;fails=0}AE='Username atau kata sandi salah';return}
  login(u);
 }else if(f=='user'){
  const nama=d.nama.trim(),user=d.user.trim().toLowerCase(),role=d.role,bad=x=>{UM={t:'bad',x}};
  if(!nama)return bad('Nama lengkap wajib diisi');
  if(!RL[role])return bad('Peran tidak valid');
  if(!UREG.test(user))return bad(UERR);
  if(S.u.some(x=>x.user==user&&x.id!=d.id))return bad('Username sudah dipakai');
  const ex=d.id?S.u.find(x=>x.id==d.id):null;
  if(d.id&&!ex)return bad('Pengguna tidak ditemukan');
  if(!ex&&d.pw.length<6)return bad('Kata sandi minimal 6 karakter');
  if(ex&&d.pw&&d.pw.length<6)return bad('Kata sandi minimal 6 karakter');
  if(ex&&ex.role=='admin'&&role!='admin'&&S.u.filter(x=>x.role=='admin').length<2)return bad('Harus ada minimal satu Kepala Gudang');
  const prev=JSON.stringify(S.u);
  if(ex){ex.nama=nama;ex.user=user;ex.role=role;if(d.pw){ex.salt=uid()+uid();ex.hash=await hsh(d.pw,ex.salt);delete ex.hf;if(ex.id!=ME.id)ex.must=true}}
  else{const salt=uid()+uid();S.u.push({id:uid(),user,nama,role,salt,hash:await hsh(d.pw,salt),must:true})}
  if(!save()){const id=ME.id;S.u=JSON.parse(prev);ME=S.u.find(x=>x.id==id);return bad('Gagal menyimpan pengguna')}
  UE={};UM={t:'ok',x:'Pengguna tersimpan'};toast('Pengguna tersimpan');
 }else if(f=='pw'){
  const bad=x=>{UM={t:'bad',x}};
  if(!(await chk(ME,d.old)))return bad('Kata sandi lama salah');
  if(d.pw.length<6)return bad('Kata sandi baru minimal 6 karakter');
  if(d.pw!==d.pw2)return bad('Ulangi kata sandi tidak sama');
  const old={salt:ME.salt,hash:ME.hash,hf:ME.hf,must:ME.must};ME.salt=uid()+uid();ME.hash=await hsh(d.pw,ME.salt);delete ME.hf;delete ME.must;
  if(!save()){Object.assign(ME,old);return bad('Gagal menyimpan')}
  UM={t:'ok',x:'Kata sandi berhasil diganti'};toast('Kata sandi diganti');
 }
}
['click','keydown','input'].forEach(t=>document.addEventListener(t,()=>{lastAct=Date.now()},true));
setInterval(()=>{if(ME&&Date.now()-lastAct>30*60000){logout('Sesi berakhir karena tidak aktif. Silakan masuk lagi.');view()}},30000);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const n=v=>Number(v||0).toLocaleString('id-ID',{maximumFractionDigits:2});
const uid=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,6);
const r2=x=>Math.round(x*100)/100;
let AS=null;
let tab='ring',q='',msg=null,T={t:'IN',p:'',a:'',b:'',q:'',r:'',c:''},E={};
const TP={IN:'Barang masuk',OUT:'Barang keluar',TRANSFER:'Pindah gudang'};
function loc(p){return[p.rak&&'Rak '+p.rak,p.line&&'Line '+p.line].filter(Boolean).join(', ')}
const stok=(p,w)=>S.s[p+'|'+w]||0;
const total=p=>S.w.reduce((a,w)=>a+stok(p.id,w.id),0);
const wn=id=>(S.w.find(w=>w.id==id)||{}).nama||'-';
const pn=id=>(S.p.find(p=>p.id==id)||{}).nama||'(dihapus)';
let tt;function toast(x,bad){const e=$('#toast');e.textContent=x;e.className=bad?'bad':'';e.style.display='block';clearTimeout(tt);tt=setTimeout(()=>e.style.display='none',2600)}
function save(){try{localStorage.setItem(K,JSON.stringify(S));return true}catch(e){toast('Gagal menyimpan ke browser',1);return false}}

function move(f){
 const p=S.p.find(x=>x.id==f.p),a=f.a,b=f.b,qty=+f.q;
 if(!p)return'Pilih produk';if(!a)return'Pilih gudang';if(!(qty>0))return'Jumlah harus lebih dari 0';
 const ns={...S.s},k=w=>p.id+'|'+w;
 if(f.t=='IN')ns[k(a)]=r2((ns[k(a)]||0)+qty);
 else{
  if((ns[k(a)]||0)<qty)return`Stok ${p.nama} di ${wn(a)} tidak cukup (tersedia ${n(ns[k(a)])})`;
  ns[k(a)]=r2(ns[k(a)]-qty);
  if(f.t=='TRANSFER'){if(!b||b==a)return'Gudang tujuan harus berbeda dari gudang asal';ns[k(b)]=r2((ns[k(b)]||0)+qty)}
 }
 const prev=[S.s,S.m];
 S.s=ns;S.m=[{id:uid(),t:f.t,p:p.id,a,b:f.t=='TRANSFER'?b:'',q:qty,r:f.r,c:f.c,u:ME?ME.nama:'',at:Date.now()},...S.m].slice(0,2000);
 if(!save()){[S.s,S.m]=prev;return'Penyimpanan gagal, transaksi dibatalkan'}
 return'';
}

function vLogin(){
 if(!S.u.length)return`<section class="card lg"><h2>Buat akun Kepala Gudang</h2><p class="st">Belum ada akun. Akun pertama ini menjadi Kepala Gudang (akses penuh) dan bisa menambah akun untuk staf lain.</p>
 <form data-form="setup" autocomplete="off"><div class="grid">
 <div><label>Nama lengkap</label><input name="nama" id="su" required maxlength="80"></div>
 <div><label>Username</label><input name="user" required maxlength="30" autocapitalize="none" autocomplete="off"></div>
 <div><label>Kata sandi (min. 6 karakter)</label><input name="pw" type="password" required minlength="6" autocomplete="new-password"></div>
 <div><label>Ulangi kata sandi</label><input name="pw2" type="password" required autocomplete="new-password"></div></div>
 <p class="st bad">${esc(AE)}</p><div class="row"><button>Buat akun &amp; masuk</button></div></form></section>`;
 return`<section class="card lg"><h2>Masuk ke Sistem Gudang</h2>
 <form data-form="login"><div class="grid">
 <div><label>Username</label><input name="user" id="lu" required autocapitalize="none" autocomplete="username"></div>
 <div><label>Kata sandi</label><input name="pw" type="password" required autocomplete="current-password"></div></div>
 <p class="st bad">${esc(AE)}</p><div class="row"><button>Masuk</button></div>
 <p class="st">Lupa kata sandi? Minta Kepala Gudang mengganti lewat menu Pengguna.</p></form></section>`;
}
function vUsr(){
 const e=UE,ed=!!e.id;
 return`<section class="card"><h2>${ed?'Ubah Pengguna':'Tambah Pengguna'}</h2><form data-form="user" autocomplete="off"><input type="hidden" name="id" value="${esc(e.id)}"><div class="grid">
 <div><label>Nama lengkap</label><input name="nama" required maxlength="80" value="${esc(e.nama)}"></div>
 <div><label>Username</label><input name="user" required maxlength="30" autocapitalize="none" value="${esc(e.user)}"></div>
 <div><label>${ed?'Kata sandi baru (kosongkan jika tidak diganti)':'Kata sandi (min. 6 karakter)'}</label><input name="pw" type="password" autocomplete="new-password" ${ed?'':'required minlength="6"'}></div>
 <div><label>Peran</label><select name="role">${Object.entries(RL).map(([k,l])=>`<option value="${k}" ${(e.role||'staf')==k?'selected':''}>${l}</option>`).join('')}</select></div></div>
 <p class="st"><b>Kepala Gudang</b>: akses penuh. <b>Staf Gudang</b>: catat transaksi, tambah stok, pengiriman, opname. <b>Hanya Lihat</b>: melihat stok dan laporan saja.</p>
 <div class="row"><button>${ed?'Simpan perubahan':'Tambah pengguna'}</button>${ed?'<button type="button" class="g" data-act="cancelu">Batal</button>':''}<span class="st ${UM?UM.t:''}">${esc(UM?UM.x:'')}</span></div></form></section>
 <section class="card"><h2>Daftar Pengguna</h2><div class="tw"><table><thead><tr><th>Nama</th><th>Username</th><th>Peran</th><th></th></tr></thead><tbody>${
 S.u.map(u=>`<tr><td>${esc(u.nama)}${u.id==ME.id?' <span class="st">(Anda)</span>':''}</td><td>${esc(u.user)}</td><td>${RL[u.role]||'-'}</td><td><button class="g s" data-act="editu" data-v="${u.id}">Ubah</button> ${u.id==ME.id?'':`<button class="g s" data-act="delu" data-v="${u.id}">Hapus</button>`}</td></tr>`).join('')}</tbody></table></div></section>`;
}
function vForce(){
 return`<section class="card lg"><h2>Ganti kata sandi sementara</h2><p class="st">Halo, <b>${esc(ME.nama)}</b>. Demi keamanan, ganti kata sandi sementara Anda dengan yang baru sebelum memakai sistem.</p>
 <form data-form="pw" autocomplete="off"><div class="grid">
 <div><label>Kata sandi sementara</label><input name="old" type="password" required autocomplete="current-password"></div>
 <div><label>Kata sandi baru (min. 6)</label><input name="pw" type="password" required minlength="6" autocomplete="new-password"></div>
 <div><label>Ulangi kata sandi baru</label><input name="pw2" type="password" required autocomplete="new-password"></div></div>
 <p class="st bad">${esc(UM?UM.x:'')}</p><div class="row"><button>Simpan &amp; lanjut</button></div></form></section>`;
}
function vAkn(){
 return`<section class="card"><h2>Akun Saya</h2><p style="margin:0 0 12px"><b>${esc(ME.nama)}</b> <span class="rl">${RL[ME.role]}</span><br><span class="st">Username: ${esc(ME.user)}</span></p>
 <form data-form="pw" autocomplete="off"><div class="grid">
 <div><label>Kata sandi lama</label><input name="old" type="password" required autocomplete="current-password"></div>
 <div><label>Kata sandi baru (min. 6)</label><input name="pw" type="password" required minlength="6" autocomplete="new-password"></div>
 <div><label>Ulangi kata sandi baru</label><input name="pw2" type="password" required autocomplete="new-password"></div></div>
 <div class="row"><button>Ganti kata sandi</button><span class="st ${UM?UM.t:''}">${esc(UM?UM.x:'')}</span></div></form></section>`;
}
function vAdd(){
 if(!AS)return'';const p=S.p.find(x=>x.id==AS.p);if(!p)return'';
 return`<div class="ov"><div class="md" role="dialog" aria-modal="true"><h2>Tambah Stok</h2>
 <p style="margin:0 0 12px"><b>${esc(p.nama)}</b><br><span class="st">${esc(p.sku)}${loc(p)?' &middot; <b>'+esc(loc(p))+'</b>':''} &middot; Total stok: ${n(total(p))} ${esc(p.sat)}</span></p>
 <form data-form="addstok"><div class="grid">
 <div><label>Gudang</label><select name="a" id="asa" required>${S.w.map(w=>`<option value="${w.id}" ${w.id==AS.a?'selected':''}>${esc(w.nama)} (stok ${n(stok(p.id,w.id))})</option>`).join('')}</select></div>
 <div><label>Jumlah yang ditambahkan (${esc(p.sat)})</label><input name="q" id="asq" type="number" min="0.01" step="any" required value="${esc(AS.q)}"></div>
 <div><label>Catatan</label><input name="c" maxlength="255" value="${esc(AS.c)}" placeholder="Contoh: pembelian dari supplier"></div></div>
 <p class="st" id="asp"></p>
 <p class="st bad">${esc(AS.err||'')}</p>
 <div class="row"><button>Tambah stok</button><button type="button" class="g" data-act="closeadd">Batal</button></div></form></div></div>`;
}
function asPrev(){const e=$('#asp');if(!e||!AS)return;const p=S.p.find(x=>x.id==AS.p),a=$('#asa'),q=+($('#asq')||{}).value;if(!p||!a)return;const cur=stok(p.id,a.value);e.textContent=q>0?`Stok di gudang ini: ${n(cur)} → ${n(r2(cur+q))} ${p.sat}`:''}
document.addEventListener('input',e=>{if(e.target.closest('form[data-form=addstok]'))asPrev()});
document.addEventListener('change',e=>{if(e.target.closest('form[data-form=addstok]'))asPrev()});
document.addEventListener('click',e=>{if(e.target.classList&&e.target.classList.contains('ov')){AS=null;view()}});
document.addEventListener('keydown',e=>{if(e.key=='Escape'&&AS){AS=null;view()}});
function view(){
 if(ME&&!S.u.some(x=>x.id==ME.id))ME=null;
 if(!ME){$('#nav').innerHTML='';$('#who').innerHTML='';$('#app').innerHTML=vLogin();setTimeout(()=>{const i=$('#lu')||$('#su');if(i)i.focus()},0);return}
 if(ME.must){$('#nav').innerHTML='';$('#who').innerHTML=`<span>${esc(ME.nama)}</span><button data-act="logout">Keluar</button>`;$('#app').innerHTML=vForce();return}
 const tabs=[['ring','Ringkasan'],['trx','Transaksi'],['exp','Ekspedisi'],['opn','Opname'],['krt','Kartu stok'],['rst','Restok'],['lap','Laporan'],['prd','Produk'],['gdg','Gudang'],['usr','Pengguna'],['akn','Akun saya']].filter(([k])=>TABS[ME.role].includes(k));
 if(!tabs.some(([k])=>k==tab))tab='ring';
 $('#who').innerHTML=`<span>${esc(ME.nama)} <span class="rl">${RL[ME.role]}</span></span><button data-act="logout">Keluar</button>`;
 $('#nav').innerHTML=tabs.map(([k,l])=>`<button class="tb ${tab==k?'on':''}" data-act="tab" data-v="${k}">${l}</button>`).join('');
 $('#app').innerHTML=({ring:vRing,trx:vTrx,exp:vExp,opn:vOpn,krt:vKartu,rst:vRestok,lap:vLap,prd:vPrd,gdg:vGdg,usr:vUsr,akn:vAkn})[tab]()+vAdd();
 if(tab=='ring')tbl();
 if(AS&&!AS.q)setTimeout(()=>{const i=$('#asq');if(i)i.focus()},0);
}

function vRing(){
 const low=S.p.filter(p=>total(p)<=p.min).length,units=S.p.reduce((a,p)=>a+total(p),0),nilai=S.p.reduce((a,p)=>a+total(p)*(p.hrg||0),0);
 const today=new Date().toDateString(),mt=S.m.filter(m=>new Date(m.at).toDateString()==today).length;
 return`<section class="stats">
 <div class="stat"><span>Produk</span><b>${S.p.length}</b></div>
 <div class="stat"><span>Nilai persediaan</span><b>${rp(nilai)}</b></div>
 <div class="stat"><span>Total unit di gudang</span><b>${n(units)}</b></div>
 <div class="stat"><span>Perlu restok</span><b class="${low?'bad':''}">${low}</b></div>
 <div class="stat"><span>Transaksi hari ini</span><b>${mt}</b></div></section>
 ${low?`<section class="card" style="border-color:var(--bad)"><b class="bad">${low} produk perlu restok.</b> <button class="s" data-act="tab" data-v="rst">Lihat daftar restok</button></section>`:''}
 <section class="card"><h2>Stok per Gudang</h2><input id="q" placeholder="Cari SKU atau nama produk" value="${esc(q)}"><div class="tw" id="tbl" style="margin-top:12px"></div></section>
 ${isA()?`<section class="card"><h2>Cadangan Data</h2>
 <p class="st">Data tersimpan di browser ini. Salin cadangan secara berkala, dan pulihkan di perangkat lain bila perlu.</p>
 <textarea id="bk" rows="3" placeholder="Hasil cadangan muncul di sini, atau tempel cadangan untuk dipulihkan"></textarea>
 <div class="row"><button data-act="bkup">Salin cadangan</button><button class="g" data-act="rest">Pulihkan dari cadangan</button></div></section>`:''}`;
}
function tbl(){
 const ql=q.toLowerCase(),rows=S.p.filter(p=>(p.sku+' '+p.nama+' '+(p.kat||'')+' '+(p.rak||'')+' '+(p.line||'')).toLowerCase().includes(ql));
 $('#tbl').innerHTML=`<table><thead><tr><th>SKU</th><th>Produk</th>${S.w.map(w=>`<th>${esc(w.nama)}</th>`).join('')}<th>Total</th><th>Status</th>${canW()?'<th></th>':''}</tr></thead><tbody>${
 rows.map(p=>{const t=total(p),l=t<=p.min;return`<tr><td>${esc(p.sku)}</td><td>${esc(p.nama)}<div class="st">${esc([p.kat,loc(p)].filter(Boolean).join(', '))}</div></td>${S.w.map(w=>`<td>${n(stok(p.id,w.id))}</td>`).join('')}<td><b>${n(t)} ${esc(p.sat)}</b></td><td class="${l?'bad':'ok'}">${l?'Perlu restok':'Aman'}</td>${canW()?`<td><button class="s" data-act="addstok" data-v="${p.id}">+ Stok</button></td>`:''}</tr>`}).join('')
 ||`<tr><td colspan="${S.w.length+(canW()?5:4)}" class="st">Belum ada produk. Tambahkan di tab Produk, lalu catat barang masuk di tab Transaksi.</td></tr>`}</tbody></table>`;
}

function vTrx(){
 const o=(arr,v,f)=>arr.map(x=>`<option value="${x.id}" ${x.id==v?'selected':''}>${esc(f(x))}</option>`).join('');
 const tr=T.t=='TRANSFER';
 return`<section class="card"><h2>Catat Transaksi Stok</h2>
 <div class="row" style="margin:0 0 12px">${Object.entries(TP).map(([k,l])=>`<button class="${T.t==k?'':'g'}" data-act="type" data-v="${k}">${l}</button>`).join('')}</div>
 <form data-form="trx"><div class="grid">
 <div><label>Produk</label><select name="p" required><option value="">Pilih produk</option>${o(S.p,T.p,x=>x.sku+' - '+x.nama+(loc(x)?' ['+loc(x)+']':''))}</select></div>
 <div><label>${tr?'Gudang asal':'Gudang'}</label><select name="a" required><option value="">Pilih gudang</option>${o(S.w,T.a,x=>x.nama)}</select></div>
 ${tr?`<div><label>Gudang tujuan</label><select name="b" required><option value="">Pilih gudang</option>${o(S.w,T.b,x=>x.nama)}</select></div>`:''}
 <div><label>Jumlah</label><input name="q" type="number" min="0.01" step="any" required value="${esc(T.q)}"></div>
 <div><label>No. referensi</label><input name="r" value="${esc(T.r)}" maxlength="60"></div>
 <div><label>Catatan</label><input name="c" value="${esc(T.c)}" maxlength="255"></div></div>
 <div class="row"><button>Simpan transaksi</button><span class="st ${msg?msg.t:''}">${esc(msg?msg.x:'')}</span></div></form></section>
 <section class="card"><h2>Riwayat Transaksi</h2><div class="tw"><table><thead><tr><th>Waktu</th><th>Jenis</th><th>Produk</th><th>Gudang</th><th>Jumlah</th><th>Referensi</th><th>Oleh</th></tr></thead><tbody>${
 S.m.slice(0,100).map(m=>`<tr><td>${new Date(m.at).toLocaleString('id-ID',{dateStyle:'medium',timeStyle:'short'})}</td><td>${TP[m.t]||'Opname'}</td><td>${esc(pn(m.p))}</td><td>${esc(wn(m.a))}${m.b?' ke '+esc(wn(m.b)):''}</td><td>${m.t=='ADJ'?(m.d>0?'+':'-'):''}${n(m.q)}</td><td>${esc(m.r)}</td><td>${esc(m.u||'-')}</td></tr>`).join('')
 ||'<tr><td colspan="7" class="st">Belum ada transaksi.</td></tr>'}</tbody></table></div></section>`;
}

function vPrd(){
 return`<section class="card"><h2>${E.id?'Ubah Produk':'Tambah Produk'}</h2><form data-form="prd"><input type="hidden" name="id" value="${esc(E.id)}"><div class="grid">
 <div><label>SKU</label><input name="sku" required maxlength="40" value="${esc(E.sku)}"></div>
 <div><label>Nama produk</label><input name="nama" required maxlength="160" value="${esc(E.nama)}"></div>
 <div><label>Satuan</label><input name="sat" required maxlength="20" value="${esc(E.sat||'pcs')}"></div>
 <div><label>Batas minimum</label><input name="min" type="number" min="0" step="any" required value="${esc(E.min??0)}"></div>
 <div><label>Kategori</label><input name="kat" maxlength="60" list="kl" value="${esc(E.kat)}"><datalist id="kl">${[...new Set(S.p.map(p=>p.kat).filter(Boolean))].map(k=>`<option value="${esc(k)}">`).join('')}</datalist></div>
 <div><label>Lokasi rak</label><input name="rak" maxlength="30" value="${esc(E.rak)}"></div>
 <div><label>Line rak (nomor baris/lajur)</label><input name="line" maxlength="30" value="${esc(E.line)}" placeholder="Contoh: 3"></div>
 <div><label>Harga beli (Rp)</label><input name="hrg" type="number" min="0" step="any" value="${esc(E.hrg??0)}"></div></div>
 <div class="row"><button>${E.id?'Simpan perubahan':'Tambah produk'}</button>${E.id?'<button type="button" class="g" data-act="cancel">Batal</button>':''}</div></form></section>
 <section class="card"><div class="tw"><table><thead><tr><th>SKU</th><th>Nama</th><th>Kategori</th><th>Rak</th><th>Line</th><th>Satuan</th><th>Batas minimum</th><th>Harga beli</th><th></th></tr></thead><tbody>${
 S.p.map(p=>`<tr><td>${esc(p.sku)}</td><td>${esc(p.nama)}</td><td>${esc(p.kat)}</td><td>${esc(p.rak)}</td><td>${esc(p.line)}</td><td>${esc(p.sat)}</td><td>${n(p.min)}</td><td>${rp(p.hrg||0)}</td><td><button class="s" data-act="addstok" data-v="${p.id}">+ Stok</button> <button class="g s" data-act="editp" data-v="${p.id}">Ubah</button> <button class="g s" data-act="delp" data-v="${p.id}">Hapus</button></td></tr>`).join('')
 ||'<tr><td colspan="9" class="st">Belum ada produk.</td></tr>'}</tbody></table></div></section>`;
}

function vGdg(){
 return`<section class="card"><h2>Tambah Gudang</h2><form data-form="gdg"><div class="grid">
 <div><label>Kode</label><input name="kode" required maxlength="20"></div>
 <div><label>Nama gudang</label><input name="nama" required maxlength="120"></div>
 <div><label>Kapasitas (unit, opsional)</label><input name="kap" type="number" min="0" step="any" value="0"></div></div>
 <div class="row"><button>Tambah gudang</button></div></form></section>
 <section class="card"><div class="tw"><table><thead><tr><th>Kode</th><th>Nama</th><th>Total unit</th><th>Kapasitas</th><th>Terisi</th><th></th></tr></thead><tbody>${
 S.w.map(w=>`<tr><td>${esc(w.kode)}</td><td>${esc(w.nama)}</td><td>${n(S.p.reduce((a,p)=>a+stok(p.id,w.id),0))}</td><td>${w.kap?n(w.kap):'-'}</td><td class="${w.kap&&S.p.reduce((a,p)=>a+stok(p.id,w.id),0)>w.kap?'bad':''}">${w.kap?n(S.p.reduce((a,p)=>a+stok(p.id,w.id),0)/w.kap*100)+'%':'-'}</td><td><button class="g s" data-act="delw" data-v="${w.id}">Hapus</button></td></tr>`).join('')}</tbody></table></div></section>`;
}

const SEED=[{"user":"kepala.gudang","nama":"Kepala Gudang","role":"admin","salt":"e3b0dbb54b68d2d96864daf562076693","hash":"p:b65694746601f54ba36c01c515eb096dc9aece93829fc3760fcbcd8751761cd2","hf":"f:1c22f7ade03bd5","must":true},{"user":"staf1","nama":"Staf Gudang 1","role":"staf","salt":"e16526cff996c9880f2e46d1e819ac3e","hash":"p:01688d55fcfe1a1f5ffbe8976e9393a3b82773d268a39ff9b770fe01f16a17cd","hf":"f:16f31d3a3da706","must":true},{"user":"staf2","nama":"Staf Gudang 2","role":"staf","salt":"81171ef206cfe21d8c535f11d47200e6","hash":"p:8d4f62567f58ff40b73dd64a54f6e169e3f63e629a882816bec3d516fe707259","hf":"f:104639c62db7ef","must":true},{"user":"staf3","nama":"Staf Gudang 3","role":"staf","salt":"36349b322f61f1eab276a68f420b1921","hash":"p:b239153611ca8589f31e88ae0a23f53c18b4bb22822b10236fa0618fa238ab82","hf":"f:1486da7cfe20a6","must":true},{"user":"staf4","nama":"Staf Gudang 4","role":"staf","salt":"7b9758f1e703d6e9cce90c645b13798f","hash":"p:36ca4bea5b62c5f3f2949d7606db9796f8931a147cb0eccc394135faeb2b00a2","hf":"f:1481c7a791d164","must":true},{"user":"staf5","nama":"Staf Gudang 5","role":"staf","salt":"9ec7a546edde5aeac85c1ae4cff12b73","hash":"p:7bc995e3be3a78cf0c02e3ffad71bb283385adcba529aa09518b0628991f2469","hf":"f:1eb6a7da3b916b","must":true},{"user":"pengawas","nama":"Pengawas","role":"lihat","salt":"7ab2fc832b47cb5a4a91e950522a0d22","hash":"p:249842c823437eefa8286e5215070ccf6af7453e4863139b4d89e4f2fbf24231","hf":"f:73a89122c4877","must":true}];
function fix(){S.u=Array.isArray(S.u)?S.u:[];if(!S.u.length&&!S.sd){S.u=SEED.map(x=>({...x,id:uid()}));S.sd=1;save()}S.x=S.x||[];S.o=S.o||[];S.e=S.e||['JNE','J&T','SiCepat','Kurir Internal'].map(nama=>({id:uid(),nama}))}
fix();
try{const sid=sessionStorage.getItem(SK);ME=S.u.find(x=>x.id==sid)||null}catch(e){}
const rp=v=>'Rp '+n(v),ymd=d=>d.toLocaleDateString('sv-SE'),opt=(arr,f)=>arr.map(x=>`<option value="${x.id}">${esc(f(x))}</option>`).join('');
let R={a:ymd(new Date(new Date().getFullYear(),new Date().getMonth(),1)),b:ymd(new Date())};

function vExp(){
 return`<section class="card"><h2>Buat Pengiriman</h2><form data-form="ship"><div class="grid">
 <div><label>Nama penerima</label><input name="nama" required maxlength="120"></div>
 <div><label>Alamat tujuan</label><input name="almt" required maxlength="255"></div>
 <div><label>Ekspedisi</label><select name="kurir" required>${S.e.map(k=>`<option>${esc(k.nama)}</option>`).join('')}</select></div>
 <div><label>No. resi</label><input name="resi" maxlength="60"></div>
 <div><label>Produk</label><select name="p" required><option value="">Pilih produk</option>${opt(S.p,x=>x.sku+' - '+x.nama+(loc(x)?' ['+loc(x)+']':''))}</select></div>
 <div><label>Dari gudang</label><select name="a" required><option value="">Pilih gudang</option>${opt(S.w,x=>x.nama)}</select></div>
 <div><label>Jumlah</label><input name="q" type="number" min="0.01" step="any" required></div>
 <div><label>Ongkos kirim (Rp)</label><input name="ongkir" type="number" min="0" step="any" value="0"></div></div>
 <div class="row"><button>Buat pengiriman</button><span class="st ${msg?msg.t:''}">${esc(msg?msg.x:'')}</span></div></form></section>
 <section class="card"><h2>Daftar Pengiriman</h2><div class="tw"><table><thead><tr><th>No. surat jalan</th><th>Penerima</th><th>Ekspedisi</th><th>Barang</th><th>Ongkir</th><th>Status</th><th></th></tr></thead><tbody>${
 S.x.map(x=>`<tr><td>${esc(x.no)}<div class="st">${new Date(x.at).toLocaleDateString('id-ID',{dateStyle:'medium'})}</div></td><td>${esc(x.nama)}<div class="st">${esc(x.almt)}</div></td><td>${esc(x.kurir)}${x.resi?'<div class="st">'+esc(x.resi)+'</div>':''}</td><td>${n(x.q)} ${esc(pn(x.p))}</td><td>${rp(x.ongkir)}</td><td class="${x.st=='Diterima'?'ok':x.st=='Batal'?'bad':''}">${x.st}</td><td>${x.st=='Dikirim'?`<button class="g s" data-act="sts" data-v="${x.id}" data-s="Diterima">Diterima</button> <button class="g s" data-act="sts" data-v="${x.id}" data-s="Batal">Batalkan</button>`:''}</td></tr>`).join('')
 ||'<tr><td colspan="7" class="st">Belum ada pengiriman. Stok berkurang otomatis saat pengiriman dibuat.</td></tr>'}</tbody></table></div></section>
 <section class="card"><h2>Daftar Ekspedisi</h2><form data-form="kurir"><div class="row" style="margin-top:0"><input name="nama" required maxlength="60" placeholder="Nama ekspedisi" style="max-width:260px"><button>Tambah</button></div></form>
 <div class="row">${S.e.map(k=>`<span class="bd">${esc(k.nama)} <button class="g s" data-act="dele" data-v="${k.id}">Hapus</button></span>`).join('')}</div></section>`;
}

function lapData(){
 const a=new Date(R.a+'T00:00:00').getTime(),z=new Date(R.b+'T23:59:59.999').getTime();
 const m=S.m.filter(x=>x.at>=a&&x.at<=z),sx=S.x.filter(x=>x.at>=a&&x.at<=z),bt=x=>(x.r||'').startsWith('BATAL ');
 const sm=(arr,p)=>arr.filter(x=>x.p==p.id).reduce((t,x)=>t+x.q,0),inn=m.filter(x=>x.t=='IN');
 const prod=S.p.map(p=>({p,masuk:sm(inn.filter(x=>!bt(x)),p),keluar:r2(sm(m.filter(x=>x.t=='OUT'),p)-sm(inn.filter(bt),p)),pindah:sm(m.filter(x=>x.t=='TRANSFER'),p),opname:r2(m.filter(x=>x.t=='ADJ'&&x.p==p.id).reduce((t,x)=>t+x.d,0)),stok:total(p)}));
 const ok=sx.filter(x=>x.st!='Batal');
 const kur=[...new Set(ok.map(x=>x.kurir))].map(nama=>{const l=ok.filter(x=>x.kurir==nama);return{nama,jml:l.length,qty:l.reduce((t,x)=>t+x.q,0),ongkir:l.reduce((t,x)=>t+x.ongkir,0)}});
 return{prod,kur,kirim:ok.length,batal:sx.length-ok.length,ongkir:ok.reduce((t,x)=>t+x.ongkir,0),masuk:prod.reduce((t,r)=>t+r.masuk,0),keluar:prod.reduce((t,r)=>t+r.keluar,0)};
}
function csv(){
 const d=lapData(),c=r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',');
 return[c(['Laporan',R.a,R.b]),c(['SKU','Produk','Masuk','Keluar','Pindah','Selisih opname','Stok saat ini']),...d.prod.map(r=>c([r.p.sku,r.p.nama,r.masuk,r.keluar,r.pindah,r.opname,r.stok])),'',c(['Ekspedisi','Pengiriman','Jumlah barang','Ongkir']),...d.kur.map(r=>c([r.nama,r.jml,r.qty,r.ongkir]))].join('\n');
}
function vLap(){
 const d=lapData();
 return`<section class="card noprint"><h2>Periode Laporan</h2><div class="grid"><div><label>Dari tanggal</label><input type="date" id="r1" value="${R.a}"></div><div><label>Sampai tanggal</label><input type="date" id="r2" value="${R.b}"></div></div>
 <div class="row"><button data-act="csv">Salin CSV</button><button class="g" data-act="prt">Cetak laporan</button></div><textarea id="csvout" rows="2" style="margin-top:10px" placeholder="Hasil CSV muncul di sini"></textarea></section>
 <h2 style="display:none">Laporan ${R.a} sampai ${R.b}</h2>
 <section class="stats"><div class="stat"><span>Barang masuk</span><b>${n(d.masuk)}</b></div><div class="stat"><span>Barang keluar</span><b>${n(d.keluar)}</b></div>
 <div class="stat"><span>Pengiriman</span><b>${d.kirim}</b><span>${d.batal} dibatalkan</span></div><div class="stat"><span>Total ongkir</span><b>${rp(d.ongkir)}</b></div></section>
 <section class="card"><h2>Mutasi per Produk</h2><div class="tw"><table><thead><tr><th>SKU</th><th>Produk</th><th>Masuk</th><th>Keluar</th><th>Pindah</th><th>Opname</th><th>Stok saat ini</th></tr></thead><tbody>${
 d.prod.map(r=>`<tr><td>${esc(r.p.sku)}</td><td>${esc(r.p.nama)}</td><td>${n(r.masuk)}</td><td>${n(r.keluar)}</td><td>${n(r.pindah)}</td><td>${r.opname>0?'+':''}${n(r.opname)}</td><td><b>${n(r.stok)} ${esc(r.p.sat)}</b></td></tr>`).join('')||'<tr><td colspan="7" class="st">Belum ada produk.</td></tr>'}</tbody></table></div></section>
 <section class="card"><h2>Nilai Persediaan per Gudang</h2><div class="tw"><table><thead><tr><th>Gudang</th><th></th><th>Total unit</th><th>Nilai (harga beli)</th></tr></thead><tbody>${S.w.map(w=>`<tr><td>${esc(w.nama)}</td><td></td><td>${n(S.p.reduce((a,p)=>a+stok(p.id,w.id),0))}</td><td>${rp(S.p.reduce((a,p)=>a+stok(p.id,w.id)*(p.hrg||0),0))}</td></tr>`).join('')}</tbody></table></div></section>
 <section class="card"><h2>Pengiriman per Ekspedisi</h2><div class="tw"><table><thead><tr><th>Ekspedisi</th><th></th><th>Pengiriman</th><th>Jumlah barang</th><th>Ongkir</th></tr></thead><tbody>${
 d.kur.map(r=>`<tr><td>${esc(r.nama)}</td><td></td><td>${r.jml}</td><td>${n(r.qty)}</td><td>${rp(r.ongkir)}</td></tr>`).join('')||'<tr><td colspan="5" class="st">Tidak ada pengiriman pada periode ini.</td></tr>'}</tbody></table></div></section>`;
}
let O={a:'',q:{},c:''};
function selTxt(v,s){if(v===''||v==null)return'';const d=r2(+v-s);return d==0?'<span class="ok">Sesuai</span>':`<span class="bad">${d>0?'+':''}${n(d)}</span>`}
function opname(){
 const a=O.a;if(!a)return'Pilih gudang';
 const lines=[];
 for(const p of S.p){const v=O.q[p.id];if(v===undefined||v==='')continue;const f=+v;if(!(f>=0))return`Stok fisik ${p.nama} tidak valid`;lines.push({p:p.id,sis:stok(p.id,a),fis:r2(f)})}
 if(!lines.length)return'Isi stok fisik minimal satu produk';
 const day=ymd(new Date()).replace(/-/g,''),no='ON-'+day+'-'+String(S.o.filter(x=>x.no.startsWith('ON-'+day)).length+1).padStart(3,'0'),at=Date.now();
 const prev=[S.s,S.m,S.o],ns={...S.s},mv=[];
 for(const l of lines){const d=r2(l.fis-l.sis);l.sel=d;if(d){ns[l.p+'|'+a]=l.fis;mv.push({id:uid(),t:'ADJ',p:l.p,a,b:'',q:Math.abs(d),d,r:no,c:O.c||'Stock opname',u:ME?ME.nama:'',at})}}
 S.s=ns;S.m=[...mv,...S.m].slice(0,2000);S.o=[{id:uid(),no,a,at,u:ME?ME.nama:'',c:O.c,lines},...S.o];
 if(!save()){[S.s,S.m,S.o]=prev;return'Penyimpanan gagal, opname dibatalkan'}
 return'';
}
function vOpn(){
 const a=O.a;
 const rows=a?S.p.map(p=>{const s=stok(p.id,a),v=O.q[p.id]??'';return`<tr><td>${esc(p.sku)}</td><td>${esc(p.nama)}</td><td>${n(s)} ${esc(p.sat)}</td><td><input data-op="${p.id}" type="number" min="0" step="any" value="${esc(v)}" style="width:110px;text-align:right"></td><td id="sel${p.id}">${selTxt(v,s)}</td></tr>`}).join(''):'';
 return`<section class="card"><h2>Stock Opname Baru</h2><div class="grid">
 <div><label>Gudang yang dihitung</label><select id="opa"><option value="">Pilih gudang</option>${S.w.map(w=>`<option value="${w.id}" ${w.id==a?'selected':''}>${esc(w.nama)}</option>`).join('')}</select></div>
 <div><label>Catatan</label><input id="opc" maxlength="255" value="${esc(O.c)}" placeholder="Contoh: opname akhir bulan"></div></div>
 ${a?`<p class="st">Isi stok fisik hasil hitungan. Produk yang dibiarkan kosong tidak diubah.</p><div class="tw"><table><thead><tr><th>SKU</th><th>Produk</th><th>Stok sistem</th><th>Stok fisik</th><th>Selisih</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="st">Belum ada produk.</td></tr>'}</tbody></table></div>
 <div class="row"><button data-act="opsave">Simpan hasil opname</button><span class="st ${msg?msg.t:''}">${esc(msg?msg.x:'')}</span></div>`:`<div class="row"><span class="st ${msg?msg.t:''}">${esc(msg?msg.x:'Pilih gudang untuk mulai menghitung.')}</span></div>`}</section>
 <section class="card"><h2>Riwayat Opname</h2>${S.o.map(o=>{const df=o.lines.filter(l=>l.sel),net=r2(df.reduce((t,l)=>t+l.sel,0));
  return`<details style="border-bottom:1px solid var(--line);padding:8px 0"><summary><b>${esc(o.no)}</b> <span class="st">${new Date(o.at).toLocaleDateString('id-ID',{dateStyle:'medium'})}, ${esc(wn(o.a))}${o.u?', oleh '+esc(o.u):''}: ${o.lines.length} produk dihitung, ${df.length} berselisih (total ${net>0?'+':''}${n(net)})</span></summary>
  ${o.c?`<p class="st">${esc(o.c)}</p>`:''}<div class="tw"><table><thead><tr><th>SKU</th><th>Produk</th><th>Sistem</th><th>Fisik</th><th>Selisih</th></tr></thead><tbody>${o.lines.map(l=>{const p=S.p.find(x=>x.id==l.p)||{};return`<tr><td>${esc(p.sku)}</td><td>${esc(p.nama||'(dihapus)')}</td><td>${n(l.sis)}</td><td>${n(l.fis)}</td><td>${selTxt(l.fis,l.sis)}</td></tr>`}).join('')}</tbody></table></div></details>`}).join('')||'<p class="st">Belum ada opname.</p>'}</section>`;
}
document.addEventListener('input',e=>{const t=e.target;if(t.dataset.op!==undefined){O.q[t.dataset.op]=t.value;const c=$('#sel'+t.dataset.op);if(c)c.innerHTML=selTxt(t.value,stok(t.dataset.op,O.a))}else if(t.id=='opc')O.c=t.value});
document.addEventListener('change',e=>{if(e.target.id=='opa'){O.a=e.target.value;O.q={};msg=null;view()}});
let KS={p:'',g:''};
function eff(m,g){const q=m.q;if(!g)return m.t=='IN'?q:m.t=='OUT'?-q:m.t=='ADJ'?m.d:0;let e=0;if(m.a==g)e+=m.t=='IN'?q:m.t=='ADJ'?m.d:-q;if(m.b==g&&m.t=='TRANSFER')e+=q;return e}
function vKartu(){
 const p=S.p.find(x=>x.id==KS.p),g=KS.g;let body='<p class="st">Pilih produk untuk melihat kartu stoknya.</p>';
 if(p){
  const L=S.m.filter(m=>m.p==p.id).reverse();
  let s=r2((g?stok(p.id,g):total(p))-L.reduce((t,m)=>t+eff(m,g),0));
  const rows=L.map(m=>{const e=eff(m,g);s=r2(s+e);return{m,e,s}}).slice(-200),awal=rows.length?r2(rows[0].s-rows[0].e):s;
  body=`<div class="tw"><table><thead><tr><th>Waktu</th><th>Jenis</th><th>Referensi</th><th>Masuk</th><th>Keluar</th><th>Saldo</th></tr></thead><tbody><tr><td colspan="5">Saldo awal</td><td><b>${n(awal)}</b></td></tr>${rows.map(r=>`<tr><td>${new Date(r.m.at).toLocaleString('id-ID',{dateStyle:'medium',timeStyle:'short'})}</td><td>${TP[r.m.t]||'Opname'}</td><td>${esc(r.m.r)}</td><td>${r.e>0?n(r.e):''}</td><td>${r.e<0?n(-r.e):''}</td><td><b>${n(r.s)}</b></td></tr>`).join('')}</tbody></table></div>`;
 }
 return`<section class="card"><h2>Kartu Stok</h2><div class="grid">
 <div><label>Produk</label><select id="kp"><option value="">Pilih produk</option>${S.p.map(x=>`<option value="${x.id}" ${x.id==KS.p?'selected':''}>${esc(x.sku+' - '+x.nama)}</option>`).join('')}</select></div>
 <div><label>Gudang</label><select id="kg"><option value="">Semua gudang</option>${S.w.map(w=>`<option value="${w.id}" ${w.id==g?'selected':''}>${esc(w.nama)}</option>`).join('')}</select></div></div></section>
 <section class="card">${body}</section>`;
}
function restok(){return S.p.filter(p=>total(p)<=p.min).map(p=>({p,t:total(p),saran:p.min>0?r2(p.min*2-total(p)):0})).sort((a,b)=>a.t-b.t)}
function vRestok(){
 const L=restok(),est=L.reduce((t,r)=>t+r.saran*(r.p.hrg||0),0);
 return`<section class="card"><h2>Daftar Restok</h2><p class="st">Produk dengan stok di bawah atau sama dengan batas minimum. Saran pesan mengisi stok hingga dua kali batas minimum.</p>
 <div class="tw"><table><thead><tr><th>SKU</th><th>Produk</th><th>Stok</th><th>Minimum</th><th>Saran pesan</th><th>Estimasi biaya</th>${canW()?'<th></th>':''}</tr></thead><tbody>${L.map(r=>`<tr><td>${esc(r.p.sku)}</td><td>${esc(r.p.nama)}<div class="st">${esc(loc(r.p))}</div></td><td class="bad">${n(r.t)} ${esc(r.p.sat)}</td><td>${n(r.p.min)}</td><td>${r.saran?n(r.saran)+' '+esc(r.p.sat):'-'}</td><td>${rp(r.saran*(r.p.hrg||0))}</td>${canW()?`<td><button class="s" data-act="addstok" data-v="${r.p.id}" data-q="${r.saran||''}">+ Stok</button></td>`:''}</tr>`).join('')||`<tr><td colspan="${canW()?7:6}" class="st">Semua stok di atas batas minimum.</td></tr>`}</tbody></table></div>
 <div class="row"><b>Estimasi total: ${rp(est)}</b><button data-act="rcopy">Salin daftar belanja</button></div><textarea id="rout" rows="2" style="margin-top:10px" placeholder="Daftar belanja muncul di sini"></textarea></section>`;
}
document.addEventListener('change',e=>{const i=e.target.id;if(i=='kp'||i=='kg'){KS[i=='kp'?'p':'g']=e.target.value;view()}});
document.addEventListener('change',e=>{if(e.target.id=='r1'||e.target.id=='r2'){R[e.target.id=='r1'?'a':'b']=e.target.value;if(R.a&&R.b)view()}});

document.addEventListener('click',async e=>{
 const b=e.target.closest('[data-act]');if(!b)return;const a=b.dataset.act,v=b.dataset.v;
 if(!ME)return;
 if(ME.must&&a!='logout')return;
 if(['addstok','sts','opsave'].includes(a)&&!canW())return toast('Peran Anda tidak boleh mengubah data',1);
 if(['editp','delp','delw','dele','bkup','rest','editu','delu','cancelu'].includes(a)&&!isA())return toast('Hanya Kepala Gudang yang bisa melakukan ini',1);
 if(a=='logout')logout();
 else if(a=='editu'){UE={...S.u.find(x=>x.id==v)};UM=null}
 else if(a=='cancelu'){UE={};UM=null}
 else if(a=='delu'){const u=S.u.find(x=>x.id==v);if(!u||u.id==ME.id)return toast('Tidak bisa menghapus akun sendiri',1);if(u.role=='admin'&&S.u.filter(x=>x.role=='admin').length<2)return toast('Harus ada minimal satu Kepala Gudang',1);S.u=S.u.filter(x=>x.id!=v);save();toast('Pengguna dihapus')}
 else if(a=='tab'){tab=v;msg=null;UM=null;UE={}}
 else if(a=='addstok'){if(!S.w.length)return toast('Belum ada gudang',1);AS={p:v,a:S.w[0].id,q:b.dataset.q||'',c:'',err:''}}
 else if(a=='closeadd')AS=null;
 else if(a=='type'){T.t=v;msg=null}
 else if(a=='editp')E={...S.p.find(p=>p.id==v)};
 else if(a=='cancel')E={};
 else if(a=='delp'){const p=S.p.find(x=>x.id==v);if(total(p)>0)return toast('Produk masih punya stok, kosongkan dulu lewat barang keluar',1);S.p=S.p.filter(x=>x.id!=v);save()}
 else if(a=='delw'){if(S.w.length<2)return toast('Minimal harus ada satu gudang',1);if(S.p.some(p=>stok(p.id,v)>0))return toast('Gudang masih berisi stok, pindahkan dulu',1);S.w=S.w.filter(w=>w.id!=v);save()}
 else if(a=='rcopy'){const t=restok().filter(r=>r.saran>0).map(r=>`${r.p.sku} - ${r.p.nama}: ${n(r.saran)} ${r.p.sat}`).join('\n');$('#rout').value=t;try{await navigator.clipboard.writeText(t);toast('Daftar disalin')}catch(x){$('#rout').select();toast('Salin manual dari kotak teks')}return}
 else if(a=='opsave'){const err=opname();msg=err?{t:'bad',x:err}:{t:'ok',x:'Opname tersimpan, stok sudah disesuaikan'};if(!err){O.q={};O.c=''}}
 else if(a=='sts'){const x=S.x.find(z=>z.id==v);if(!x||x.st!='Dikirim')return;
  if(b.dataset.s=='Batal'){const err=move({t:'IN',p:x.p,a:x.a,q:x.q,r:'BATAL '+x.no,c:'Pembatalan pengiriman'});if(err)return toast(err,1)}
  x.st=b.dataset.s;save();toast('Status pengiriman diperbarui')}
 else if(a=='dele'){S.e=S.e.filter(k=>k.id!=v);save()}
 else if(a=='csv'){const t=csv();$('#csvout').value=t;try{await navigator.clipboard.writeText(t);toast('CSV disalin')}catch(x){$('#csvout').select();toast('Salin manual dari kotak teks')}return}
 else if(a=='prt'){try{window.print()}catch(x){toast('Cetak tidak tersedia di sini',1)}return}
 else if(a=='bkup'){const t=JSON.stringify({...S,u:undefined});$('#bk').value=t;try{await navigator.clipboard.writeText(t);toast('Cadangan disalin')}catch(x){$('#bk').select();toast('Salin manual dari kotak teks')}return}
 else if(a=='rest'){try{const d=JSON.parse($('#bk').value);if(!Array.isArray(d.p)||!Array.isArray(d.w)||!d.w.length||typeof d.s!='object'||!Array.isArray(d.m))throw 0;const ku=S.u;S=d;S.u=ku;fix();save();toast('Data dipulihkan')}catch(x){return toast('Format cadangan tidak valid',1)}}
 view();
});
document.addEventListener('input',e=>{if(e.target.id=='q'){q=e.target.value;tbl()}});
document.addEventListener('change',e=>{const f=e.target.closest('form[data-form=trx]');if(f&&e.target.name)T[e.target.name]=e.target.value});
document.addEventListener('submit',async e=>{
 e.preventDefault();const f=e.target.dataset.form,d=Object.fromEntries(new FormData(e.target));
 if(['login','setup','user','pw'].includes(f)){
  if(f=='user'&&!isA())return;if(f=='pw'&&!ME)return;
  try{await authForm(f,d)}catch(x){AE='Terjadi kesalahan, coba lagi';UM={t:'bad',x:'Terjadi kesalahan, coba lagi'}}
  view();return}
 if(!ME)return;
 if(ME.must)return;
 if(['addstok','trx','ship'].includes(f)&&!canW())return toast('Peran Anda tidak boleh mengubah data',1);
 if(['prd','kurir','gdg'].includes(f)&&!isA())return toast('Hanya Kepala Gudang yang bisa melakukan ini',1);
 if(f=='addstok'){
  AS={...AS,...d,err:''};
  const err=move({t:'IN',p:AS.p,a:AS.a,q:AS.q,r:'TAMBAH STOK',c:(AS.c||'').trim()||'Penambahan stok'});
  if(err)AS.err=err;else{const p=S.p.find(x=>x.id==AS.p);toast(`Stok ${p?p.nama:''} bertambah ${n(AS.q)}`);AS=null}
 }else if(f=='trx'){T={...T,...d};const err=move(T);msg={t:err?'bad':'ok',x:err||'Transaksi tersimpan'};if(!err)T={...T,q:'',r:'',c:''}}
 else if(f=='prd'){
  const sku=d.sku.trim();if(S.p.some(p=>p.sku.toLowerCase()==sku.toLowerCase()&&p.id!=d.id))return toast('SKU sudah dipakai',1);
  const o={sku,nama:d.nama.trim(),sat:d.sat.trim(),min:+d.min,kat:d.kat.trim(),rak:d.rak.trim(),line:(d.line||'').trim(),hrg:+d.hrg||0};
  if(d.id)S.p=S.p.map(p=>p.id==d.id?{...p,...o}:p);else S.p.push({id:uid(),...o});
  E={};save();toast('Produk tersimpan');
 }else if(f=='ship'){
  const day=ymd(new Date()).replace(/-/g,''),no='SJ-'+day+'-'+String(S.x.filter(x=>x.no.startsWith('SJ-'+day)).length+1).padStart(3,'0');
  const err=move({t:'OUT',p:d.p,a:d.a,q:d.q,r:no,c:'Pengiriman ke '+d.nama});
  if(err)msg={t:'bad',x:err};
  else{S.x.unshift({id:uid(),no,nama:d.nama.trim(),almt:d.almt.trim(),kurir:d.kurir,resi:d.resi.trim(),p:d.p,a:d.a,q:+d.q,ongkir:+d.ongkir||0,st:'Dikirim',u:ME?ME.nama:'',at:Date.now()});save();msg={t:'ok',x:'Pengiriman '+no+' dibuat, stok berkurang otomatis'}}
 }else if(f=='kurir'){
  const nama=d.nama.trim();if(S.e.some(k=>k.nama.toLowerCase()==nama.toLowerCase()))return toast('Ekspedisi sudah ada',1);
  S.e.push({id:uid(),nama});save();toast('Ekspedisi ditambahkan');
 }else if(f=='gdg'){
  const kode=d.kode.trim().toUpperCase();if(S.w.some(w=>w.kode==kode))return toast('Kode gudang sudah dipakai',1);
  S.w.push({id:uid(),kode,nama:d.nama.trim(),kap:+d.kap||0});save();toast('Gudang ditambahkan');
 }
 view();
});
view();
