#!/usr/bin/env python3
"""DS Company social venture IR voting. Python stdlib server; qrcode optional."""
import os, json, sqlite3, secrets, hashlib, hmac, base64, csv, io, time, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from pathlib import Path
from http.cookies import SimpleCookie

ROOT=Path(__file__).resolve().parent
DB=Path(os.getenv('IR_DB_PATH',str(ROOT/'ir_data.sqlite3')))
HOST=os.getenv('IR_HOST','0.0.0.0'); PORT=int(os.getenv('IR_PORT','8080'))
ADMIN_PASSWORD=os.getenv('IR_ADMIN_PASSWORD','')
BASE_URL=os.getenv('IR_BASE_URL',f'http://localhost:{PORT}').rstrip('/')
SECRET=os.getenv('IR_SESSION_SECRET','') or secrets.token_hex(32)
SESSIONS={}
CRITERIA={'social':40,'profit':30,'feasible':30}

def connect():
    c=sqlite3.connect(DB,timeout=15); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA journal_mode=WAL'); return c

def init():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', show_results INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER NOT NULL REFERENCES classes(id), name TEXT NOT NULL, UNIQUE(class_id,name));
        CREATE TABLE IF NOT EXISTS voters(id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER NOT NULL REFERENCES classes(id), team_id INTEGER NOT NULL REFERENCES teams(id), code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL, submitted_at TEXT);
        CREATE TABLE IF NOT EXISTS ratings(id INTEGER PRIMARY KEY AUTOINCREMENT, voter_id INTEGER NOT NULL REFERENCES voters(id), target_team_id INTEGER NOT NULL REFERENCES teams(id), social INTEGER NOT NULL, profit INTEGER NOT NULL, feasible INTEGER NOT NULL, UNIQUE(voter_id,target_team_id));
        ''')
        for i in range(1,9): c.execute('INSERT OR IGNORE INTO classes(id,name) VALUES(?,?)',(i,f'{i}반'))

def hcode(code):return hashlib.sha256(code.strip().upper().encode()).hexdigest()
def jsonbytes(obj):return json.dumps(obj,ensure_ascii=False,separators=(',',':')).encode()
def newcode():return '-'.join([''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4)) for _ in range(3)])

def overview(c, cid, detail=False):
    cl=c.execute('SELECT * FROM classes WHERE id=?',(cid,)).fetchone()
    if not cl:return None
    teams=[dict(x) for x in c.execute('SELECT id,name FROM teams WHERE class_id=? ORDER BY id',(cid,))]
    total=c.execute('SELECT COUNT(*) FROM voters WHERE class_id=?',(cid,)).fetchone()[0]
    done=c.execute('SELECT COUNT(*) FROM voters WHERE class_id=? AND submitted_at IS NOT NULL',(cid,)).fetchone()[0]
    result={'id':cid,'name':cl['name'],'status':cl['status'],'show_results':bool(cl['show_results']),'teams':teams,'registered':total,'submitted':done,'url':f'{BASE_URL}/c/{cid}'}
    if detail:
        stats=[]
        for t in teams:
            r=c.execute('SELECT COUNT(*) n, AVG(social) social, AVG(profit) profit, AVG(feasible) feasible, AVG(social+profit+feasible) total FROM ratings WHERE target_team_id=?',(t['id'],)).fetchone()
            stats.append({'team_id':t['id'],'name':t['name'],'count':r['n'],'social':round(r['social'],2) if r['social'] is not None else None,'profit':round(r['profit'],2) if r['profit'] is not None else None,'feasible':round(r['feasible'],2) if r['feasible'] is not None else None,'total':round(r['total'],2) if r['total'] is not None else None})
        stats.sort(key=lambda x: (x['total'] is None,-(x['total'] or 0),x['name']))
        result['results']=stats
    return result

class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args): print('%s %s'%(self.address_string(),fmt%args))
    def send(self,status,obj=None,ctype='application/json; charset=utf-8',extra=None):
        data=jsonbytes(obj) if ctype.startswith('application/json') else (obj if isinstance(obj,bytes) else obj.encode())
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Frame-Options','DENY')
        for k,v in (extra or {}).items():self.send_header(k,v)
        self.end_headers();self.wfile.write(data)
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if n>100000:return None
        try:return json.loads(self.rfile.read(n))
        except:return None
    def admin(self):
        cookie=SimpleCookie()
        try:cookie.load(self.headers.get('Cookie',''))
        except:return False
        tok=cookie.get('ir_admin')
        if not tok:return False
        try:payload,sig=tok.value.rsplit('.',1);raw=base64.urlsafe_b64decode(payload+'='*(-len(payload)%4));expect=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest();return hmac.compare_digest(sig,expect) and int(raw.decode())>time.time()
        except:return False
    def student(self):
        auth=self.headers.get('Authorization','')
        if not auth.startswith('Bearer '):return None
        token=auth[7:];entry=SESSIONS.get(token)
        if not entry or entry[1]<time.time():return None
        return entry[0]
    def needadmin(self):
        if not self.admin():self.send(401,{'error':'관리자 로그인이 필요합니다.'});return False
        return True
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/' or p=='/admin' or re.fullmatch(r'/c/[1-8]',p):
            self.send(200,(ROOT/'static'/'index.html').read_bytes(),'text/html; charset=utf-8');return
        if p=='/api/public/classes':
            with connect() as c:self.send(200,[{'id':x['id'],'name':x['name']} for x in c.execute('SELECT id,name FROM classes')]);return
        m=re.fullmatch(r'/api/public/class/([1-8])',p)
        if m:
            with connect() as c:
                x=overview(c,int(m[1]));self.send(200,{'id':x['id'],'name':x['name'],'status':x['status'],'teams':x['teams']});return
        if p=='/api/student/me':
            vid=self.student()
            if not vid:self.send(401,{'error':'평가코드를 다시 입력해주세요.'});return
            with connect() as c:
                v=c.execute('SELECT * FROM voters WHERE id=?',(vid,)).fetchone();cl=overview(c,v['class_id']);own=next(t for t in cl['teams'] if t['id']==v['team_id']);self.send(200,{'class':cl['name'],'status':cl['status'],'own_team':own,'targets':[t for t in cl['teams'] if t['id']!=v['team_id']],'submitted':bool(v['submitted_at'])});return
        if p=='/api/admin/overview':
            if not self.needadmin():return
            with connect() as c:self.send(200,[overview(c,i,True) for i in range(1,9)]);return
        m=re.fullmatch(r'/api/admin/codes/([1-8])\.csv',p)
        if m:
            if not self.needadmin():return
            self.send(410,{'error':'보안을 위해 평가코드는 생성 순간에만 다운로드할 수 있습니다. 새 코드를 추가 발급하세요.'});return
        m=re.fullmatch(r'/api/admin/results/([1-8])\.csv',p)
        if m:
            if not self.needadmin():return
            cid=int(m[1]);buf=io.StringIO();w=csv.writer(buf);w.writerow(['학급','팀명','평가수','사회적 가치 평균(40)','수익 가능성 평균(30)','실현 가능성 평균(30)','총점 평균(100)'])
            with connect() as c:
                x=overview(c,cid,True)
                for r in x['results']:w.writerow([x['name'],r['name'],r['count'],r['social'],r['profit'],r['feasible'],r['total']])
            self.send(200,'\ufeff'.encode()+buf.getvalue().encode(),'text/csv; charset=utf-8',{'Content-Disposition':f'attachment; filename="class_{cid}_results.csv"'});return
        m=re.fullmatch(r'/api/admin/qr/([1-8])\.png',p)
        if m:
            if not self.needadmin():return
            try:
                import qrcode
                b=io.BytesIO();qrcode.make(f'{BASE_URL}/c/{m[1]}').save(b,format='PNG');self.send(200,b.getvalue(),'image/png')
            except ImportError:self.send(500,{'error':'QR 생성을 위해 pip install qrcode[pil] 실행이 필요합니다.'})
            return
        self.send(404,{'error':'페이지를 찾을 수 없습니다.'})
    def do_POST(self):
        p=urlparse(self.path).path;d=self.body()
        if not isinstance(d,dict):self.send(400,{'error':'요청 형식이 올바르지 않습니다.'});return
        if p=='/api/admin/login':
            pw=str(d.get('password',''))
            if not ADMIN_PASSWORD or not hmac.compare_digest(pw,ADMIN_PASSWORD):self.send(401,{'error':'관리자 비밀번호가 올바르지 않습니다.'});return
            payload=base64.urlsafe_b64encode(str(int(time.time()+8*3600)).encode()).decode().rstrip('=');sig=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
            secure='; Secure' if self.headers.get('X-Forwarded-Proto')=='https' else ''
            self.send(200,{'ok':True},extra={'Set-Cookie':f'ir_admin={payload}.{sig}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{secure}'})
            return
        if p=='/api/admin/logout':
            self.send(200,{'ok':True},extra={'Set-Cookie':'ir_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});return
        if p=='/api/student/login':
            cid=d.get('class_id');code=str(d.get('code','')).strip().upper()
            if not isinstance(cid,int) or not 1<=cid<=8 or not code:self.send(400,{'error':'학급과 평가코드를 확인하세요.'});return
            with connect() as c:
                v=c.execute('SELECT * FROM voters WHERE class_id=? AND code_hash=?',(cid,hcode(code))).fetchone()
                if not v:self.send(401,{'error':'평가코드가 올바르지 않습니다.'});return
                if v['submitted_at']:self.send(409,{'error':'이미 제출한 평가코드입니다.'});return
                cl=c.execute('SELECT status FROM classes WHERE id=?',(cid,)).fetchone()
                if cl['status']!='open':self.send(409,{'error':'현재 평가가 진행 중이지 않습니다.'});return
                token=secrets.token_urlsafe(32);SESSIONS[token]=(v['id'],time.time()+3*3600)
                self.send(200,{'token':token});return
        if p=='/api/student/submit':
            vid=self.student()
            if not vid:self.send(401,{'error':'인증이 만료되었습니다. 평가코드를 다시 입력해주세요.'});return
            ratings=d.get('ratings')
            if not isinstance(ratings,list):self.send(400,{'error':'평가 자료가 올바르지 않습니다.'});return
            try:
                with connect() as c:
                    c.execute('BEGIN IMMEDIATE')
                    v=c.execute('SELECT * FROM voters WHERE id=?',(vid,)).fetchone();cl=c.execute('SELECT status FROM classes WHERE id=?',(v['class_id'],)).fetchone()
                    if v['submitted_at'] or cl['status']!='open':raise ValueError('이미 제출했거나 평가가 마감되었습니다.')
                    expected={r[0] for r in c.execute('SELECT id FROM teams WHERE class_id=? AND id<>?',(v['class_id'],v['team_id']))}
                    ids=[r.get('team_id') for r in ratings]
                    if len(ids)!=len(expected) or set(ids)!=expected:raise ValueError('본인 팀을 제외한 모든 팀을 평가해야 합니다.')
                    for r in ratings:
                        for key,maxval in CRITERIA.items():
                            val=r.get(key)
                            if type(val)!=int or val<0 or val>maxval or val%5:raise ValueError('평가점수는 5점 단위로 선택해주세요.')
                        c.execute('INSERT INTO ratings(voter_id,target_team_id,social,profit,feasible) VALUES(?,?,?,?,?)',(vid,r['team_id'],r['social'],r['profit'],r['feasible']))
                    c.execute('UPDATE voters SET submitted_at=datetime("now") WHERE id=?',(vid,))
                self.send(200,{'ok':True})
            except ValueError as e:self.send(409,{'error':str(e)})
            except sqlite3.IntegrityError:self.send(409,{'error':'중복 평가가 감지되었습니다.'})
            return
        if p.startswith('/api/admin/'):
            if not self.needadmin():return
            m=re.fullmatch(r'/api/admin/class/([1-8])/teams',p)
            if m:
                cid=int(m[1]);names=d.get('names')
                if not isinstance(names,list) or not 2<=len(names)<=20 or any(not isinstance(n,str) or not n.strip() or len(n)>60 for n in names) or len(set(n.strip() for n in names))!=len(names):self.send(400,{'error':'중복 없이 2~20개 팀 이름을 입력하세요.'});return
                with connect() as c:
                    cl=c.execute('SELECT status FROM classes WHERE id=?',(cid,)).fetchone();cnt=c.execute('SELECT COUNT(*) FROM voters WHERE class_id=?',(cid,)).fetchone()[0]
                    if cl['status']!='draft' or cnt:self.send(409,{'error':'평가코드 발급 전, 준비 상태에서만 팀 구성을 변경할 수 있습니다.'});return
                    c.execute('DELETE FROM teams WHERE class_id=?',(cid,))
                    for name in names:c.execute('INSERT INTO teams(class_id,name) VALUES(?,?)',(cid,name.strip()))
                self.send(200,{'ok':True});return
            m=re.fullmatch(r'/api/admin/class/([1-8])/codes',p)
            if m:
                cid=int(m[1]);tid=d.get('team_id');count=d.get('count')
                if type(tid)!=int or type(count)!=int or not 1<=count<=100:self.send(400,{'error':'팀과 발급 인원(1~100)을 확인하세요.'});return
                with connect() as c:
                    cl=c.execute('SELECT status FROM classes WHERE id=?',(cid,)).fetchone();team=c.execute('SELECT * FROM teams WHERE id=? AND class_id=?',(tid,cid)).fetchone()
                    if not team or cl['status']=='closed':self.send(409,{'error':'팀이 없거나 마감된 학급입니다.'});return
                    rows=[]
                    for _ in range(count):
                        code=newcode();c.execute('INSERT INTO voters(class_id,team_id,code_hash,code_hint) VALUES(?,?,?,?)',(cid,tid,hcode(code),code[-4:]));rows.append({'class':f'{cid}반','team':team['name'],'code':code})
                self.send(200,{'codes':rows,'warning':'코드는 이 응답에서만 제공됩니다. 즉시 다운로드하고 안전하게 배부하세요.'});return
            m=re.fullmatch(r'/api/admin/class/([1-8])/status',p)
            if m:
                cid=int(m[1]);status=d.get('status')
                if status not in ('draft','open','closed'):self.send(400,{'error':'상태가 올바르지 않습니다.'});return
                with connect() as c:
                    teams=c.execute('SELECT COUNT(*) FROM teams WHERE class_id=?',(cid,)).fetchone()[0];voters=c.execute('SELECT COUNT(*) FROM voters WHERE class_id=?',(cid,)).fetchone()[0]
                    if status=='open' and (teams<2 or voters<1):self.send(409,{'error':'팀과 평가코드를 먼저 등록하세요.'});return
                    c.execute('UPDATE classes SET status=? WHERE id=?',(status,cid))
                self.send(200,{'ok':True});return
            m=re.fullmatch(r'/api/admin/class/([1-8])/visibility',p)
            if m:
                with connect() as c:c.execute('UPDATE classes SET show_results=? WHERE id=?',(1 if d.get('show_results') is True else 0,int(m[1])))
                self.send(200,{'ok':True});return
        self.send(404,{'error':'요청을 찾을 수 없습니다.'})

if __name__=='__main__':
    if not ADMIN_PASSWORD or len(ADMIN_PASSWORD)<12:raise SystemExit('IR_ADMIN_PASSWORD 환경변수에 12자 이상의 관리자 비밀번호를 설정하세요.')
    init();print(f'학생: {BASE_URL}/c/1 | 관리자: {BASE_URL}/admin',flush=True)
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
