import os, json, csv, io, socket, ipaddress, hashlib, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests, phonenumbers, dns.resolver
from phonenumbers import geocoder, carrier, timezone as ptimezone

app=Flask(__name__)
app.config['SECRET_KEY']=os.environ.get('SECRET_KEY', secrets.token_hex(32))
db_url=os.environ.get('DATABASE_URL','sqlite:///faizan_osint.db').replace('postgres://','postgresql+psycopg://')
app.config['SQLALCHEMY_DATABASE_URI']=db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)
 
class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False); password_hash=db.Column(db.String(255),nullable=False); role=db.Column(db.String(30),default='investigator'); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class Case(db.Model):
 id=db.Column(db.Integer,primary_key=True); title=db.Column(db.String(180),nullable=False); created_by=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False); status=db.Column(db.String(30),default='open'); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class Evidence(db.Model):
 id=db.Column(db.Integer,primary_key=True); case_id=db.Column(db.Integer,db.ForeignKey('case.id'),nullable=False); kind=db.Column(db.String(40),nullable=False); query=db.Column(db.String(255),nullable=False); result_json=db.Column(db.Text,nullable=False); source_note=db.Column(db.String(500),default='Public/authorized source'); sha256=db.Column(db.String(64),nullable=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,nullable=True); action=db.Column(db.String(100),nullable=False); detail=db.Column(db.String(500),default=''); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))

PLATFORMS={'GitHub':'https://github.com/{u}','Reddit':'https://www.reddit.com/user/{u}/','X':'https://x.com/{u}','Instagram':'https://www.instagram.com/{u}/','TikTok':'https://www.tiktok.com/@{u}','LinkedIn':'https://www.linkedin.com/in/{u}/'}
def ts(): return datetime.now(timezone.utc).isoformat()
def audit(action,detail=''):
 db.session.add(Audit(user_id=session.get('uid'),action=action,detail=detail[:500])); db.session.commit()
def login_required(f):
 @wraps(f)
 def w(*a,**k):
  if 'uid' not in session:return jsonify(error='Authentication required'),401
  return f(*a,**k)
 return w
def username(v):
    u = v.strip().lstrip('@')
    r = {'input': u, 'timestamp': ts(), 'profiles': []}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    for p, t in PLATFORMS.items():
        url = t.format(u=u)
        try:
            x = requests.get(url, timeout=6, allow_redirects=True, headers=headers)
            
            # Advanced validation to avoid false positives (200 OK custom error pages)
            is_reachable = False
            if 200 <= x.status_code < 400:
                body_text = x.text.lower()
                # Common negative keywords for deleted/non-existent profiles
                not_found_keywords = [
                    'not found', 'doesn\'t exist', 'page not available', 
                    'account has been suspended', 'user doesn\'t exist',
                    'this page isn\'t available', 'looking for something?'
                ]
                if not any(kw in body_text for kw in not_found_keywords):
                    is_reachable = True
            
            r['profiles'].append({
                'platform': p, 
                'url': url, 
                'status': x.status_code, 
                'reachable': is_reachable
            })
        except Exception:
            r['profiles'].append({'platform': p, 'url': url, 'status': 'network_error', 'reachable': False})
            
    r['limitation'] = 'Verified via content-filtering to reduce false positives; match is a lead, not proof.'
    return r
 
def phone(v):
 r={'input':v,'timestamp':ts()}
 try:
  p=phonenumbers.parse(v,'PK');r.update(valid=phonenumbers.is_valid_number(p),possible=phonenumbers.is_possible_number(p),e164=phonenumbers.format_number(p,phonenumbers.PhoneNumberFormat.E164),international=phonenumbers.format_number(p,phonenumbers.PhoneNumberFormat.INTERNATIONAL),country_code=p.country_code,region=geocoder.description_for_number(p,'en'),carrier=carrier.name_for_number(p,'en'),timezones=list(ptimezone.time_zones_for_number(p)))
 except Exception as e:r['error']=str(e)
 r['limitation']='Metadata only; no live GPS or private subscriber records.';return r
def ipinfo(v):
 r={'input':v,'timestamp':ts()}
 try:
  x=ipaddress.ip_address(v);r['parsed']={'version':x.version,'private':x.is_private,'loopback':x.is_loopback}
 except Exception as e:r['error']=str(e);return r
 if not r['parsed']['private'] and not r['parsed']['loopback']:
  try:r['geo']=requests.get('http://ip-api.com/json/'+v,params={'fields':'status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query'},timeout=8).json()
  except Exception as e:r['error']=type(e).__name__
 r['limitation']='IP geolocation is approximate, not live device location.';return r
def domain(v):
 v=v.replace('https://','').replace('http://','').split('/')[0];r={'input':v,'timestamp':ts(),'dns':{}}
 for typ in ('A','AAAA','MX','NS','TXT','CNAME'):
  try:r['dns'][typ]=sorted({str(x) for x in dns.resolver.resolve(v,typ,lifetime=4)})
  except Exception:r['dns'][typ]=[]
 try:r['addresses']=socket.gethostbyname_ex(v)[2]
 except Exception:r['addresses']=[]
 try:
  import whois;w=whois.whois(v);r['whois']={'registrar':w.registrar,'creation_date':str(w.creation_date),'expiration_date':str(w.expiration_date),'name_servers':list(w.name_servers or [])}
 except Exception:r['whois']='Unavailable'
 return r

def investigate(k,v):return {'phone':phone,'ip':ipinfo,'domain':domain,'username':username}[k](v)

@app.before_request
def init():
 if not hasattr(app,'_db_ready'):
  with app.app_context():
   db.create_all()
   if not User.query.filter_by(username='admin').first():
    u=User(username='admin',password_hash=generate_password_hash(os.environ.get('ADMIN_PASSWORD','change-me-now')),role='admin');db.session.add(u);db.session.commit()
  app._db_ready=True
@app.get('/')
def home():return render_template('index.html',user=session.get('user'))
@app.post('/api/login')
def login():
 d=request.get_json(silent=True) or {};u=User.query.filter_by(username=d.get('username','')).first()
 if not u or not check_password_hash(u.password_hash,d.get('password','')):return jsonify(error='Invalid credentials'),401
 session['uid']=u.id;session['user']=u.username;audit('login','Successful login');return jsonify(ok=True)
@app.post('/api/logout')
def logout():audit('logout');session.clear();return jsonify(ok=True)
@app.post('/api/cases')
@login_required
def create_case():
 d=request.get_json(silent=True) or {};title=str(d.get('title','')).strip()
 if not title:return jsonify(error='title required'),400
 c=Case(title=title,created_by=session['uid']);db.session.add(c);db.session.commit();audit('case_create',f'case={c.id}');return jsonify(id=c.id,title=c.title,status=c.status)
@app.get('/api/cases')
@login_required
def cases():return jsonify([{'id':c.id,'title':c.title,'status':c.status,'created_at':c.created_at.isoformat()} for c in Case.query.order_by(Case.id.desc()).all()])
@app.post('/api/investigate')
@login_required
def api():
 d=request.get_json(silent=True) or {};k=str(d.get('type',''));v=str(d.get('query','')).strip();case_id=d.get('case_id')
 if k not in ('phone','ip','domain','username') or not v:return jsonify(error='Supported types: phone, ip, domain, username'),400
 if case_id and not Case.query.get(case_id):return jsonify(error='case not found'),404
 result=investigate(k,v);raw=json.dumps(result,ensure_ascii=False,sort_keys=True);ev=None
 if case_id:
  ev=Evidence(case_id=case_id,kind=k,query=v,result_json=raw,sha256=hashlib.sha256(raw.encode()).hexdigest());db.session.add(ev);db.session.commit();audit('evidence_add',f'case={case_id}; evidence={ev.id}')
 return jsonify({'timestamp':ts(),'type':k,'query':v,'case_id':case_id,'result':result,'evidence_id':ev.id if ev else None})
@app.get('/export.csv')
@login_required
def export():
 out=io.StringIO();w=csv.writer(out);w.writerow(['evidence_id','case_id','timestamp','type','query','sha256'])
 for e in Evidence.query.order_by(Evidence.id.desc()).all():w.writerow([e.id,e.case_id,e.created_at.isoformat(),e.kind,e.query,e.sha256])
 audit('export_csv');return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=evidence_index.csv'})
@app.get('/health')
def health():return jsonify(status='ok',version='4.0')
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT','10000')))
