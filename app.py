import os, sqlite3, zipfile, subprocess, signal, shutil, psutil, time, datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO

# Global process tracker
running_procs = {}
start_times   = {}

socketio = SocketIO()

def get_db():
    db_path = os.path.join(os.getcwd(), 'storage/nehost.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _is_valid_sqlite(path):
    if not os.path.exists(path):  return True
    if os.path.getsize(path) == 0: return False
    try:
        with open(path, 'rb') as f:
            return f.read(16) == b'SQLite format 3\x00'
    except: return False

def init_db():
    db_path = os.path.join(os.getcwd(), 'storage/nehost.db')
    os.makedirs('storage', exist_ok=True)
    os.makedirs(os.path.join(os.getcwd(), 'storage/instances'), exist_ok=True)
    if not _is_valid_sqlite(db_path):
        print('[init_db] Corrupted DB — removing and rebuilding.')
        os.remove(db_path)

    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fname TEXT DEFAULT '', lname TEXT DEFAULT '', username TEXT DEFAULT '',
        email TEXT, password TEXT,
        pfp TEXT DEFAULT 'default.png',
        role TEXT DEFAULT 'free',
        status TEXT DEFAULT 'active',
        server_limit INTEGER DEFAULT 1,
        notifications TEXT DEFAULT ''
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, name TEXT, folder TEXT,
        status TEXT DEFAULT 'Offline', startup TEXT DEFAULT 'main.py',
        pid INTEGER, server_status TEXT DEFAULT 'active'
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, subject TEXT, message TEXT,
        status TEXT DEFAULT 'open', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS admin_settings (
        id INTEGER PRIMARY KEY,
        username TEXT, password TEXT,
        popup_title TEXT DEFAULT '', popup_msg TEXT DEFAULT '',
        popup_img TEXT DEFAULT '', show_popup INTEGER DEFAULT 0
    )''')
    if not db.execute('SELECT * FROM admin_settings WHERE id=1').fetchone():
        db.execute('INSERT INTO admin_settings (id, username, password) VALUES (1, "mafuu-admin", "mafuu-admin")')
    db.commit()
    db.close()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY']    = os.environ.get('SECRET_KEY', 'nehost_ultra_pro_max_99')
    app.config['BASE_STORAGE']  = os.path.join(os.getcwd(), 'storage/instances')
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')
    os.makedirs(app.config['BASE_STORAGE'],  exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    socketio.init_app(app)

    def get_precise_uptime(ts):
        if not ts: return "Offline"
        diff = int(time.time() - ts)
        months, r = divmod(diff, 2592000)
        days,   r = divmod(r, 86400)
        hours,  r = divmod(r, 3600)
        minutes,_ = divmod(r, 60)
        parts = []
        if months: parts.append(f"{months}mo")
        if days:   parts.append(f"{days}d")
        if hours:  parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return " ".join(parts)

    # ─── Public ───────────────────────────────────────────────────
    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            fname    = request.form.get('fname','').strip()
            lname    = request.form.get('lname','').strip()
            username = request.form.get('username','').strip()
            email    = request.form.get('email','').strip()
            pwd      = request.form.get('password','')
            cpwd     = request.form.get('confirm_password','')
            pfp      = request.files.get('pfp')

            if not all([fname, username, email, pwd]):
                return jsonify({'status':'error','msg':'All fields are required.'}), 400
            if pwd != cpwd:
                return jsonify({'status':'error','msg':'Passwords do not match!'}), 400

            db = get_db()
            if db.execute('SELECT id FROM users WHERE email=? OR username=?',(email,username)).fetchone():
                db.close()
                return jsonify({'status':'error','msg':'Email or Username already taken!'}), 400

            pfp_name = 'default.png'
            if pfp and pfp.filename:
                pfp_name = secure_filename(pfp.filename)
                pfp.save(os.path.join(app.config['UPLOAD_FOLDER'], pfp_name))

            db.execute(
                'INSERT INTO users (fname,lname,username,email,password,pfp,server_limit,role,status) VALUES (?,?,?,?,?,?,?,?,?)',
                (fname, lname, username, email, generate_password_hash(pwd), pfp_name, 10, 'free', 'active')
            )
            db.commit(); db.close()
            return jsonify({'status':'success','url':url_for('login')})
        return render_template('web/signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            ident = request.form.get('email','').strip()
            pwd   = request.form.get('password','')
            db    = get_db()
            user  = db.execute('SELECT * FROM users WHERE email=? OR username=?',(ident,ident)).fetchone()
            db.close()
            if user and check_password_hash(user['password'], pwd):
                if user['status'] == 'banned':
                    return jsonify({'status':'banned','msg':'Your account has been suspended!'}), 403
                session['user_id'] = user['id']
                return jsonify({'status':'success','url':url_for('dashboard')}), 200
            return jsonify({'status':'error','msg':'Invalid credentials!'}), 401
        return render_template('web/login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        return redirect(url_for('login'))

    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session: return redirect(url_for('login'))
        db   = get_db()
        user = db.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
        db.close()
        if not user or user['status'] != 'active':
            session.clear()
            return redirect(url_for('login'))
        return render_template('web/dashboard.html', user=user)

    @app.route('/profile/update', methods=['POST'])
    def update_profile():
        if 'user_id' not in session: return jsonify({'status':'error'})
        uid   = session['user_id']
        fname = request.form.get('fname','').strip()
        lname = request.form.get('lname','').strip()
        pwd   = request.form.get('password','')
        pfp   = request.files.get('pfp')
        db    = get_db()
        if pfp and pfp.filename:
            pfp_name = secure_filename(pfp.filename)
            pfp.save(os.path.join(app.config['UPLOAD_FOLDER'], pfp_name))
            db.execute('UPDATE users SET pfp=? WHERE id=?',(pfp_name,uid))
        if pwd:
            db.execute('UPDATE users SET fname=?,lname=?,password=? WHERE id=?',(fname,lname,generate_password_hash(pwd),uid))
        else:
            db.execute('UPDATE users SET fname=?,lname=? WHERE id=?',(fname,lname,uid))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/ticket/create', methods=['POST'])
    def create_ticket():
        if 'user_id' not in session: return jsonify({'status':'error'})
        d = request.json or {}
        db = get_db()
        db.execute('INSERT INTO tickets (user_id,subject,message) VALUES (?,?,?)',
                   (session['user_id'], d.get('subject',''), d.get('message','')))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/api/announcement')
    def get_announcement():
        db   = get_db()
        conf = db.execute('SELECT popup_title,popup_msg,popup_img,show_popup FROM admin_settings WHERE id=1').fetchone()
        db.close()
        if not conf:
            return jsonify({'popup_title':'','popup_msg':'','popup_img':'','show_popup':0})
        return jsonify(dict(conf))

    # ─── Servers ──────────────────────────────────────────────────
    @app.route('/servers')
    def list_servers():
        if 'user_id' not in session: return jsonify({'servers':[]})
        db   = get_db()
        rows = db.execute('SELECT * FROM servers WHERE user_id=?',(session['user_id'],)).fetchall()
        db.close()
        srvs = []
        for r in rows:
            f, saved_pid = r['folder'], r['pid']
            online = False
            if saved_pid and psutil.pid_exists(saved_pid):
                try:
                    p = psutil.Process(saved_pid)
                    if p.is_running() and p.status() != psutil.STATUS_ZOMBIE: online = True
                except: pass
            elif f in running_procs and running_procs[f].poll() is None: online = True
            uptime = get_precise_uptime(start_times.get(f)) if (online and f in start_times) else ("Online" if online else "Offline")
            cpu, ram = "0%", "0MB"
            if online:
                try:
                    pid_  = running_procs[f].pid if f in running_procs else saved_pid
                    proc_ = psutil.Process(pid_)
                    cpu   = f"{proc_.cpu_percent(interval=None)}%"
                    ram   = f"{proc_.memory_info().rss/(1024*1024):.1f}MB"
                except: pass
            srvs.append({'name':r['name'],'folder':f,'online':online,'startup':r['startup'],
                         'uptime':uptime,'cpu':cpu,'ram':ram,'status':r['server_status']})
        return jsonify({'servers':srvs})

    @app.route('/add', methods=['POST'])
    def add_srv():
        if 'user_id' not in session: return jsonify({'status':'error','msg':'Not logged in'})
        db    = get_db()
        user  = db.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
        count = db.execute('SELECT COUNT(*) as c FROM servers WHERE user_id=?',(session['user_id'],)).fetchone()['c']
        if user['role'] != 'admin' and count >= user['server_limit']:
            db.close()
            return jsonify({'status':'error','msg':f"Limit reached! Max: {user['server_limit']}"})
        name = (request.json or {}).get('name','').strip()
        if not name:
            db.close()
            return jsonify({'status':'error','msg':'Server name cannot be empty'})
        folder = secure_filename(name).lower() + "_" + str(int(time.time()))
        db.execute('INSERT INTO servers (user_id,name,folder,status,startup) VALUES (?,?,?,?,?)',
                   (session['user_id'],name,folder,'Offline','main.py'))
        db.commit(); db.close()
        os.makedirs(os.path.join(app.config['BASE_STORAGE'],folder), exist_ok=True)
        # Return folder so callers (e.g. deployZips) can use it directly
        return jsonify({'status':'success','folder':folder})

    @app.route('/server/action/<folder>/<act>', methods=['POST'])
    def server_action(folder, act):
        db       = get_db()
        srv_data = db.execute('SELECT server_status FROM servers WHERE folder=?',(folder,)).fetchone()
        if srv_data and srv_data['server_status'] == 'suspended':
            db.close()
            return jsonify({'status':'error','msg':'This server is suspended by Admin.'})
        path    = os.path.join(app.config['BASE_STORAGE'], folder)
        logpath = os.path.join(path, 'console.log')
        now     = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if act == 'install':
            req = os.path.join(path, 'requirements.txt')
            if os.path.exists(req):
                flog = open(logpath, 'a')
                flog.write(f"\n[{now}] 📦 Installing packages...\n")
                flog.flush()
                subprocess.Popen(['pip','install','-r','requirements.txt'], cwd=path, stdout=flog, stderr=flog)
                db.close()
                return jsonify({'status':'installing'})
            db.close()
            return jsonify({'status':'error','msg':'requirements.txt not found'})

        if act in ['start','restart']:
            row     = db.execute('SELECT pid,startup FROM servers WHERE folder=?',(folder,)).fetchone()
            old_pid = row['pid'] if row else None
            if folder in running_procs or (old_pid and psutil.pid_exists(old_pid)):
                try:
                    t = running_procs[folder].pid if folder in running_procs else old_pid
                    os.killpg(os.getpgid(t), signal.SIGKILL)
                except: pass
            startup = row['startup'] if row and row['startup'] else 'main.py'
            flog = open(logpath, 'a')
            flog.write(f"\n[{now}] 🚀 Instance {act.upper()}ED\n")
            proc = subprocess.Popen(['python3', startup], cwd=path, stdout=flog, stderr=flog, preexec_fn=os.setsid)
            running_procs[folder] = proc
            start_times[folder]   = time.time()
            db.execute('UPDATE servers SET pid=? WHERE folder=?',(proc.pid,folder))
            db.commit(); db.close()
            return jsonify({'status':'started'})

        if act == 'stop':
            row   = db.execute('SELECT pid FROM servers WHERE folder=?',(folder,)).fetchone()
            t_pid = running_procs[folder].pid if folder in running_procs else (row['pid'] if row else None)
            if t_pid:
                try: os.killpg(os.getpgid(t_pid), signal.SIGKILL)
                except: pass
            running_procs.pop(folder, None)
            start_times.pop(folder, None)
            db.execute('UPDATE servers SET pid=NULL WHERE folder=?',(folder,))
            db.commit(); db.close()
            with open(logpath,'a') as f: f.write(f"\n[{now}] 🛑 Instance STOPPED\n")
            return jsonify({'status':'stopped'})
        db.close()
        return jsonify({'status':'ok'})

    @app.route('/server/log/<folder>')
    def server_log(folder):
        if 'user_id' not in session: return jsonify({'log':'Unauthorized'})
        path = os.path.join(app.config['BASE_STORAGE'], folder, 'console.log')
        if os.path.exists(path):
            with open(path,'r',errors='ignore') as f:
                return jsonify({'log': f.read()[-8000:]})
        return jsonify({'log':'No logs yet...'})

    @app.route('/server/set-startup/<folder>', methods=['POST'])
    def set_startup(folder):
        if 'user_id' not in session: return jsonify({'status':'error'})
        fname = (request.json or {}).get('file','').strip()
        if not fname: return jsonify({'status':'error','msg':'Filename cannot be empty'})
        db = get_db()
        db.execute('UPDATE servers SET startup=? WHERE folder=?',(fname,folder))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    # FIX: was missing entirely — dashboard console input calls this
    @app.route('/server/command/<folder>', methods=['POST'])
    def server_command(folder):
        if 'user_id' not in session: return jsonify({'status':'error','msg':'Not logged in'})
        cmd  = (request.json or {}).get('command','').strip()
        if not cmd: return jsonify({'status':'error','msg':'No command provided'})
        srv_path = os.path.join(app.config['BASE_STORAGE'], folder)
        logpath  = os.path.join(srv_path, 'console.log')
        now      = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # If the bot process is live and has open stdin, pipe the command to it
        proc = running_procs.get(folder)
        if proc and proc.poll() is None and proc.stdin:
            try:
                proc.stdin.write(cmd + '\n')
                proc.stdin.flush()
                with open(logpath, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{now}] $ {cmd}\n")
                return jsonify({'status':'success','output':''})
            except Exception:
                pass  # Fall through to standalone shell execution

        # Run as a standalone shell command in the server directory
        try:
            result = subprocess.run(
                cmd, shell=True, cwd=srv_path,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=30, errors='replace'
            )
            output = result.stdout.strip() if result.stdout else ''
            with open(logpath, 'a', encoding='utf-8') as f:
                f.write(f"\n[{now}] $ {cmd}\n")
                if output:
                    f.write(output + '\n')
            return jsonify({'status':'success','output':output})
        except subprocess.TimeoutExpired:
            return jsonify({'status':'error','msg':'Command timed out (30s)'})
        except Exception as e:
            return jsonify({'status':'error','msg':str(e)})

    @app.route('/server/delete/<folder>', methods=['POST'])
    def delete_server(folder):
        if 'user_id' not in session: return jsonify({'status':'error','msg':'Not logged in'})
        db  = get_db()
        srv = db.execute('SELECT user_id,server_status,pid FROM servers WHERE folder=?',(folder,)).fetchone()
        if not srv:    db.close(); return jsonify({'status':'error','msg':'Server not found'})
        if srv['user_id'] != session['user_id']: db.close(); return jsonify({'status':'error','msg':'Access denied'})
        if srv['server_status'] == 'suspended':  db.close(); return jsonify({'status':'error','msg':'Suspended servers cannot be deleted!'})
        t_pid = running_procs[folder].pid if folder in running_procs else srv['pid']
        if t_pid:
            try: os.killpg(os.getpgid(t_pid), signal.SIGKILL)
            except: pass
        running_procs.pop(folder, None)
        start_times.pop(folder, None)
        db.execute('DELETE FROM servers WHERE folder=?',(folder,))
        db.commit(); db.close()
        path = os.path.join(app.config['BASE_STORAGE'], folder)
        if os.path.exists(path): shutil.rmtree(path)
        return jsonify({'status':'deleted'})

    # ─── File Manager ─────────────────────────────────────────────
    @app.route('/files/list/<folder>')
    def flist(folder):
        sub   = request.args.get('path','')
        full  = os.path.normpath(os.path.join(app.config['BASE_STORAGE'],folder,sub))
        if not full.startswith(app.config['BASE_STORAGE']): return jsonify([])
        if not os.path.exists(full): return jsonify([])
        items = []
        for f in sorted(os.listdir(full)):
            if f == 'console.log': continue
            p = os.path.join(full, f)
            items.append({'name':f,'is_dir':os.path.isdir(p),'is_zip':f.lower().endswith('.zip')})
        return jsonify(items)

    # FIX: was named /files/content/<folder>/<n> — URL param `n` didn't match function arg `name` → 500
    # FIX: dashboard calls /files/read/<folder>?name=...&path=... — backend had different URL
    @app.route('/files/read/<folder>')
    def fread(folder):
        name = request.args.get('name','')
        sub  = request.args.get('path','')
        p    = os.path.normpath(os.path.join(app.config['BASE_STORAGE'],folder,sub,name))
        if not p.startswith(app.config['BASE_STORAGE']):
            return jsonify({'content':'Access denied'})
        try:
            with open(p,'r',encoding='utf-8',errors='ignore') as f:
                return jsonify({'content':f.read()})
        except Exception as e:
            return jsonify({'content':f'Error: {e}'})

    # FIX: was /files/save/<folder>/<n> — dashboard sends JSON body with name field, no URL param
    @app.route('/files/save/<folder>', methods=['POST'])
    def fsave(folder):
        d    = request.json or {}
        name = d.get('name','')
        sub  = d.get('path','')
        p    = os.path.normpath(os.path.join(app.config['BASE_STORAGE'],folder,sub,name))
        if not p.startswith(app.config['BASE_STORAGE']):
            return jsonify({'status':'error','msg':'Access denied'})
        try:
            with open(p,'w',encoding='utf-8') as f: f.write(d.get('content',''))
            return jsonify({'status':'saved'})
        except Exception as e:
            return jsonify({'status':'error','msg':str(e)})

    @app.route('/files/delete-bulk/<folder>', methods=['POST'])
    def delete_bulk(folder):
        d     = request.json or {}
        sub   = d.get('path','')
        names = d.get('names',[])
        base  = os.path.join(app.config['BASE_STORAGE'],folder,sub)
        if not names: names = [f for f in os.listdir(base) if f != 'console.log']
        for name in names:
            if name == 'console.log': continue
            p = os.path.join(base, name)
            try:
                if os.path.isdir(p): shutil.rmtree(p)
                elif os.path.exists(p): os.remove(p)
            except: pass
        return jsonify({'status':'ok'})

    @app.route('/files/create-file/<folder>', methods=['POST'])
    def create_file_route(folder):
        d = request.json or {}
        p = os.path.join(app.config['BASE_STORAGE'],folder,d.get('path',''),secure_filename(d.get('name','newfile.py')))
        with open(p,'w') as f: f.write('')
        return jsonify({'status':'success'})

    @app.route('/files/create-folder/<folder>', methods=['POST'])
    def create_folder_route(folder):
        d = request.json or {}
        p = os.path.join(app.config['BASE_STORAGE'],folder,d.get('path',''),secure_filename(d.get('name','new_folder')))
        os.makedirs(p, exist_ok=True)
        return jsonify({'status':'success'})

    @app.route('/files/upload/<folder>', methods=['POST'])
    def upload_file(folder):
        sub  = request.form.get('path','')
        file = request.files.get('file')
        if not file: return jsonify({'status':'error','msg':'No file'})
        
        dest = os.path.join(app.config['BASE_STORAGE'],folder,sub)
        os.makedirs(dest, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(dest, filename)
        
        # Save the file
        try:
            file.save(filepath)
            # Verify file was written
            if not os.path.exists(filepath):
                return jsonify({'status':'error','msg':f'File {filename} was not saved'})
            
            # Log to console
            logpath = os.path.join(dest, 'console.log')
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            try:
                with open(logpath, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{now}] 📁 Uploaded: {filename} ({os.path.getsize(filepath)} bytes)\n")
            except: pass
            
            return jsonify({'status':'success','filename':filename})
        except Exception as e:
            return jsonify({'status':'error','msg':f'Upload failed: {str(e)}'})

    @app.route('/files/rename/<folder>', methods=['POST'])
    def rename_file(folder):
        d    = request.json or {}
        base = os.path.join(app.config['BASE_STORAGE'],folder,d.get('path',''))
        try:
            os.rename(os.path.join(base,d['old']), os.path.join(base,d['new']))
            return jsonify({'status':'success'})
        except Exception as e:
            return jsonify({'status':'error','msg':str(e)})

    # FIX: was /files/download/<folder>/<n> but function arg was `name` — mismatch → 500
    @app.route('/files/download/<folder>/<name>')
    def download_file(folder, name):
        sub = request.args.get('path','')
        p   = os.path.normpath(os.path.join(app.config['BASE_STORAGE'],folder,sub,name))
        if not p.startswith(app.config['BASE_STORAGE']): return "Access Denied", 403
        if not os.path.exists(p): return "Not found", 404
        return send_file(p, as_attachment=True)

    @app.route('/files/zip-bulk/<folder>', methods=['POST'])
    def zip_bulk(folder):
        d     = request.json or {}
        names = d.get('names',[])
        sub   = d.get('path','')
        base  = os.path.join(app.config['BASE_STORAGE'],folder,sub)
        if not names: names = [f for f in os.listdir(base) if f != 'console.log']
        zname = f"archive_{int(time.time())}.zip"
        zpath = os.path.join(base, zname)
        with zipfile.ZipFile(zpath,'w') as z:
            for n in names:
                p = os.path.join(base,n)
                if n == zname: continue
                if os.path.isdir(p):
                    for root,_,files in os.walk(p):
                        for file in files:
                            fp = os.path.join(root,file)
                            z.write(fp, os.path.relpath(fp,base))
                elif os.path.exists(p): z.write(p,n)
        return jsonify({'status':'success','zip':zname})

    @app.route('/files/unzip/<folder>', methods=['POST'])
    def unzip_file(folder):
        d    = request.json or {}
        sub  = d.get('path','')
        base = os.path.join(app.config['BASE_STORAGE'],folder,sub)
        zname = d.get('name','')
        zpath = os.path.join(base, zname)
        
        # Debug logging
        logpath = os.path.join(base, 'console.log')
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if file exists
        if not os.path.exists(zpath):
            msg = f'ZIP file not found: {zpath}'
            try:
                with open(logpath, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{now}] ✗ UNZIP FAILED: {msg}\n")
                    f.write(f"  Files in directory: {os.listdir(base)}\n")
            except: pass
            return jsonify({'status':'error','msg':msg})
        
        # Check if it's a valid ZIP
        if not zipfile.is_zipfile(zpath):
            msg = f'Not a valid ZIP file: {zname}'
            try:
                with open(logpath, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{now}] ✗ UNZIP FAILED: {msg}\n")
            except: pass
            return jsonify({'status':'error','msg':msg})
        
        # Extract the ZIP
        try:
            with open(logpath, 'a', encoding='utf-8') as f:
                f.write(f"\n[{now}] 📂 Extracting {zname}...\n")
            
            with zipfile.ZipFile(zpath,'r') as z:
                z.extractall(base)
            
            # Delete the ZIP file after successful extraction
            os.remove(zpath)
            
            with open(logpath, 'a', encoding='utf-8') as f:
                f.write(f"[{now}] ✓ Successfully extracted and removed {zname}\n")
                f.write(f"  Extracted files: {os.listdir(base)}\n")
            
            return jsonify({'status':'success','msg':f'Extracted {zname}'})
        except Exception as e:
            msg = f'Extraction error: {str(e)}'
            try:
                with open(logpath, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{now}] ✗ UNZIP ERROR: {msg}\n")
            except: pass
            return jsonify({'status':'error','msg':msg})

    @app.route('/server/detect-startup/<folder>')
    def detect_startup(folder):
        """Scan the server folder for a Python entry point and return its relative path."""
        base = os.path.join(app.config['BASE_STORAGE'], folder)
        priority = ['main.py', 'app.py', 'bot.py', 'run.py', 'start.py', 'index.py']

        # 1) Check root level first
        for name in priority:
            if os.path.isfile(os.path.join(base, name)):
                return jsonify({'status':'found', 'startup': name})

        # 2) Scan one level deep (handles ZIPs that extract into a subfolder)
        try:
            for entry in os.listdir(base):
                sub = os.path.join(base, entry)
                if os.path.isdir(sub):
                    for name in priority:
                        if os.path.isfile(os.path.join(sub, name)):
                            return jsonify({'status':'found', 'startup': f"{entry}/{name}"})
        except Exception:
            pass

        # 3) Last resort: any .py file at root
        try:
            for f in os.listdir(base):
                if f.endswith('.py') and f != 'console.log':
                    return jsonify({'status':'found', 'startup': f})
        except Exception:
            pass

        return jsonify({'status':'not_found', 'startup': 'main.py'})

    @app.route('/server/sync-install/<folder>', methods=['POST'])
    def sync_install(folder):
        """Run pip install synchronously and return when done — used by auto-deploy."""
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'msg': 'Not logged in'})
        path    = os.path.join(app.config['BASE_STORAGE'], folder)
        req     = os.path.join(path, 'requirements.txt')
        logpath = os.path.join(path, 'console.log')
        now     = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not os.path.isfile(req):
            return jsonify({'status': 'skipped', 'msg': 'No requirements.txt'})

        try:
            with open(logpath, 'a', encoding='utf-8') as flog:
                flog.write(f"\n[{now}] 📦 Auto-installing packages...\n")
            result = subprocess.run(
                ['pip', 'install', '-r', 'requirements.txt'],
                cwd=path, capture_output=True, text=True, timeout=120
            )
            output = (result.stdout + result.stderr).strip()
            with open(logpath, 'a', encoding='utf-8') as flog:
                flog.write(output + '\n')
            return jsonify({'status': 'success', 'output': output})
        except subprocess.TimeoutExpired:
            return jsonify({'status': 'error', 'msg': 'pip install timed out (120s)'})
        except Exception as e:
            return jsonify({'status': 'error', 'msg': str(e)})

    # ─── Admin ────────────────────────────────────────────────────
    @app.route('/admin-login', methods=['GET','POST'])
    def admin_login():
        if request.method == 'POST':
            user  = request.form.get('username','')
            pwd   = request.form.get('password','')
            db    = get_db()
            admin = db.execute('SELECT * FROM admin_settings WHERE username=? AND password=?',(user,pwd)).fetchone()
            db.close()
            if admin:
                session['admin_logged'] = True
                return redirect(url_for('admin_panel'))
        return render_template('web/admin_login.html')

    @app.route('/admin/panel')
    def admin_panel():
        if not session.get('admin_logged'): return redirect(url_for('admin_login'))
        return render_template('web/admin_panel.html')

    # FIX: added missing admin logout route
    @app.route('/admin/logout')
    def admin_logout():
        session.pop('admin_logged', None)
        return redirect(url_for('admin_login'))

    @app.route('/admin/stats')
    def admin_stats():
        if not session.get('admin_logged'): return jsonify({}), 403
        db        = get_db()
        users     = db.execute('SELECT * FROM users').fetchall()
        user_list = []
        for u in users:
            srvs = db.execute('SELECT * FROM servers WHERE user_id=?',(u['id'],)).fetchall()
            act  = 0
            for s in srvs:
                on = False
                if s['pid'] and psutil.pid_exists(s['pid']):
                    try:
                        proc = psutil.Process(s['pid'])
                        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE: on = True
                    except: pass
                elif s['folder'] in running_procs and running_procs[s['folder']].poll() is None: on = True
                if on: act += 1
            user_list.append({'id':u['id'],'fname':u['fname'],'email':u['email'],
                              'srv_count':len(srvs),'active_srvs':act,'status':u['status'],
                              'role':u['role'],'server_limit':u['server_limit']})
        db.close()
        return jsonify({'users':user_list,'sys_cpu':f"{psutil.cpu_percent()}%",'sys_ram':f"{psutil.virtual_memory().percent}%"})

    @app.route('/admin/user/update', methods=['POST'])
    def update_user():
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        d  = request.json or {}
        db = get_db()
        db.execute('UPDATE users SET role=?,status=?,server_limit=? WHERE id=?',
                   (d.get('role','free'),d.get('status','active'),d.get('limit',1),d['user_id']))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/admin/set-popup', methods=['POST'])
    def set_popup():
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        title = request.form.get('title','')
        msg   = request.form.get('msg','')
        show  = request.form.get('show','false')
        img   = request.files.get('image')
        db    = get_db()
        old   = db.execute('SELECT popup_img FROM admin_settings WHERE id=1').fetchone()
        iname = old['popup_img'] if old else ''
        if img and img.filename:
            iname = secure_filename(img.filename)
            img.save(os.path.join(app.config['UPLOAD_FOLDER'], iname))
        db.execute('UPDATE admin_settings SET popup_title=?,popup_msg=?,popup_img=?,show_popup=? WHERE id=1',
                   (title,msg,iname,1 if show=='true' else 0))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/admin/send-warning', methods=['POST'])
    def send_warning():
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        d = request.json or {}
        db = get_db()
        db.execute('UPDATE users SET notifications=? WHERE id=?',(d.get('message',''),d['user_id']))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/admin/login-as/<int:uid>')
    def login_as(uid):
        if not session.get('admin_logged'): return redirect(url_for('admin_login'))
        session['user_id'] = uid
        return redirect(url_for('dashboard'))

    @app.route('/admin/manage-user/<int:uid>')
    def admin_manage_user_servers(uid):
        if not session.get('admin_logged'): return redirect(url_for('admin_login'))
        db      = get_db()
        user    = db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        rows    = db.execute('SELECT * FROM servers WHERE user_id=?',(uid,)).fetchall()
        db.close()
        servers = []
        for r in rows:
            f = r['folder']
            online = (f in running_procs and running_procs[f].poll() is None) or (r['pid'] and psutil.pid_exists(r['pid']))
            servers.append({'id':r['id'],'name':r['name'],'folder':f,'online':online,'status':r['server_status']})
        return render_template('web/admin_manage_user.html', user=user, servers=servers)

    @app.route('/admin/suspend-server/<int:sid>', methods=['POST'])
    def admin_suspend_server(sid):
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        status = (request.json or {}).get('status','active')
        db = get_db()
        db.execute('UPDATE servers SET server_status=? WHERE id=?',(status,sid))
        db.commit(); db.close()
        return jsonify({'status':'success'})

    @app.route('/admin/delete-server/<int:sid>', methods=['POST'])
    def admin_delete_server(sid):
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        db  = get_db()
        srv = db.execute('SELECT folder FROM servers WHERE id=?',(sid,)).fetchone()
        if not srv: db.close(); return jsonify({'status':'error','msg':'Not found'})
        folder = srv['folder']
        if folder in running_procs:
            try: os.killpg(os.getpgid(running_procs[folder].pid), signal.SIGKILL)
            except: pass
            del running_procs[folder]
        db.execute('DELETE FROM servers WHERE id=?',(sid,))
        db.commit()
        path = os.path.join(app.config['BASE_STORAGE'],folder)
        if os.path.exists(path): shutil.rmtree(path)
        db.close()
        return jsonify({'status':'deleted'})

    # FIX: was crashing with DB constraint — lname/username are NOT NULL
    @app.route('/admin/create-user', methods=['POST'])
    def admin_create_user():
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        d     = request.json or {}
        raw   = d.get('name','User').strip()
        parts = (raw+' ').split(' ',1)
        fname = parts[0] or 'User'
        lname = parts[1].strip() or ''
        email = d.get('email','').strip()
        uname = (email.split('@')[0] + str(int(time.time()))[-4:]).lower()
        hashed = generate_password_hash(d.get('pass','changeme123'))
        limit  = int(d.get('limit',1))
        db = get_db()
        try:
            db.execute('INSERT INTO users (fname,lname,username,email,password,server_limit) VALUES (?,?,?,?,?,?)',
                       (fname,lname,uname,email,hashed,limit))
            db.commit(); db.close()
            return jsonify({'status':'success'})
        except Exception as e:
            db.close()
            return jsonify({'status':'error','msg':str(e)})

    @app.route('/admin/delete-user/<int:uid>', methods=['POST'])
    def delete_user(uid):
        if not session.get('admin_logged'): return jsonify({'status':'error'}), 403
        db   = get_db()
        srvs = db.execute('SELECT folder FROM servers WHERE user_id=?',(uid,)).fetchall()
        for s in srvs:
            p = os.path.join(app.config['BASE_STORAGE'],s['folder'])
            if os.path.exists(p): shutil.rmtree(p)
        db.execute('DELETE FROM servers WHERE user_id=?',(uid,))
        db.execute('DELETE FROM users WHERE id=?',(uid,))
        db.commit(); db.close()
        return jsonify({'status':'deleted'})

    @app.route('/admin/files/<folder>')
    def admin_browse_files(folder):
        if not session.get('admin_logged'): return redirect(url_for('admin_login'))
        return render_template('web/dashboard.html',
                               user={'fname':'Admin','role':'admin'},
                               is_admin_view=True, admin_folder=folder)

    return app

app = create_app()

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
