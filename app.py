import os, sqlite3, secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB=os.environ.get("DATABASE_PATH","karibu.db")

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'manager', active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT,email TEXT,nationality TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS tours(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,days INTEGER,price REAL,type TEXT);
    CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY AUTOINCREMENT,customer TEXT NOT NULL,service TEXT NOT NULL,date TEXT,amount REAL DEFAULT 0,status TEXT DEFAULT 'Confirmed',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS finance(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT NOT NULL,description TEXT NOT NULL,amount REAL DEFAULT 0,reference TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS vehicles(id INTEGER PRIMARY KEY AUTOINCREMENT,plate TEXT NOT NULL,driver TEXT NOT NULL,type TEXT,model TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    if not c.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        c.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",("admin",generate_password_hash(os.environ.get("ADMIN_PASSWORD","ChangeMeNow!")),"super_admin"))
    c.commit(); c.close()
init()

def logged():
    return session.get("uid") is not None
def audit(action):
    c=db(); c.execute("INSERT INTO audit(user_id,action) VALUES(?,?)",(session.get("uid"),action)); c.commit(); c.close()

@app.route("/",methods=["GET","POST"])
def login():
    if logged(): return redirect(url_for("dashboard"))
    if request.method=="POST":
        u=request.form["username"].strip(); p=request.form["password"]
        c=db(); user=c.execute("SELECT * FROM users WHERE username=? AND active=1",(u,)).fetchone(); c.close()
        if user and check_password_hash(user["password"],p):
            session["uid"]=user["id"]; session["username"]=user["username"]; session["role"]=user["role"]; audit("login"); return redirect(url_for("dashboard"))
        flash("Invalid username or password.","error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not logged(): return redirect(url_for("login"))
    c=db()
    rev=(c.execute("SELECT COALESCE(SUM(amount),0) x FROM bookings").fetchone()["x"] or 0)+(c.execute("SELECT COALESCE(SUM(amount),0) x FROM finance WHERE type='income'").fetchone()["x"] or 0)
    exp=c.execute("SELECT COALESCE(SUM(amount),0) x FROM finance WHERE type='expense'").fetchone()["x"] or 0
    data={"revenue":rev,"expenses":exp,"profit":rev-exp,
          "customers":c.execute("SELECT COUNT(*) n FROM customers").fetchone()["n"],
          "bookings":c.execute("SELECT COUNT(*) n FROM bookings").fetchone()["n"],
          "tours":c.execute("SELECT COUNT(*) n FROM tours").fetchone()["n"],
          "vehicles":c.execute("SELECT COUNT(*) n FROM vehicles").fetchone()["n"]}
    recent=c.execute("SELECT * FROM bookings ORDER BY id DESC LIMIT 10").fetchall(); c.close()
    return render_template("dashboard.html",data=data,recent=recent)

@app.route("/api/<entity>",methods=["GET","POST"])
def api(entity):
    if not logged(): return jsonify(error="unauthorized"),401
    allowed={"customers":"customers","tours":"tours","bookings":"bookings","finance":"finance","vehicles":"vehicles"}
    if entity not in allowed:return jsonify(error="not found"),404
    table=allowed[entity]; c=db()
    if request.method=="GET":
        rows=c.execute(f"SELECT * FROM {table} ORDER BY id DESC").fetchall(); c.close(); return jsonify([dict(x) for x in rows])
    d=request.json or {}
    if table=="customers": c.execute("INSERT INTO customers(name,phone,email,nationality) VALUES(?,?,?,?)",(d.get("name"),d.get("phone"),d.get("email"),d.get("nationality")))
    elif table=="tours": c.execute("INSERT INTO tours(name,days,price,type) VALUES(?,?,?,?)",(d.get("name"),d.get("days"),d.get("price",0),d.get("type")))
    elif table=="bookings": c.execute("INSERT INTO bookings(customer,service,date,amount,status) VALUES(?,?,?,?,?)",(d.get("customer"),d.get("service"),d.get("date"),d.get("amount",0),d.get("status","Confirmed")))
    elif table=="finance": c.execute("INSERT INTO finance(type,description,amount,reference) VALUES(?,?,?,?)",(d.get("type"),d.get("description"),d.get("amount",0),d.get("reference")))
    elif table=="vehicles": c.execute("INSERT INTO vehicles(plate,driver,type,model) VALUES(?,?,?,?)",(d.get("plate"),d.get("driver"),d.get("type"),d.get("model")))
    c.commit(); c.close(); audit(f"create_{table}"); return jsonify(ok=True)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
