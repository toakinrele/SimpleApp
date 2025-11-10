"""
Deliberately Insecure Flask Application for CodeQL Testing
WARNING: This code contains intentional security vulnerabilities
DO NOT use in production or any real environment
"""

from flask import Flask, request, render_template_string, redirect
from urllib.parse import urlparse
import sqlite3
import os
import pickle
import subprocess

app = Flask(__name__)

DATABASE = 'users.db'
ADMIN_PASSWORD = 'admin123'
SECRET_KEY = 'hardcoded_secret_key_12345'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return f"Welcome {username}!"
        return "Login failed"
    
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/ping')
def ping():
    allowed_hosts = ['localhost', '127.0.0.1']
    host = request.args.get('host', 'localhost')
    if host not in allowed_hosts:
        return "Invalid host", 400
    result = os.popen(f'ping -c 1 {host}').read()
    return f'<pre>{result}</pre>'

@app.route('/read_file')
def read_file():
    BASE_DIR = os.path.abspath("safe_files")
    filename = request.args.get('file', 'default.txt')
    safe_path = os.path.normpath(os.path.join(BASE_DIR, filename))
    try:
        if not safe_path.startswith(BASE_DIR):
            return "File not found"
        with open(safe_path, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except:
        return 'File not found'

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    template = '<h1>Hello {{ name }}!</h1>'
    return render_template_string(template, name=name)

@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.form.get('data')
    try:
        obj = pickle.loads(bytes.fromhex(data))
        return f'Loaded: {obj}'
    except:
        return 'Invalid data'

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.data
    try:
        root = ET.fromstring(xml_data)
        return f'Parsed: {root.tag}'
    except:
        return 'Invalid XML'

@app.route('/redirect')
def redirect_url():
    url = request.args.get('url', '/')
    url = url.replace('\\', '')
    parsed = urlparse(url)
    # Only allow relative redirects
    if not parsed.netloc and not parsed.scheme:
        return redirect(url)
    return redirect('/')


@app.route('/hash_password')
def hash_password():
    import hashlib
    password = request.args.get('password', '')
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f'Hashed password: {hashed}'


@app.route('/debug')
def debug():
    return f'''
    <h2>Debug Info</h2>
    <p>Database: {DATABASE}</p>
    <p>Admin Password: {ADMIN_PASSWORD}</p>
    <p>Secret Key: {SECRET_KEY}</p>
    <p>Environment: {os.environ}</p>
    '''


@app.route('/execute')
def execute():
    cmd = request.args.get('cmd', 'ls')
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f'<pre>{result.stdout}</pre>'


@app.route('/admin/delete_user')
def delete_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return 'User deleted'

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0')