"""
Deliberately Insecure Flask Application for CodeQL Testing
WARNING: This code contains intentional security vulnerabilities
DO NOT use in production or any real environment
"""

from flask import Flask, request, render_template_string, redirect
import sqlite3
import os
import pickle
import subprocess

app = Flask(__name__)

# Vulnerability 1: Hardcoded credentials
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

# Vulnerability 2: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SQL Injection vulnerability - user input directly concatenated
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
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

# Vulnerability 3: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Command injection - unsanitized user input in shell command
    result = os.popen(f'ping -c 1 {host}').read()
    return f'<pre>{result}</pre>'

# Vulnerability 4: Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', 'default.txt')
    # Path traversal vulnerability - no validation of file path
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except:
        return 'File not found'

# Vulnerability 5: Server-Side Template Injection (SSTI)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # SSTI vulnerability - user input directly in template
    template = f'<h1>Hello {name}!</h1>'
    return render_template_string(template)

# Vulnerability 6: Insecure Deserialization
@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.form.get('data')
    # Insecure deserialization - pickle.loads on user input
    try:
        obj = pickle.loads(bytes.fromhex(data))
        return f'Loaded: {obj}'
    except:
        return 'Invalid data'

# Vulnerability 7: XML External Entity (XXE) Injection
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.data
    # XXE vulnerability - parsing untrusted XML without disabling external entities
    try:
        root = ET.fromstring(xml_data)
        return f'Parsed: {root.tag}'
    except:
        return 'Invalid XML'

# Vulnerability 8: Open Redirect
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url', '/')
    # Open redirect - no validation of redirect target
    return redirect(url)

# Vulnerability 9: Weak Cryptography
@app.route('/hash_password')
def hash_password():
    import hashlib
    password = request.args.get('password', '')
    # Weak hashing algorithm (MD5) for passwords
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f'Hashed password: {hashed}'

# Vulnerability 10: Information Disclosure
@app.route('/debug')
def debug():
    # Exposing sensitive debugging information
    return f'''
    <h2>Debug Info</h2>
    <p>Database: {DATABASE}</p>
    <p>Admin Password: {ADMIN_PASSWORD}</p>
    <p>Secret Key: {SECRET_KEY}</p>
    <p>Environment: {os.environ}</p>
    '''

# Vulnerability 11: Using subprocess with shell=True
@app.route('/execute')
def execute():
    cmd = request.args.get('cmd', 'ls')
    # Command injection via subprocess with shell=True
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f'<pre>{result.stdout}</pre>'

# Vulnerability 12: Missing authentication
@app.route('/admin/delete_user')
def delete_user():
    # No authentication check for sensitive operation
    user_id = request.args.get('id')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return 'User deleted'

if __name__ == '__main__':
    init_db()
    # Vulnerability 13: Debug mode enabled
    app.run(debug=True, host='0.0.0.0')