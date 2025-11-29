from flask import Flask, request, render_template_string, send_file
import sqlite3
import os
import subprocess

app = Flask(__name__)

# Initialize database with sample data
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY, user_id INTEGER, comment TEXT)''')

    # Insert sample data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@test.com')")
    c.execute("INSERT OR IGNORE INTO comments VALUES (1, 1, 'Welcome to our vulnerable site!')")

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template_string('''
    <html>
    <head><title>Vulnerable Test Site</title></head>
    <body>
        <h1>🚨 VULNERABLE TEST SITE 🚨</h1>
        <p>This site contains intentional vulnerabilities for testing Snort IDS.</p>
        <p><strong>DO NOT USE IN PRODUCTION!</strong></p>

        <h2>Testable Vulnerabilities:</h2>
        <ul>
            <li><a href="/login">SQL Injection Login</a></li>
            <li><a href="/search">SQL Injection Search</a></li>
            <li><a href="/comment">XSS Comment System</a></li>
            <li><a href="/file">Directory Traversal</a></li>
            <li><a href="/exec">Command Injection</a></li>
            <li><a href="/upload">File Upload (Potential RCE)</a></li>
        </ul>

        <h2>Attack Commands:</h2>
        <pre>
# SQL Injection
curl "http://localhost:8080/login?username=admin'--&password=anything"

# XSS
curl "http://localhost:8080/comment?comment=<script>alert('XSS')</script>"

# Directory Traversal
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Command Injection
curl "http://localhost:8080/exec?cmd=cat%20/etc/passwd"
        </pre>
    </body>
    </html>
    ''')

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')

    if username and password:
        # VULNERABLE: Direct SQL injection
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"Executing query: {query}")  # Debug logging

        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()

            if user:
                return f"<h1>Welcome {user[1]}!</h1><p>Login successful.</p>"
            else:
                return "<h1>Login Failed</h1><p>Invalid credentials.</p>"
        except Exception as e:
            return f"<h1>Database Error</h1><p>{str(e)}</p>"

    return render_template_string('''
    <html>
    <head><title>Login - SQL Injection Test</title></head>
    <body>
        <h1>Login Form (Vulnerable to SQL Injection)</h1>
        <form method="GET">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>

        <h2>Test Payloads:</h2>
        <ul>
            <li>Username: <code>admin'--</code> (Bypass auth)</li>
            <li>Username: <code>' OR '1'='1</code> (Union attack)</li>
        </ul>
    </body>
    </html>
    ''')

@app.route('/search')
def search():
    query = request.args.get('q', '')

    if query:
        # VULNERABLE: SQL injection in search
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        sql_query = f"SELECT * FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
        print(f"Search query: {sql_query}")

        try:
            c.execute(sql_query)
            results = c.fetchall()
            conn.close()

            output = "<h1>Search Results</h1>"
            for user in results:
                output += f"<p>User: {user[1]}, Email: {user[3]}</p>"
            return output
        except Exception as e:
            return f"<h1>Search Error</h1><p>{str(e)}</p>"

    return render_template_string('''
    <html>
    <head><title>Search - SQL Injection Test</title></head>
    <body>
        <h1>User Search (Vulnerable to SQL Injection)</h1>
        <form method="GET">
            Search: <input type="text" name="q" placeholder="Search users...">
            <input type="submit" value="Search">
        </form>

        <h2>Test Payloads:</h2>
        <ul>
            <li>Search: <code>%' UNION SELECT * FROM users--</code></li>
            <li>Search: <code>%' OR '1'='1</code></li>
        </ul>
    </body>
    </html>
    ''')

@app.route('/comment')
def comment():
    user_comment = request.args.get('comment', '')

    if user_comment:
        # VULNERABLE: XSS - direct output without sanitization
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        c.execute("INSERT INTO comments (user_id, comment) VALUES (?, ?)", (1, user_comment))
        conn.commit()
        conn.close()

        return f"<h1>Comment Posted!</h1><p>Your comment: {user_comment}</p>"

    # Display all comments (also vulnerable to XSS)
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("SELECT comment FROM comments")
    comments = c.fetchall()
    conn.close()

    comments_html = ""
    for comment in comments:
        comments_html += f"<div class='comment'>{comment[0]}</div>"

    return render_template_string(f'''
    <html>
    <head><title>Comments - XSS Test</title></head>
    <body>
        <h1>Comment System (Vulnerable to XSS)</h1>
        <form method="GET">
            Comment: <input type="text" name="comment" size="50">
            <input type="submit" value="Post Comment">
        </form>

        <h2>Existing Comments:</h2>
        {comments_html}

        <h2>Test Payloads:</h2>
        <ul>
            <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
        </ul>
    </body>
    </html>
    ''')

@app.route('/file')
def file_access():
    filepath = request.args.get('path', '')

    if filepath:
        # VULNERABLE: Directory traversal
        try:
            # Allow access to files (dangerous!)
            if os.path.exists(filepath):
                return send_file(filepath)
            else:
                return f"<h1>File Not Found</h1><p>Could not find: {filepath}</p>"
        except Exception as e:
            return f"<h1>Error</h1><p>{str(e)}</p>"

    return render_template_string('''
    <html>
    <head><title>File Access - Directory Traversal Test</title></head>
    <body>
        <h1>File Access (Vulnerable to Directory Traversal)</h1>
        <form method="GET">
            File Path: <input type="text" name="path" size="50" placeholder="/etc/passwd">
            <input type="submit" value="Access File">
        </form>

        <h2>Test Payloads:</h2>
        <ul>
            <li><code>../../../etc/passwd</code> (Unix systems)</li>
            <li><code>../../../Windows/System32/drivers/etc/hosts</code> (Windows)</li>
            <li><code>....//....//....//etc/passwd</code> (Bypass filters)</li>
        </ul>

        <p><strong>Note:</strong> This will actually try to access files on the server!</p>
    </body>
    </html>
    ''')

@app.route('/exec')
def command_exec():
    cmd = request.args.get('cmd', '')

    if cmd:
        # VULNERABLE: Command injection
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            return f"<h1>Command Output</h1><pre>{output}</pre>"
        except Exception as e:
            return f"<h1>Command Error</h1><p>{str(e)}</p>"

    return render_template_string('''
    <html>
    <head><title>Command Execution - RCE Test</title></head>
    <body>
        <h1>Command Execution (Vulnerable to RCE)</h1>
        <form method="GET">
            Command: <input type="text" name="cmd" size="50" placeholder="whoami">
            <input type="submit" value="Execute">
        </form>

        <h2>Test Payloads:</h2>
        <ul>
            <li><code>cat /etc/passwd</code></li>
            <li><code>net user</code> (Windows)</li>
            <li><code>; cat /etc/passwd</code> (Command chaining)</li>
        </ul>

        <p><strong>Warning:</strong> This executes actual system commands!</p>
    </body>
    </html>
    ''')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # VULNERABLE: Unrestricted file upload
            filename = file.filename
            filepath = os.path.join('uploads', filename)

            # Create uploads directory if it doesn't exist
            os.makedirs('uploads', exist_ok=True)

            file.save(filepath)
            return f"<h1>File Uploaded</h1><p>Saved as: {filepath}</p>"

    return render_template_string('''
    <html>
    <head><title>File Upload - RCE Test</title></head>
    <body>
        <h1>File Upload (Potential RCE via Malicious Files)</h1>
        <form method="POST" enctype="multipart/form-data">
            File: <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>

        <h2>Test Scenarios:</h2>
        <ul>
            <li>Upload a PHP shell: <code>&lt;?php system($_GET['cmd']); ?&gt;</code></li>
            <li>Upload executable files</li>
            <li>Test with various file extensions</li>
        </ul>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    print("🚨 Starting VULNERABLE test site on http://localhost:3000")
    print("⚠️  This site contains intentional security vulnerabilities!")
    print("⚠️  Only use in a controlled testing environment!")
    app.run(host='127.0.0.1', port=3000, debug=True)