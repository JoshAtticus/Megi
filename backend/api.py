import sqlite3
import time
import os
import json
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from better_profanity import profanity
from datetime import datetime, timedelta
import re

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
socketio = SocketIO(app)
load_dotenv()

password = os.environ.get('PASSWORD')
presence = {}  # Store presence information

# Load banned IPs
with open('ipbans.json', 'r') as f:
    banned_ips = json.load(f)

# Database setup
conn = sqlite3.connect('messages.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    color TEXT NOT NULL
)
''')
conn.commit()

def load_messages():
    cursor.execute('SELECT id, name, content, timestamp, color FROM messages')
    rows = cursor.fetchall()
    messages = [{'id': row[0], 'name': row[1], 'content': row[2], 'timestamp': row[3], 'color': row[4]} for row in rows]
    return messages

def save_message(name, content, timestamp, color):
    cursor.execute('INSERT INTO messages (name, content, timestamp, color) VALUES (?, ?, ?, ?)',
                   (name, content, timestamp, color))
    conn.commit()

def delete_message(message_id):
    cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()

def log_request(ip, username):
    log_entry = {
        'ip': ip,
        'username': username,
        'timestamp': datetime.now().isoformat()
    }
    with open('logs.json', 'r+') as f:
        logs = json.load(f)
        logs.append(log_entry)
        f.seek(0)
        json.dump(logs, f, indent=4)

@app.route('/api/messages', methods=['GET'])
def get_messages():
    if request.remote_addr in banned_ips:
        return jsonify({'error': 'Your IP has been banned.'}), 403
    
    log_request(request.remote_addr, "GET /api/messages")
    messages = load_messages()
    return jsonify(messages[-50:])

@app.route('/api/messages', methods=['POST'])
def add_message():
    if request.remote_addr in banned_ips:
        return jsonify({'error': 'Your IP has been banned.'}), 403

    name = request.json['name'][:20]  # Limit name to 20 characters
    if profanity.contains_profanity(name):
        return jsonify({'error': 'Name contains profanity.'}), 400

    content = request.json['content']
    timestamp = int(time.time())
    rgb_color = request.json.get('color', [239, 0, 10])

    # Check for script tags
    if "<script>" in content.lower():
        return jsonify({'error': 'XSS attempt blocked'}), 400

    # Check for image tags with JavaScript
    if re.search(r'<img[^>]+src\s*=\s*["\']?javascript:', content, re.IGNORECASE):
        return jsonify({'error': 'XSS attempt blocked'}), 400

    # Basic SQL Injection check
    sql_injection_patterns = ["' or '1'='1", ";", "--"]
    if any(pattern in content for pattern in sql_injection_patterns) or any(pattern in name for pattern in sql_injection_patterns):
        return jsonify({'error': 'SQL Injection attempt blocked.'}), 400

    if len(content) <= 1500:
        save_message(name, content, timestamp, str(rgb_color))
        log_request(request.remote_addr, name)
        return jsonify({'message': 'Message sent successfully.'}), 201
    else:
        return jsonify({'error': 'Message content exceeds the maximum limit of 1500 characters.'}), 400

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
def delete_message_route(message_id):
    if request.remote_addr in banned_ips:
        return jsonify({'error': 'Your IP has been banned.'}), 403
    
    password_input = request.args.get('password')
    if password_input == password:
        delete_message(message_id)
        log_request(request.remote_addr, f"DELETE /api/messages/{message_id}")
        return jsonify({'message': 'Message deleted successfully.'}), 200
    else:
        return jsonify({'error': 'Unauthorized access. Please check your password and try again.'}), 401

@app.route('/api/presence', methods=['POST'])
def update_presence():
    if request.remote_addr in banned_ips:
        return jsonify({'error': 'Your IP has been banned.'}), 403

    username = request.json.get('username')
    
    # Check for profanity
    if profanity.contains_profanity(username):
        return jsonify({'error': 'Profanity is not allowed.'}), 400
    
    # Check for character limit
    if len(username) > 20:
        return jsonify({'error': 'Invalid username'}), 400
    
    if not username:
        return jsonify({'error': 'Username is required.'}), 400
    
    presence[username] = datetime.now()
    log_request(request.remote_addr, username)
    return jsonify({'message': 'Presence updated successfully.'}), 200

@app.route('/api/online-users', methods=['GET'])
def get_online_users():
    if request.remote_addr in banned_ips:
        return jsonify({'error': 'Your IP has been banned.'}), 403

    now = datetime.now()
    online_users = [user for user, last_seen in presence.items() if now - last_seen < timedelta(seconds=30)]
    log_request(request.remote_addr, "GET /api/online-users")
    return jsonify(online_users), 200

if __name__ == '__main__':
    profanity.load_censor_words()
    socketio.run(app, allow_unsafe_werkzeug=True, port=5023)
