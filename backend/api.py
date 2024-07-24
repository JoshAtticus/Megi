import sqlite3
import time
import os
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
cursor.execute('''
CREATE INDEX IF NOT EXISTS messages_id_idx ON messages(id)
''')
conn.commit()

def load_messages(start_id=-1):
    if start_id == -1:
        cursor.execute('''
SELECT * FROM (
    SELECT id, name, content, timestamp, color FROM messages ORDER BY id DESC LIMIT 50
) ORDER BY id ASC''')
    else:
        cursor.execute('SELECT id, name, content, timestamp, color FROM messages WHERE id >= ? ORDER BY id LIMIT 50', (start_id,))
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

@app.route('/api/messages', methods=['GET'])
def get_messages():
    if request.args.get('start_post') is not None:
        messages = load_messages(int(request.args.get('start_post')))
    else:
        messages = load_messages()
    return jsonify(messages)

@app.route('/api/messages', methods=['POST'])
def add_message():
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
        return jsonify({'message': 'Message sent successfully.'}), 201
    else:
        return jsonify({'error': 'Message content exceeds the maximum limit of 1500 characters.'}), 400

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
def delete_message_route(message_id):
    password_input = request.args.get('password')
    if password_input == password:
        delete_message(message_id)
        return jsonify({'message': 'Message deleted successfully.'}), 200
    else:
        return jsonify({'error': 'Unauthorized access. Please check your password and try again.'}), 401

@app.route('/api/presence', methods=['POST'])
def update_presence():
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
    return jsonify({'message': 'Presence updated successfully.'}), 200

@app.route('/api/online-users', methods=['GET'])
def get_online_users():
    now = datetime.now()
    online_users = [user for user, last_seen in presence.items() if now - last_seen < timedelta(seconds=30)]
    return jsonify(online_users), 200

if __name__ == '__main__':
    profanity.load_censor_words()
    socketio.run(app, allow_unsafe_werkzeug=True, port=5023)
