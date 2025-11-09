from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import sqlite3

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

def init_db():
    """Initialize database with all tables"""
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mood_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            emotion TEXT NOT NULL,
            confidence REAL NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            duration INTEGER,
            emotions_detected INTEGER DEFAULT 0,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

@app.route('/api/health', methods=['GET'])
def health_check():
    '''Health check endpoint'''
    return jsonify({'status': 'healthy', 'message': 'API is running'}), 200

@app.route('/api/signup', methods=['POST'])
def signup():
    '''Register a new user'''
    data = request.get_json()
    
    if not data or not data.get('fullname') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    fullname = data['fullname']
    email = data['email']
    password = data['password']
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    try:
        conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)',
            (fullname, email, hashed_password)
        )
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Email already exists'}), 409
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    '''Login user and return JWT token'''
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    email = data['email']
    password = data['password']
    
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, fullname, email, password FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    user_id, fullname, user_email, hashed_password = user
    
    if not check_password_hash(hashed_password, password):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    token = jwt.encode({
        'user_id': user_id,
        'email': user_email,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user_id,
            'fullname': fullname,
            'email': user_email
        }
    }), 200

@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user_id, user_id):
    '''Get user profile'''
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, fullname, email, created_at FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'id': user[0],
        'fullname': user[1],
        'email': user[2],
        'created_at': user[3]
    }), 200

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user_id, user_id):
    '''Update user profile'''
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    if data.get('fullname'):
        cursor.execute('UPDATE users SET fullname = ? WHERE id = ?', (data['fullname'], user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user_id, user_id):
    '''Delete user account'''
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM mood_records WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User deleted successfully'}), 200


@app.route('/api/mood-records', methods=['POST'])
@token_required
def create_mood_record(current_user_id):
    '''Create a new mood record'''
    data = request.get_json()
    
    if not data or not data.get('emotion') or data.get('confidence') is None:
        return jsonify({'message': 'Missing required fields'}), 400
    
    emotion = data['emotion']
    confidence = float(data['confidence'])
    
    try:
        conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO mood_records (user_id, emotion, confidence) VALUES (?, ?, ?)',
            (current_user_id, emotion, confidence)
        )
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'message': 'Mood record created successfully',
            'record_id': record_id
        }), 201
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/mood-records', methods=['GET'])
@token_required
def get_mood_records(current_user_id):
    '''Get all mood records for current user'''
    limit = request.args.get('limit', 100, type=int)
    
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, emotion, confidence, timestamp FROM mood_records WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?',
        (current_user_id, limit)
    )
    
    records = cursor.fetchall()
    conn.close()
    
    mood_list = []
    for record in records:
        mood_list.append({
            'id': record[0],
            'emotion': record[1],
            'confidence': record[2],
            'timestamp': record[3]
        })
    
    return jsonify(mood_list), 200

@app.route('/api/mood-records/<int:record_id>', methods=['GET'])
@token_required
def get_mood_record(current_user_id, record_id):
    '''Get a specific mood record'''
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, user_id, emotion, confidence, timestamp FROM mood_records WHERE id = ?',
        (record_id,)
    )
    
    record = cursor.fetchone()
    conn.close()
    
    if not record:
        return jsonify({'message': 'Record not found'}), 404
    
    if record[1] != current_user_id:
        return jsonify({'message': 'Unauthorized'}), 403
    
    return jsonify({
        'id': record[0],
        'emotion': record[2],
        'confidence': record[3],
        'timestamp': record[4]
    }), 200

@app.route('/api/mood-records/<int:record_id>', methods=['DELETE'])
@token_required
def delete_mood_record(current_user_id, record_id):
    '''Delete a mood record'''
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('SELECT user_id FROM mood_records WHERE id = ?', (record_id,))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'message': 'Record not found'}), 404
    
    if record[0] != current_user_id:
        conn.close()
        return jsonify({'message': 'Unauthorized'}), 403
    
    cursor.execute('DELETE FROM mood_records WHERE id = ?', (record_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Record deleted successfully'}), 200

@app.route('/api/sessions', methods=['POST'])
@token_required
def create_session(current_user_id):
    '''Start a new detection session'''
    try:
        conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO sessions (user_id) VALUES (?)',
            (current_user_id,)
        )
        
        conn.commit()
        session_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'message': 'Session started',
            'session_id': session_id
        }), 201
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/sessions/<int:session_id>', methods=['PUT'])
@token_required
def update_session(current_user_id, session_id):
    '''Update session (end time, emotions detected)'''
    data = request.get_json()
    
    try:
        conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM sessions WHERE id = ?', (session_id,))
        session = cursor.fetchone()
        
        if not session or session[0] != current_user_id:
            conn.close()
            return jsonify({'message': 'Unauthorized'}), 403
        
        if data.get('emotions_detected') is not None:
            cursor.execute(
                'UPDATE sessions SET emotions_detected = ? WHERE id = ?',
                (data['emotions_detected'], session_id)
            )
        
        if data.get('end_session'):
            cursor.execute(
                'UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE id = ?',
                (session_id,)
            )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Session updated'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/sessions', methods=['GET'])
@token_required
def get_sessions(current_user_id):
    '''Get all sessions for current user'''
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, duration, emotions_detected, start_time, end_time FROM sessions WHERE user_id = ? ORDER BY start_time DESC',
        (current_user_id,)
    )
    
    sessions = cursor.fetchall()
    conn.close()
    
    session_list = []
    for session in sessions:
        session_list.append({
            'id': session[0],
            'duration': session[1],
            'emotions_detected': session[2],
            'start_time': session[3],
            'end_time': session[4]
        })
    
    return jsonify(session_list), 200

@app.route('/api/stats/emotions', methods=['GET'])
@token_required
def get_emotion_stats(current_user_id):
    '''Get emotion distribution statistics'''
    conn = sqlite3.connect('mood_detector.db', check_same_thread=False, timeout=10)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT emotion, COUNT(*) as count, AVG(confidence) as avg_confidence
        FROM mood_records
        WHERE user_id = ?
        GROUP BY emotion
        ORDER BY count DESC
    ''', (current_user_id,))
    
    stats = cursor.fetchall()
    conn.close()
    
    emotion_stats = []
    for stat in stats:
        emotion_stats.append({
            'emotion': stat[0],
            'count': stat[1],
            'avg_confidence': round(stat[2], 2)
        })
    
    return jsonify(emotion_stats), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
