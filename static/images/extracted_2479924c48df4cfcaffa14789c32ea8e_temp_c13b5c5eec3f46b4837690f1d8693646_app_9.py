from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room
import mysql.connector, os, datetime, base64, io, hashlib, json ,threading ,time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2          # time-lock key derivation
import cv2
import numpy as np
from werkzeug.utils import secure_filename
from PIL import Image
from base64 import b64encode
import pytz
import uuid
import struct 
import base64


FIXED_APP_SECRET = b'Your32ByteSecretKey4Encryption!!' # Exactly 32 bytes

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for static files
app.secret_key = '403ef9474fb2d1540e89fceada035db6'
app.config['UPLOAD_FOLDER'] = 'static/images/'
app.config['MAX_IMAGE_SIZE'] = (1920, 1080)  # ✅ Limit max image dimensions
app.config['MAX_HIDDEN_FILE_SIZE'] = 500 * 1024  # ✅ 500KB max for hidden files
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
socketio = SocketIO(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'



def get_db_connection():
    try:
        return mysql.connector.connect(
            host='localhost',
            user='root',
            password='admin',
            database='secure_messaging'
        )
    except mysql.connector.Error as err:
        flash(f'Database connection failed: {err}') 
        return None

def init_db():
    conn = get_db_connection()
    if not conn:
        print("Could not connect to database for initialization.")
        return
    
    cursor = None
    try:
        cursor = conn.cursor()

        # 1. Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                dateofbirth DATE,
                email VARCHAR(255) UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_email (email)
            )
        ''')

        # 2. Messages table (WITH SCREENSHOT PROTECTION)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(80) NOT NULL,
                receiver VARCHAR(80) NOT NULL,
                content TEXT,
                image_path VARCHAR(500),
                aes_key BLOB,
                message_hash VARCHAR(64) NOT NULL,
                image_hash VARCHAR(64),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_status ENUM('sent', 'delivered', 'read') DEFAULT 'sent',
                delivered_at TIMESTAMP NULL,
                read_at TIMESTAMP NULL,
                burn_after_view BOOLEAN DEFAULT FALSE,
                viewed BOOLEAN DEFAULT FALSE,
                unlock_at DATETIME NULL,
                screenshot_protect BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (receiver) REFERENCES users(username) ON DELETE CASCADE,
                INDEX idx_sender (sender),
                INDEX idx_receiver (receiver),
                INDEX idx_timestamp (timestamp),
                INDEX idx_read_status (read_status),
                INDEX idx_unlock_at (unlock_at)
            )
        ''')

        # 3. Conversation reads
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversation_reads (
                user VARCHAR(80) NOT NULL,
                partner VARCHAR(80) NOT NULL,
                last_read TIMESTAMP DEFAULT NULL,
                PRIMARY KEY (user, partner),
                FOREIGN KEY (user) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (partner) REFERENCES users(username) ON DELETE CASCADE,
                INDEX idx_partner (partner)
            )
        ''')

        # 4. Screenshot Events Table (NEW - for logging screenshot attempts)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshot_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                message_id INT NOT NULL,
                detected_by VARCHAR(80) NOT NULL,
                sender VARCHAR(80) NOT NULL,
                receiver VARCHAR(80) NOT NULL,
                detection_reason TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_message_id (message_id),
                INDEX idx_detected_by (detected_by),
                INDEX idx_timestamp (timestamp)
            )
        ''')
        cursor.execute('''        
                CREATE TABLE IF NOT EXISTS deadman_settings (
                    user_id INT PRIMARY KEY,
                    checkin_interval_hours INT NOT NULL DEFAULT 24,
                    grace_period_hours INT NOT NULL DEFAULT 6,
                    last_checkin_at DATETIME NULL,
                    trusted_contacts_json TEXT NOT NULL,
                    is_active TINYINT(1) NOT NULL DEFAULT 0,
                    CONSTRAINT fk_deadman_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );

                    CREATE TABLE deadman_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    stage ENUM('ACTIVE','OVERDUE','GRACE','EMERGENCY') NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT NOW(),
                    processed TINYINT(1) NOT NULL DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                ''')
        
        # ── MIGRATION: add unlock_at to pre-existing messages tables ──
        # Safe to run every startup; does nothing if the column already exists.
        cursor.execute("SHOW COLUMNS FROM messages LIKE 'unlock_at'")
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE messages ADD COLUMN unlock_at DATETIME NULL AFTER viewed')
            cursor.execute('ALTER TABLE messages ADD INDEX idx_unlock_at (unlock_at)')
            print("✓ Migration: added unlock_at column + index to messages")
            
        cursor.execute("SHOW COLUMNS FROM messages LIKE 'screenshot_protect'")
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE messages ADD COLUMN screenshot_protect BOOLEAN DEFAULT TRUE AFTER unlock_at')
            print("✓ Migration: added screenshot_protect column (default TRUE)")
        else:
            # Update existing column default to TRUE
            cursor.execute('ALTER TABLE messages MODIFY COLUMN screenshot_protect BOOLEAN DEFAULT TRUE')
            print("✓ Migration: updated screenshot_protect default to TRUE")
        
        # ── MIGRATION: add delivered_at and read_at timestamp columns ──
        cursor.execute("SHOW COLUMNS FROM messages LIKE 'delivered_at'")
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE messages ADD COLUMN delivered_at TIMESTAMP NULL AFTER read_status')
            print("✓ Migration: added delivered_at column to messages")
            
        cursor.execute("SHOW COLUMNS FROM messages LIKE 'read_at'")
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE messages ADD COLUMN read_at TIMESTAMP NULL AFTER delivered_at')
            print("✓ Migration: added read_at column to messages")
        
        # ── MIGRATION: add integritystatus column for SHA-256 integrity check ──
        cursor.execute("SHOW COLUMNS FROM messages LIKE 'integritystatus'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE messages ADD COLUMN integritystatus VARCHAR(20) DEFAULT 'pending' AFTER image_hash")
            print("✓ Migration: added integritystatus column to messages")
        
        conn.commit()
        
    except mysql.connector.Error as err:
        print(f"Error during table creation: {err}")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
    print("✓ Database schema complete: users, messages, conversation_reads")


class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id=%s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1])
    return None


# ============================================
# NUMPY LSB STEGANOGRAPHY (ULTRA FAST!)
# ============================================

def hide_data_in_image_numpy(image_path: str, data_bytes: bytes) -> str:
    """
    DIAGNOSTIC VERSION - Shows timing for each step
    """
    import time
    print(f"[NUMPY HIDE] Starting to hide {len(data_bytes)} bytes")
    
    # Load image
    step = time.time()
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    print(f"  [TIMING] Load & convert: {time.time() - step:.3f}s")
    
    step = time.time()
    img_array = np.array(img, dtype=np.uint8)
    print(f"  [TIMING] Create array: {time.time() - step:.3f}s")
    
    # Encode data
    step = time.time()
    data_b64 = base64.b64encode(data_bytes).decode('utf-8')
    data_length = len(data_b64)
    header = struct.pack('>I', data_length)
    full_data = header + data_b64.encode('utf-8')
    print(f"  [TIMING] Encode: {time.time() - step:.3f}s")
    
    # Convert to bits
    step = time.time()
    data_np = np.frombuffer(full_data, dtype=np.uint8)
    bits = np.unpackbits(data_np)
    print(f"  [TIMING] unpackbits: {time.time() - step:.3f}s")
    
    # Check capacity
    total_pixels = img_array.size
    if len(bits) > total_pixels:
        raise ValueError(f"Data too large! Need {len(bits)} bits, have {total_pixels} pixels")
    
    # Flatten
    step = time.time()
    flat_img = img_array.flatten()
    print(f"  [TIMING] Flatten: {time.time() - step:.3f}s")
    
    # Embed
    step = time.time()
    flat_img[:len(bits)] = (flat_img[:len(bits)] & 0xFE) | bits
    print(f"  [TIMING] Embed: {time.time() - step:.3f}s")
    
    # Reshape
    step = time.time()
    stego_array = flat_img.reshape(img_array.shape)
    stego_img = Image.fromarray(stego_array, mode='RGB')
    print(f"  [TIMING] Reshape: {time.time() - step:.3f}s")
    
    # Save
    output_filename = f"stego_{uuid.uuid4().hex}.png"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    step = time.time()
    stego_img.save(output_path, 'PNG', compress_level=1)  # Fast compression
    print(f"  [TIMING] Save PNG: {time.time() - step:.3f}s")
    
    print(f"[NUMPY HIDE] Successfully saved: {output_path}")
    return output_path



def extract_data_from_image_numpy(image_path: str) -> bytes:
    """
    Extract data from image using NumPy LSB - ULTRA FAST!
    """
    print(f"[NUMPY EXTRACT] Extracting from: {image_path}")
    
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file missing: {image_path}")
    
    # Load image
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    img_array = np.array(img, dtype=np.uint8)
    flat_img = img_array.flatten()
    
    # ✅ OPTIMIZED: Extract header bits using NumPy
    header_bits = flat_img[:32] & 1
    header_bytes = np.packbits(header_bits)
    data_length = struct.unpack('>I', header_bytes.tobytes())[0]
    
    print(f"[NUMPY EXTRACT] Detected data length: {data_length} bytes")
    
    # Calculate total bits needed
    total_bits_needed = 32 + (data_length * 8)
    if total_bits_needed > len(flat_img):
        raise ValueError(f"Corrupted data: need {total_bits_needed} bits, have {len(flat_img)}")
    
    # ✅ OPTIMIZED: Extract all data bits using NumPy (SUPER FAST!)
    data_bits = flat_img[32:total_bits_needed] & 1
    data_bytes_np = np.packbits(data_bits)
    
    # Convert to Python bytes
    data_b64 = data_bytes_np.tobytes().decode('utf-8')
    original_data = base64.b64decode(data_b64)
    
    print(f"[NUMPY EXTRACT] Successfully extracted {len(original_data)} bytes")
    return original_data


# ============================================
# ENCRYPTION FUNCTIONS
# ============================================

def encrypt_message(plaintext_bytes: bytes, key: bytes) -> bytes:
    """Encrypt raw bytes with AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ct_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    return ct_bytes

def decrypt_message(ciphertext_bytes: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt raw bytes with AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext_bytes)
    return unpad(padded, AES.block_size)

def build_combined_payload(text: str, file_path: str = None) -> bytes:
    """Combine text and optional file into single payload."""
    parts = []
    text_bytes = text.encode('utf-8')
    parts.append(struct.pack('>I', len(text_bytes)))
    parts.append(text_bytes)
    
    if file_path and os.path.exists(file_path):
        filename_bytes = os.path.basename(file_path).encode('utf-8')
        parts.append(struct.pack('>H', len(filename_bytes)))
        parts.append(filename_bytes)
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        parts.append(struct.pack('>I', len(file_bytes)))
        parts.append(file_bytes)
    else:
        parts.append(struct.pack('>H', 0))
        parts.append(struct.pack('>I', 0))
    
    return b''.join(parts)

def parse_combined_payload(payload: bytes) -> dict:
    """Parse combined payload back into text and file."""
    offset = 0
    text_len = struct.unpack('>I', payload[offset:offset+4])[0]
    offset += 4
    text = payload[offset:offset+text_len].decode('utf-8')
    offset += text_len
    
    fn_len = struct.unpack('>H', payload[offset:offset+2])[0]
    offset += 2
    filename = payload[offset:offset+fn_len].decode('utf-8') if fn_len > 0 else ""
    offset += fn_len
    
    file_len = struct.unpack('>I', payload[offset:offset+4])[0]
    offset += 4
    file_bytes = payload[offset:offset+file_len] if file_len > 0 else b''
    
    return {'text': text, 'filename': filename, 'file_bytes': file_bytes}


# ============================================
# IMAGE OPTIMIZATION
# ============================================

def optimize_image(image_path: str, max_size=(1920, 1080)) -> str:
    """Optimized with fast compression"""
    import time
    total_start = time.time()
    print(f"[OPTIMIZE] Processing: {image_path}")
    
    try:
        step_start = time.time()
        img = Image.open(image_path)
        print(f"  [TIMING] Open: {time.time() - step_start:.3f}s")
        print(f"  [INFO] Size: {img.size[0]}x{img.size[1]}, mode: {img.mode}")
        
        step_start = time.time()
        if img.mode != 'RGB':
            img = img.convert('RGB')
            print(f"  [TIMING] Convert RGB: {time.time() - step_start:.3f}s")
        
        original_size = img.size
        step_start = time.time()
        if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            print(f"  [TIMING] Resize {original_size} -> {img.size}: {time.time() - step_start:.3f}s")
        
        optimized_path = os.path.splitext(image_path)[0] + '_opt.png'
        step_start = time.time()
        img.save(optimized_path, 'PNG', compress_level=1)  # ✅ Fast compression
        print(f"  [TIMING] Save PNG: {time.time() - step_start:.3f}s")
        
        step_start = time.time()
        if optimized_path != image_path and os.path.exists(image_path):
            os.remove(image_path)
        print(f"  [TIMING] Remove: {time.time() - step_start:.3f}s")
        
        print(f"[OPTIMIZE] Total: {time.time() - total_start:.3f}s")
        print(f"[OPTIMIZE] Saved: {optimized_path}")
        return optimized_path
            
    except Exception as e:
        print(f"[OPTIMIZE ERROR] {e}")
        return image_path


def compute_image_hash(image_path):
    """Compute SHA256 hash of image file."""
    with open(image_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()
    

def analyze_image_risk(image_path):
    """
    Analyzes an image to determine if it's suitable for steganography.
    Returns risk score and recommendations.
    """
    import cv2
    import numpy as np
    from PIL import Image
    
    print(f"[RISK ANALYSIS] Analyzing: {image_path}")
    
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        
        risk_score = 0
        reasons = []
        details = {}
        
        # Resolution check
        width, height = img.size
        total_pixels = width * height
        details['resolution'] = f"{width}x{height}"
        details['total_pixels'] = total_pixels
        
        if total_pixels < 300000:
            risk_score += 35
            reasons.append("❌ Very low resolution - image too small")
        elif total_pixels < 800000:
            risk_score += 20
            reasons.append("⚠️ Low resolution - larger image recommended")
        else:
            reasons.append("✅ Good resolution")
        
        # Color variance
        variance = np.var(img_array)
        details['variance'] = round(variance, 2)
        
        if variance < 500:
            risk_score += 40
            reasons.append("❌ Image too smooth - almost no color variation")
        elif variance < 1500:
            risk_score += 25
            reasons.append("⚠️ Limited color variation - more detail needed")
        elif variance < 3000:
            risk_score += 10
            reasons.append("🟡 Moderate variation - could be better")
        else:
            reasons.append("✅ Excellent color variation")
        
        # Edge density
        if len(img_array.shape) == 3:
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
        else:
            gray = img_array
        
        edges = cv2.Canny(gray, 100, 200)
        edge_pixels = np.count_nonzero(edges)
        edge_density = edge_pixels / edges.size
        details['edge_density'] = round(edge_density, 4)
        
        if edge_density < 0.03:
            risk_score += 30
            reasons.append("❌ Almost no texture - too simple")
        elif edge_density < 0.08:
            risk_score += 20
            reasons.append("⚠️ Low texture - more detail recommended")
        elif edge_density < 0.15:
            risk_score += 5
            reasons.append("🟡 Moderate texture")
        else:
            reasons.append("✅ High texture/detail")
        
        # Final verdict
        details['risk_score'] = risk_score
        
        if risk_score > 60:
            risk_level = "high"
            color = "#dc3545"  # Red
            icon = "🔴"
            message = "⚠️ HIGH DETECTION RISK!"
            recommendation = "This image is NOT safe. Choose a photo with more details, texture, and complexity (like nature photos, busy scenes, or textured surfaces)."
            print(f"  🔴 VERDICT: HIGH RISK")
        elif risk_score > 30:
            risk_level = "medium"
            color = "#ffc107"  # Yellow
            icon = "🟡"
            message = "⚡ MEDIUM RISK"
            recommendation = "This image works but isn't ideal. For better security, choose an image with more texture and detail."
            print(f"  🟡 VERDICT: MEDIUM RISK")
        else:
            risk_level = "low"
            color = "#28a745"  # Green
            icon = "🟢"
            message = "✅ EXCELLENT CHOICE!"
            recommendation = "Perfect! This image has good resolution, color variation, and texture. Low detection risk."
            print(f"  🟢 VERDICT: LOW RISK - EXCELLENT!")
        

        return {
            'risk': risk_level,
            'score': risk_score,
            'color': color,
            'icon': icon,
            'message': message,
            'recommendation': recommendation,
            'reasons': reasons,
            'details': details
        }

        
    except Exception as e:
        print(f"[RISK ANALYSIS ERROR] {e}")
        return {
            'risk': 'unknown',
            'score': 0,
            'color': '#6c757d',
            'icon': '❓',
            'message': 'Could not analyze image',
            'recommendation': 'Proceeding with default settings',
            'reasons': [str(e)],
            'details': {}
        }
    


# ============================================
# TIME-LOCK HELPERS
# ============================================

# Sentinel used as PBKDF2 salt for messages that have NO time-lock.
# Keeps the encrypt/decrypt code-path identical for both cases.
_NO_LOCK_SALT = b'no_time_lock_salt_v1'


def _time_lock_salt(unlock_at):
    """Return the PBKDF2 salt bytes for a message.

    Locked   → canonical ISO-8601 string of the unlock timestamp (naive UTC).
    Unlocked → fixed sentinel so legacy/non-locked messages keep working.
    """
    if unlock_at is None:
        return _NO_LOCK_SALT
    # Strip tz info so sender & receiver always produce the same bytes
    # regardless of whether the datetime object carries tzinfo.
    naive = unlock_at.replace(tzinfo=None) if unlock_at.tzinfo else unlock_at
    return naive.strftime('%Y-%m-%dT%H:%M:%S').encode('utf-8')


def _derive_payload_key(raw_aes_key, unlock_at):
    """Derive the 16-byte AES key actually used to encrypt/decrypt the payload.

    Uses PBKDF2 with the unlock timestamp as the salt.  This means even if
    an attacker extracts both the stego image AND the encrypted key blob
    from the database they still cannot decrypt without knowing the exact
    unlock_at value — defence-in-depth behind the server-side time gate.

    For non-locked messages unlock_at is None → sentinel salt is used →
    derivation is deterministic and the existing payload is decryptable.
    """
    return PBKDF2(raw_aes_key,
                  salt=_time_lock_salt(unlock_at),
                  dkLen=16,
                  count=100_000)


def seconds_until_unlock(unlock_at):
    """Seconds remaining until unlock_at (IST-aware). Negative = already unlocked."""
    # Convert naive datetime to IST timezone-aware datetime
    ist = pytz.timezone('Asia/Kolkata')
    
    # If unlock_at is naive (no timezone), assume it's IST
    if unlock_at.tzinfo is None:
        unlock_at_ist = ist.localize(unlock_at)
    else:
        unlock_at_ist = unlock_at.astimezone(ist)
    
    # Get current time in IST
    now_ist = datetime.datetime.now(ist)
    
    # Calculate remaining seconds
    return (unlock_at_ist - now_ist).total_seconds()



# ============================================
# ROUTES
# ============================================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        dateofbirth = request.form.get('dateofbirth')
        email = request.form.get('email')
       
        if not username or not password or not confirm_password or not dateofbirth or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')
       
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
       
        conn = get_db_connection()
        if not conn:
            return render_template('register.html')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
        if cursor.fetchone():
            flash('Username or email already exists. Please choose different ones.', 'error')
            conn.close()
            return render_template('register.html')
       
        try:
            password_hash = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, dateofbirth, email, password_hash)
                VALUES (%s, %s, %s, %s)
            """, (username, dateofbirth, email, password_hash))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            conn.close()
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Registration failed: {err}. Please try again.', 'error')
            conn.close()
            return render_template('register.html')
   
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
       
        conn = get_db_connection()
        if not conn:
            return render_template('login.html')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username=%s", (username,))
        row = cursor.fetchone()
        conn.close()
       
        if row and check_password_hash(row[1], password):
            user = User(row[0], username)
            login_user(user, remember=remember)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
   
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    current_time = datetime.datetime.now()
    return render_template('dashboard.html', username=current_user.username, current_time=current_time)


@app.route('/terms')
def terms():
    return render_template('terms.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
    username = request.args.get('username')
    if username:
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()
        return jsonify(user) if user else jsonify({})
    else:
        cursor.execute("SELECT username FROM users WHERE username != %s", (current_user.username,))
        users = cursor.fetchall()
        conn.close()
        return jsonify(users)

@app.route('/api/conversations', methods=['GET'])
@login_required
def get_conversations():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
   
    # Get only users who have exchanged messages
    cursor.execute("""
        SELECT DISTINCT 
            CASE 
                WHEN sender = %s THEN receiver 
                ELSE sender 
            END as partner
        FROM messages
        WHERE sender = %s OR receiver = %s
    """, (current_user.username, current_user.username, current_user.username))
    
    partners = [row['partner'] for row in cursor.fetchall()]
   
    conversations = []  # ✅ MISSING - Initialize the list
    
    for partner in partners:  # ✅ MISSING - Loop through each partner
        # Get latest message timestamp
        cursor.execute("""
            SELECT MAX(timestamp) as latest_timestamp
            FROM messages
            WHERE (sender = %s AND receiver = %s) OR (sender = %s AND receiver = %s)
        """, (current_user.username, partner, partner, current_user.username))
        latest = cursor.fetchone()['latest_timestamp']  # ✅ MISSING - Get latest timestamp
       
        # Get last read timestamp
        cursor.execute("SELECT last_read FROM conversation_reads WHERE user = %s AND partner = %s",
                       (current_user.username, partner))
        read_row = cursor.fetchone()
        last_read = read_row['last_read'] if read_row else None
       
        # Count unread messages
        if last_read:
            cursor.execute("""
                SELECT COUNT(*) as unread_count FROM messages
                WHERE sender = %s AND receiver = %s AND timestamp > %s
            """, (partner, current_user.username, last_read))
        else:
            cursor.execute("""
                SELECT COUNT(*) as unread_count FROM messages
                WHERE sender = %s AND receiver = %s
            """, (partner, current_user.username))
        
        unread_count = cursor.fetchone()['unread_count']
       
        conversations.append({
            'username': partner,  # ✅ Changed from 'partner' to 'username'
            'latest_timestamp': latest.isoformat() if latest else None,
            'unread_count': unread_count
        })
   
    conn.close()
    conversations.sort(key=lambda x: x['latest_timestamp'] or '', reverse=True)
    return jsonify(conversations)


@app.route('/api/mark_read', methods=['POST'])
@login_required
def mark_read():
    partner = request.json.get('partner')
    if not partner:
        return jsonify({'error': 'Partner required'}), 400
   
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
   
    cursor.execute("""
        INSERT INTO conversation_reads (user, partner, last_read)
        VALUES (%s, %s, NOW())
        ON DUPLICATE KEY UPDATE last_read = NOW()
    """, (current_user.username, partner))
    
    cursor.execute("""
        UPDATE messages 
        SET read_status = 'read'
        WHERE sender = %s AND receiver = %s AND read_status != 'read'
    """, (partner, current_user.username))
    
    conn.commit()
    conn.close()
   
    return jsonify({'success': True})


@app.route('/api/messages', methods=['GET'])
@login_required
def get_messages():
    try:
        with_user = request.args.get('with')
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
        SELECT id, sender, receiver, content, image_path, aes_key,
               message_hash, image_hash, timestamp, read_status,
               delivered_at, read_at,
               burn_after_view, viewed, unlock_at, screenshot_protect
        FROM messages 
        WHERE (sender = %s AND receiver = %s) OR (sender = %s AND receiver = %s)
        ORDER BY timestamp ASC
    """, (current_user.username, with_user, with_user, current_user.username))
        messages = cursor.fetchall()
        conn.close()
        
        processed_messages = []
        for message in messages:
            msg_dict = dict(message)

            for key in ['aes_key']:
                if msg_dict.get(key) is not None:
                    msg_dict[key] = base64.b64encode(msg_dict[key]).decode('utf-8')

            ts = msg_dict.get('timestamp')
            if ts:
                # Convert timestamp to ISO format string for JavaScript to handle in user's local timezone
                msg_dict['timestamp'] = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)

            # Convert delivered_at timestamp
            delivered_at = msg_dict.get('delivered_at')
            if delivered_at:
                msg_dict['delivered_at'] = delivered_at.isoformat() if hasattr(delivered_at, 'isoformat') else str(delivered_at)
            
            # Convert read_at timestamp
            read_at = msg_dict.get('read_at')
            if read_at:
                msg_dict['read_at'] = read_at.isoformat() if hasattr(read_at, 'isoformat') else str(read_at)

            # ── TIME-LOCK: tell the frontend whether this message is still locked ──
            unlock_at_val = msg_dict.get('unlock_at')
            if unlock_at_val:
                msg_dict['unlock_at'] = unlock_at_val.isoformat() if hasattr(unlock_at_val, 'isoformat') else str(unlock_at_val)
                msg_dict['is_locked'] = seconds_until_unlock(unlock_at_val) > 0

            else:
                msg_dict['unlock_at'] = None
                msg_dict['is_locked'] = False

            read_status = msg_dict.get('read_status', 'sent')
            if msg_dict['sender'] == current_user.username:
                msg_dict['tick_status'] = read_status
            else:
                msg_dict['tick_status'] = 'delivered' if read_status != 'sent' else 'sent'

            processed_messages.append(msg_dict)

        return jsonify(processed_messages)
    except Exception as e:
        print("get_messages error:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        conn = None
        cursor = None
        
        username = request.form.get('username')
        dateofbirth = request.form.get('dateofbirth')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, dateofbirth, email, new_password, confirm_password]):
            flash('All fields are required.', 'error')
            return redirect(url_for('forget_password'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('forget_password'))

        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection failed.', 'error')
                return redirect(url_for('forget_password'))
                
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM users WHERE username=%s AND dateofbirth=%s AND email=%s
            """, (username, dateofbirth, email))
            row = cursor.fetchone()

            if row:
                password_hash = generate_password_hash(new_password)
                cursor.execute("""
                    UPDATE users SET password_hash=%s WHERE id=%s
                """, (password_hash, row[0]))
                conn.commit()
                flash('Password updated successfully. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Incorrect details provided. Please check and try again.', 'error')
                return redirect(url_for('forget_password'))
                
        except Exception as e:
            print(f"Reset Error: {e}")
            flash('An error occurred. Please try again later.', 'error')
            return redirect(url_for('forget_password'))
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    else:
        return render_template('forget.html')


@app.route('/api/send_message', methods=['POST'])
@login_required
def send_message():
    """
    OPTIMIZED MESSAGE SENDING with NumPy LSB - ULTRA FAST!
    """
    import time
    start_time = time.time()
    
    cover_file = request.files.get('cover_image')
    hidden_file = request.files.get('hidden_file')

    print("="*60)
    print("📤 SEND MESSAGE REQUEST")
    print(f"Cover file: {cover_file.filename if cover_file else 'None'}")
    print(f"Hidden file: {hidden_file.filename if hidden_file else 'None'}")
    
    text = request.form.get('message', '').strip()
    recipient = request.form.get('recipient')
    burn_after_view = request.form.get('burn_after_view', 'false').lower() == 'true'
    
    # ✅ SCREENSHOT PROTECTION IS NOW MANDATORY - Always TRUE
    screenshot_protect = True  # FORCED TO TRUE
    print("🛡️ Screenshot protection: ENABLED (mandatory)")
    
    
    # ── TIME-LOCK: parse the optional unlock_at from the form ──────────
    # In your /api/send_message route, when saving unlock_at:
    # ✅ CORRECT - Has colon
    unlock_at = None
    unlock_at_raw = request.form.get('unlock_at', '').strip()
    if unlock_at_raw:
        try:
            # Accept ISO-8601 with or without 'Z' / offset
            unlock_at_raw = unlock_at_raw.replace('Z', '+00:00')
            unlock_at = datetime.datetime.fromisoformat(unlock_at_raw)
            
            # Make naive (DB expects naive DATETIME)
            if unlock_at.tzinfo is not None:
                unlock_at = unlock_at.replace(tzinfo=None)
            
            # Must be future
            if unlock_at <= datetime.datetime.utcnow():
                return jsonify({'error': 'unlock_at must be a future date/time (UTC)'}), 400
            
            print(f"🔒 TIME-LOCK: message unlocks at {unlock_at.isoformat()} UTC")
        except (ValueError, TypeError) as exc:
            return jsonify({'error': f'Invalid unlock_at format: {exc}'}), 400
    # ────────────────────────────────────────────────────────────────────────────

    # ────────────────────────────────────────────────────────────────────

    if not cover_file or not recipient:
        return jsonify({'error': 'Cover image and recipient are required'}), 400

    # Step 1: Save uploaded image
    step_time = time.time()
    unique_filename = f"{uuid.uuid4().hex}_{secure_filename(cover_file.filename)}"
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    cover_file.save(image_path)
    print(f"⏱️  Image save: {time.time() - step_time:.3f}s")

    # Step 2: Optimize image (resize + convert to RGB PNG)
    step_time = time.time()
    try:
        image_path = optimize_image(image_path, app.config['MAX_IMAGE_SIZE'])
    except Exception as e:
        if os.path.exists(image_path):
            os.remove(image_path)
        return jsonify({'error': f'Image optimization failed: {str(e)}'}), 400
    print(f"⏱️  Image optimization: {time.time() - step_time:.3f}s")

    
    risk_analysis = analyze_image_risk(image_path)
    
    # Step 3: Handle hidden file
    attached_path = None
    if hidden_file:
        # Check file size limit
        hidden_file.seek(0, os.SEEK_END)
        file_size = hidden_file.tell()
        hidden_file.seek(0)
        
        if file_size > app.config['MAX_HIDDEN_FILE_SIZE']:
            if os.path.exists(image_path):
                os.remove(image_path)
            return jsonify({'error': f'Hidden file too large. Max size: 500KB'}), 400
        
        att_filename = secure_filename(hidden_file.filename)
        attached_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4().hex}_{att_filename}")
        hidden_file.save(attached_path)
        print(f"📎 Hidden file saved: {file_size/1024:.1f}KB")

    # Step 4: Build and encrypt payload
    step_time = time.time()
    try:
        # Generate per-message AES seed key (random 16 bytes)
        aes_key = get_random_bytes(16)

        # ── Derive the real encryption key (incorporates unlock_at salt) ──
        derived_key = _derive_payload_key(aes_key, unlock_at)

        # Build combined payload (text + optional file)
        main_payload = build_combined_payload(text, attached_path)
        print(f"📦 Payload size: {len(main_payload)/1024:.2f}KB")

        # Encrypt main payload with the DERIVED key
        iv_main = get_random_bytes(16)
        cipher_main = AES.new(derived_key, AES.MODE_CBC, iv_main)
        main_encrypted = cipher_main.encrypt(pad(main_payload, AES.block_size))

        # Encrypt the AES key with fixed secret
        iv_key = get_random_bytes(16)
        cipher_key = AES.new(FIXED_APP_SECRET, AES.MODE_CBC, iv_key)
        encrypted_aes_key = cipher_key.encrypt(pad(aes_key, AES.block_size))

        # Combine: IV_key + enc_key + IV_main + enc_payload
        full_payload_bytes = iv_key + encrypted_aes_key + iv_main + main_encrypted
        print(f"🔐 Encrypted payload size: {len(full_payload_bytes)/1024:.2f}KB")

    except Exception as e:
        if attached_path and os.path.exists(attached_path):
            os.remove(attached_path)
        if image_path and os.path.exists(image_path):
            os.remove(image_path)
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 400
    
    print(f"⏱️  Encryption: {time.time() - step_time:.3f}s")

    # Step 5: Hide encrypted payload in image using NumPy LSB (FAST!)
    step_time = time.time()
    try:
        stego_path = hide_data_in_image_numpy(image_path, full_payload_bytes)
    except Exception as e:
        if attached_path and os.path.exists(attached_path):
            os.remove(attached_path)
        if image_path and os.path.exists(image_path):
            os.remove(image_path)
        return jsonify({'error': f'Steganography failed: {str(e)}'}), 400
    
    print(f"⏱️  NumPy LSB hiding: {time.time() - step_time:.3f}s ⚡")

    # Cleanup temp files
    if attached_path and os.path.exists(attached_path):
        os.remove(attached_path)
    if image_path and os.path.exists(image_path) and image_path != stego_path:
        os.remove(image_path)

    # Step 6: Compute hashes
    step_time = time.time()
    message_hash = hashlib.sha256(text.encode()).hexdigest()
    image_hash = compute_image_hash(stego_path)
    print(f"⏱️  Hashing: {time.time() - step_time:.3f}s")

    # Step 7: Store in database
    step_time = time.time()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (sender, receiver, content, image_path,
                              aes_key, message_hash, image_hash, timestamp,
                              burn_after_view, unlock_at, screenshot_protect)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s)
    ''', (current_user.username, recipient, text, stego_path,
          aes_key, message_hash, image_hash, burn_after_view, unlock_at, screenshot_protect))
    message_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"⏱️  Database: {time.time() - step_time:.3f}s")

    # Step 8: Emit socket events
    socketio.emit('receive_image', {
        'id': message_id,
        'from': current_user.username,
        'image_path': stego_path,
        'timestamp': datetime.datetime.now().isoformat(),
        'readstatus': 'sent',
        'unlock_at': unlock_at.isoformat() if unlock_at else None,
        'is_locked': unlock_at is not None
    }, room=recipient)

    socketio.emit('refresh_conversations', {}, room=current_user.username)
    socketio.emit('refresh_conversations', {}, room=recipient)

    total_time = time.time() - start_time
    print(f"✅ TOTAL TIME: {total_time:.3f}s")
    print("="*60)

    return jsonify({
        'success': True,
        'message_id': message_id,
        'processing_time': round(total_time, 3),
        'unlock_at': unlock_at.isoformat() if unlock_at else None,
        'risk_analysis': risk_analysis   # ← added
    })

@app.route("/api/deadman/config", methods=["GET"])
@login_required
def get_deadman_config():
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT checkin_interval_hours, grace_period_hours, "
        "last_checkin_at, is_active, trusted_contacts_json "
        "FROM deadman_settings WHERE user_id=%s",
        (current_user.id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        # default, not active yet
        row = {
            "checkin_interval_hours": 24,
            "grace_period_hours": 6,
            "last_checkin_at": None,
            "is_active": 0,
            "trusted_contacts_json": "[]",
        }
    return jsonify(row)

@app.route("/api/deadman/config", methods=["POST"])
@login_required
def update_deadman_config():
    data = request.get_json() or {}
    checkin = int(data.get("checkin_interval_hours", 24))
    grace = int(data.get("grace_period_hours", 6))
    is_active = 1 if data.get("is_active") else 0
    contacts = data.get("trusted_contacts", [])

    # Validation
    if checkin < 1 or checkin > 36:
        return jsonify(error="Check-in interval must be between 1 and 36 hours"), 400
    if grace < 1 or grace > 10:
        return jsonify(error="Grace period must be between 1 and 10 hours"), 400
    
    # Enforce maximum total timeline of 36 hours (check-in + grace)
    if checkin + grace > 36:
        return jsonify(error=f"Total timeline (check-in + grace) cannot exceed 36 hours. You entered {checkin + grace} hours."), 400
    
    print(f"💾 Saving Dead Man's Switch config: check-in={checkin}h, grace={grace}h, total={checkin + grace}h, active={is_active}")

    trusted_contacts_json = json.dumps(contacts)

    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO deadman_settings
          (user_id, checkin_interval_hours, grace_period_hours,
           last_checkin_at, is_active, trusted_contacts_json)
        VALUES (%s, %s, %s, NOW(), %s, %s)
        ON DUPLICATE KEY UPDATE
          checkin_interval_hours=VALUES(checkin_interval_hours),
          grace_period_hours=VALUES(grace_period_hours),
          is_active=VALUES(is_active),
          trusted_contacts_json=VALUES(trusted_contacts_json),
          last_checkin_at=NOW()
        """,
        (current_user.id, checkin, grace, is_active, trusted_contacts_json),
    )
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route("/api/deadman/checkin", methods=["POST"])
@login_required
def deadman_checkin():
    """
    User check-in to reset the Dead Man's Switch timer
    Preserves existing logic: Creates default config if not exists, updates last_checkin_at
    """
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    
    cur = conn.cursor()
    
    try:
        # Your original logic: INSERT or UPDATE
        cur.execute(
            """
            INSERT INTO deadman_settings (user_id, last_checkin_at, is_active,
                                          checkin_interval_hours, grace_period_hours,
                                          trusted_contacts_json)
            VALUES (%s, NOW(), 1, 24, 6, '[]')
            ON DUPLICATE KEY UPDATE last_checkin_at=NOW(), is_active=1
            """,
            (current_user.id,),
        )
        
        conn.commit()
        
        # ✅ NEW: Verify the check-in was successful
        rows_affected = cur.rowcount
        
        if rows_affected > 0:
            print(f"✅ Check-in successful for user {current_user.username} at {datetime.datetime.now()}")
            
            # ✅ ENHANCED: Emit socket.io event to update UI in real-time
            socketio.emit("deadman_checkin", {
                "user": current_user.username,
                "timestamp": datetime.datetime.now().isoformat(),
                "message": "Check-in successful"
            }, room=current_user.username)
            
            return jsonify(success=True, message="Check-in successful")
        else:
            print(f"⚠️ Check-in attempt but no rows affected for {current_user.username}")
            return jsonify(success=True, message="Check-in recorded")
    
    except Exception as e:
        conn.rollback()
        print(f"❌ Check-in error for {current_user.username}: {str(e)}")
        return jsonify(error=f"Check-in failed: {str(e)}"), 500
    
    finally:
        # ✅ FIX: Always close cursor before closing connection
        if cur:
            cur.close()
        if conn:
            conn.close()


def compute_deadman_status(row):
    if not row or not row["is_active"] or not row["last_checkin_at"]:
        return {"stage": "INACTIVE", "seconds_to_overdue": None, "seconds_to_emergency": None}

    now = datetime.datetime.now()  # ✅ Changed from utcnow() to now() to match MySQL NOW()
    last = row["last_checkin_at"]
    if last.tzinfo is not None:
        last = last.replace(tzinfo=None)

    checkin_sec = row["checkin_interval_hours"] * 3600
    grace_sec = row["grace_period_hours"] * 3600
    elapsed = (now - last).total_seconds()

    if elapsed < checkin_sec:
        stage = "ACTIVE"
    elif elapsed < checkin_sec + grace_sec:
        stage = "GRACE"   # “Overdue + Grace” combined; frontend can show both
    else:
        stage = "EMERGENCY"

    return {
        "stage": stage,
        "elapsed_seconds": int(elapsed),
        "checkin_seconds": checkin_sec,
        "grace_seconds": grace_sec,
        "seconds_to_overdue": max(0, int(checkin_sec - elapsed)),
        "seconds_to_emergency": max(0, int(checkin_sec + grace_sec - elapsed)),
    }


# ============================================
# DEAD MAN'S SWITCH - EMERGENCY ACTIONS
# ============================================

def send_emergency_alerts(user_id, username, trusted_contacts_json):
    """
    Send first alert to trusted contacts before executing emergency actions
    """
    try:
        if not trusted_contacts_json or trusted_contacts_json == '[]':
            print(f"⚠️ No trusted contacts for user {username}")
            return
        
        contacts = json.loads(trusted_contacts_json)
        
        alert_message = f"""
        🚨 EMERGENCY ALERT 🚨
        
        User: {username}
        Status: Grace period expired - Emergency protocol activated
        Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        All data is being deleted as per Dead Man's Switch protocol.
        """
        
        for contact in contacts:
            print(f"📧 Emergency alert would be sent to: {contact}")
            # TODO: Implement email/SMS notification here
            # send_email(contact, "Dead Man's Switch Alert", alert_message)
            # send_sms(contact, alert_message)
            
    except Exception as e:
        print(f"Error sending emergency alerts: {str(e)}")


def execute_emergency_actions(user_id, username, trusted_contacts_json):
    """
    Emergency protocol: Delete everything from database when grace period expires
    """
    try:
        print(f"\n{'='*60}")
        print(f"🚨 EMERGENCY ALERT: User {username} (ID: {user_id}) grace period expired!")
        print(f"{'='*60}\n")
        
        # 1. FIRST ALERT - Send emergency notifications
        send_emergency_alerts(user_id, username, trusted_contacts_json)
        
        # 2. EMERGENCY ACTIONS - Delete everything from database
        print(f"🔥 EXECUTING EMERGENCY ACTIONS: Deleting all data for user {username}")
        
        conn = get_db_connection()
        if not conn:
            print("❌ Database connection failed for emergency actions")
            return False
        
        cursor = conn.cursor()
        
        # Get all image paths before deletion
        cursor.execute("""
            SELECT DISTINCT image_path 
            FROM messages 
            WHERE sender = %s OR receiver = %s
        """, (username, username))
        image_paths = cursor.fetchall()
        
        # Delete all messages (sent and received)
        cursor.execute("""
            DELETE FROM messages 
            WHERE sender = %s OR receiver = %s
        """, (username, username))
        deleted_messages = cursor.rowcount
        print(f"  ✓ Deleted {deleted_messages} messages")
        
        # Delete conversation reads
        cursor.execute("""
            DELETE FROM conversation_reads 
            WHERE user = %s OR partner = %s
        """, (username, username))
        print(f"  ✓ Deleted conversation history")
        
        # Delete screenshot events
        cursor.execute("""
            DELETE FROM screenshot_events 
            WHERE sender = %s OR receiver = %s
        """, (username, username))
        print(f"  ✓ Deleted screenshot logs")
        
        # Delete user's files/images from storage
        deleted_files = 0
        for (img_path,) in image_paths:
            if img_path and os.path.exists(img_path):
                try:
                    os.remove(img_path)
                    deleted_files += 1
                    print(f"  🗑️ Deleted file: {img_path}")
                except Exception as e:
                    print(f"  ⚠️ Could not delete {img_path}: {e}")
        print(f"  ✓ Deleted {deleted_files} files from disk")
        
        # Delete Dead Man's Switch configuration
        cursor.execute("DELETE FROM deadman_settings WHERE user_id = %s", (user_id,))
        print(f"  ✓ Deleted Dead Man's Switch config")
        
        # Delete user account data (CASCADE will handle related records)
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        print(f"  ✓ Deleted user account")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"\n✅ EMERGENCY PROTOCOL COMPLETE: All data deleted for user {username}")
        print(f"{'='*60}\n")
        
        # Emit SocketIO event to disconnect user
        socketio.emit('force_logout', {
            'reason': 'deadman_switch_activated',
            'message': 'Your Dead Man\'s Switch has been activated. All data has been deleted.'
        }, room=username)
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR in emergency actions: {str(e)}")
        import traceback
        traceback.print_exc()
        if conn:
            conn.rollback()
            conn.close()
        return False


def monitor_deadman_switches():
    """
    Continuously monitor all active Dead Man's Switches
    Check for expired grace periods and trigger emergency actions
    """
    print("🛡️ Dead Man's Switch monitoring thread started")
    
    while True:
        try:
            conn = get_db_connection()
            if not conn:
                print("⚠️ Monitor: DB connection failed, retrying in 60s")
                time.sleep(60)
                continue
            
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT user_id, u.username, last_checkin_at, 
                       checkin_interval_hours, grace_period_hours, 
                       trusted_contacts_json
                FROM deadman_settings ds
                JOIN users u ON ds.user_id = u.id
                WHERE ds.is_active = 1 AND ds.last_checkin_at IS NOT NULL
            """)
            
            active_switches = cursor.fetchall()
            cursor.close()
            conn.close()
            
            if active_switches:
                print(f"⏱️ Monitoring {len(active_switches)} active Dead Man's Switch(es)")
            
            for switch in active_switches:
                user_id = switch['user_id']
                username = switch['username']
                last_checkin = switch['last_checkin_at']
                interval_hours = switch['checkin_interval_hours']
                grace_hours = switch['grace_period_hours']
                trusted_contacts = switch['trusted_contacts_json']
                
                if not last_checkin:
                    continue
                
                # Make naive if it has timezone
                if last_checkin.tzinfo is not None:
                    last_checkin = last_checkin.replace(tzinfo=None)
                
                now = datetime.datetime.utcnow()
                check_in_deadline = last_checkin + datetime.timedelta(hours=interval_hours)
                grace_deadline = check_in_deadline + datetime.timedelta(hours=grace_hours)
                
                elapsed = (now - last_checkin).total_seconds()
                total_deadline_seconds = (interval_hours + grace_hours) * 3600
                
                # Check if grace period has expired
                if elapsed >= total_deadline_seconds:
                    print(f"\n⚠️ GRACE PERIOD EXPIRED for user: {username}")
                    print(f"   Last check-in: {last_checkin}")
                    print(f"   Grace deadline: {grace_deadline}")
                    print(f"   Current time: {now}")
                    print(f"   Elapsed: {elapsed/3600:.2f} hours")
                    
                    # EXECUTE EMERGENCY ACTIONS
                    success = execute_emergency_actions(user_id, username, trusted_contacts)
                    
                    if success:
                        print(f"✅ Emergency protocol completed for {username}")
                    else:
                        print(f"❌ Emergency protocol failed for {username}")
            
            # Check every 60 seconds
            time.sleep(60)
            
        except Exception as e:
            print(f"❌ Error in monitor_deadman_switches: {str(e)}")
            import traceback
            traceback.print_exc()
            time.sleep(60)


# Start monitoring thread when Flask app initializes
monitoring_thread = threading.Thread(target=monitor_deadman_switches, daemon=True)
monitoring_thread.start()
print("✅ Dead Man's Switch monitoring thread initialized")




@app.route("/api/deadman/status", methods=["GET"])
@login_required
def deadman_status():
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT checkin_interval_hours, grace_period_hours, "
        "last_checkin_at, is_active FROM deadman_settings WHERE user_id=%s",
        (current_user.id,),
    )
    row = cur.fetchone()
    conn.close()
    status = compute_deadman_status(row)
    return jsonify(status)


# ────────────────────────────────────────────────────────────────
#  Optional: Add this endpoint to allow frontend preview/analysis
#  before actually sending the message
# ────────────────────────────────────────────────────────────────

@app.route('/api/analyze_image', methods=['POST'])
@login_required
def api_analyze_image():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400
        
        image_file = request.files['image']
        temp_filename = f"temp_analyze_{uuid.uuid4().hex}_{secure_filename(image_file.filename)}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        image_file.save(temp_path)
        
        try:
            optimized_path = optimize_image(temp_path, app.config['MAX_IMAGE_SIZE'])
            risk_analysis = analyze_image_risk(optimized_path)
            
            return jsonify({
                'success': True,
                'analysis': risk_analysis
            })
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            # Also clean optimized version if different
            if 'optimized_path' in locals() and optimized_path != temp_path:
                if os.path.exists(optimized_path):
                    os.remove(optimized_path)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/verify-integrity/<int:message_id>', methods=['POST'])
@login_required
def verify_integrity(message_id):
    """
    SHA-256 integrity check BEFORE decryption.
    Compares stored imagehash with current file hash.
    Returns: { integrity_ok: bool, status: 'verified'|'tampered', message: str }
    """
    conn = get_db_connection()
    if not conn:
        return jsonify(success=False, error="Database connection failed"), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT sender, receiver, image_path, image_hash, integritystatus FROM messages WHERE id = %s",
        (message_id,)
    )
    msg = cursor.fetchone()

    if not msg:
        conn.close()
        return jsonify(success=False, error="Message not found"), 404

    # Authorization check
    if msg['receiver'] != current_user.username and msg['sender'] != current_user.username:
        conn.close()
        return jsonify(success=False, error="Not authorized"), 403

    # If already marked tampered, block immediately (sender sees breach notice too)
    if msg['integritystatus'] == 'tampered':
        conn.close()
        role = 'receiver' if msg['receiver'] == current_user.username else 'sender'
        if role == 'sender':
            return jsonify(
                success=True,
                integrity_ok=False,
                status='tampered',
                role='sender',
                message="⚠️ Security breach detected. Data has been invalidated."
            )
        else:
            return jsonify(
                success=True,
                integrity_ok=False,
                status='tampered',
                role='receiver',
                message="🔴 Integrity check failed. Possible tampering detected."
            )

    imagepath = msg['image_path']
    stored_hash = msg['image_hash']

    if not imagepath or not os.path.exists(imagepath):
        conn.close()
        return jsonify(success=False, error="Image file missing"), 404

    # Re-compute SHA-256 of current stego image file
    current_hash = compute_image_hash(imagepath)

    if current_hash == stored_hash:
        # ✅ Hashes match — image is intact
        cursor.execute(
            "UPDATE messages SET integritystatus = 'verified' WHERE id = %s",
            (message_id,)
        )
        conn.commit()
        conn.close()
        return jsonify(
            success=True,
            integrity_ok=True,
            status='verified',
            message="✅ Integrity verified. Data is safe."
        )
    else:
        # 🔴 Hashes don't match — tampered
        cursor.execute(
            "UPDATE messages SET integritystatus = 'tampered' WHERE id = %s",
            (message_id,)
        )
        conn.commit()
        conn.close()
        socketio.emit('integrity_breach', {
            'id': message_id,
            'message': "⚠️ Security breach detected. Data has been invalidated."
        }, room=msg['sender'])
        return jsonify(
            success=True,
            integrity_ok=False,
            status='tampered',
            role='receiver',
            message="🔴 Integrity check failed. Possible tampering detected."
        )


@app.route('/api/decrypt/<int:message_id>', methods=['POST'])
@login_required
def decrypt_message(message_id):
    """
    Decrypt and retrieve message content with time-lock and burn support
    """
    import time
    start_time = time.time()
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    # Fetch message
    cursor.execute("""SELECT id, sender, receiver, content, 
                   image_path, aes_key, message_hash, image_hash, 
                   integritystatus, timestamp, read_status, 
                   burn_after_view, viewed, 
                   unlock_at FROM messages WHERE id = %s
                   """,(message_id,))
    
    msg = cursor.fetchone()
    
    if not msg:
        conn.close()
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    # Authorization check
    if msg['receiver'] != current_user.username and msg['sender'] != current_user.username:
        conn.close()
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
    
    #--- INTEGRITY GUARD (add this block) ---
    if msg['integritystatus'] == 'tampered':
        conn.close()
        return jsonify(
            success=False,
            error="Integrity check failed. Decryption blocked. This data has been invalidated.",
            integrity_failed=True
        ), 403
    # --- END INTEGRITY GUARD ---
    
    # ✅ CHECK IF IMAGE FILE EXISTS BEFORE PROCEEDING
    image_path = msg['image_path']
    if not image_path or not os.path.exists(image_path):
        conn.close()
        return jsonify({
            'success': False, 
            'error': f'Image file missing: {image_path}'
        }), 404
    
    # ── TIME-LOCK GATE ─────────────────────────────────────────────────
    unlock_at = msg['unlock_at']  # datetime or None
    if unlock_at is not None:
        # Check if message is still locked
        remaining = seconds_until_unlock(unlock_at)
        if remaining > 0:
            conn.close()
            print(f"⏳ Message {message_id} still locked: {remaining:.1f}s remaining")
            return jsonify({
                "success": False,
                "locked": True,
                "unlock_at": unlock_at.isoformat(),
                "seconds_remaining": round(remaining, 1),
                "error": "Message is time-locked and cannot be opened yet."
            }), 423  # 423 Locked
    # ────────────────────────────────────────────────────────────────────
    
    # ✅ Check burn/expiration BEFORE decrypting (for ALL messages)
    if msg['burn_after_view'] and msg['viewed']:
        conn.close()
        return jsonify({'success': False, 'error': 'Sorry, message expired'}), 410
    
    # ✅ Decrypt using NumPy LSB (FAST!) - for ALL messages
    try:
        print(f"🔓 DECRYPTING MESSAGE {message_id}")
        
        # Extract payload using NumPy
        step_time = time.time()
        extracted_bytes = extract_data_from_image_numpy(image_path)
        print(f"⏱️ NumPy LSB extraction: {time.time() - step_time:.3f}s ⚡")
        
        if len(extracted_bytes) < 80:
            raise ValueError("Extracted data too short")
        
        # Parse encrypted payload
        offset = 0
        iv_key = extracted_bytes[offset:offset+16]
        offset += 16
        encrypted_aes_key = extracted_bytes[offset:offset+32]
        offset += 32
        iv_main = extracted_bytes[offset:offset+16]
        offset += 16
        main_encrypted = extracted_bytes[offset:]
        
        # Decrypt the AES seed key from the blob
        step_time = time.time()
        cipher_key = AES.new(FIXED_APP_SECRET, AES.MODE_CBC, iv_key)
        aes_key_padded = cipher_key.decrypt(encrypted_aes_key)
        aes_key = unpad(aes_key_padded, AES.block_size)
        
        # ── Derive the payload key using the same unlock_at salt ────────
        derived_key = _derive_payload_key(aes_key, unlock_at)
        
        # Decrypt the main payload with the derived key
        cipher_main = AES.new(derived_key, AES.MODE_CBC, iv_main)
        main_payload_padded = cipher_main.decrypt(main_encrypted)
        main_payload = unpad(main_payload_padded, AES.block_size)
        print(f"⏱️ Decryption: {time.time() - step_time:.3f}s")
        
        # Parse combined payload
        parsed = parse_combined_payload(main_payload)
        
        result = {
            'success': True,
            'message': parsed['text'],
            'filename': parsed['filename'],
            'burn_after_view': msg['burn_after_view'],  # Tell frontend if this is a burn message
            'is_burnable': False  # Will be set to True if this is first view
        }
        
        # Save extracted file if present
        if parsed['filename'] and parsed['file_bytes']:
            saved_filename = f"extracted_{uuid.uuid4().hex}_{parsed['filename']}"
            saved_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            with open(saved_path, 'wb') as f:
                f.write(parsed['file_bytes'])
            result['download_url'] = url_for('download_extracted', filename=saved_filename)
            result['has_file'] = True
        
        # Mark as viewed if burn_after_view (so next access triggers the burn check)
        if msg['burn_after_view'] and msg['receiver'] == current_user.username:
            if not msg['viewed']:  # First time viewing
                cursor.execute("UPDATE messages SET viewed = TRUE WHERE id = %s", (message_id,))
                conn.commit()
                result['is_burnable'] = True  # Frontend should auto-burn on modal close
                print(f"🔥 BURN AFTER VIEW: Message {message_id} marked as viewed, will burn on modal close")
            else:
                result['is_burnable'] = False
        
        conn.close()
        
        total_time = time.time() - start_time
        print(f"✅ DECRYPTION TOTAL TIME: {total_time:.3f}s")
        
        return jsonify(result)
        
    except FileNotFoundError as e:
        conn.close()
        print(f"❌ FILE NOT FOUND: {e}")
        return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'}), 404
        
    except Exception as e:
        conn.close()
        print(f"❌ DECRYPT ERROR: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'}), 400

@app.route('/api/lock_status/<int:message_id>', methods=['GET'])
@login_required
def lock_status(message_id):
    """Lightweight polling endpoint.  The frontend calls this every few
    seconds for any locked message so it can show a live countdown.
    The instant the clock hits zero we also push a 'message_unlocked'
    SocketIO event so the UI can react without waiting for the next poll.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database error'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT unlock_at FROM messages
        WHERE id = %s AND (sender = %s OR receiver = %s)
    """, (message_id, current_user.username, current_user.username))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Message not found'}), 404

    unlock_at = row['unlock_at']

    # Not a time-locked message at all
    if unlock_at is None:
        return jsonify({'locked': False, 'unlock_at': None, 'seconds_remaining': 0})

    remaining = seconds_until_unlock(unlock_at)

    if remaining <= 0:
        # Just crossed the threshold — push a real-time nudge so the UI
        # reacts immediately instead of waiting for the next poll.
        socketio.emit('message_unlocked', {
            'id': message_id,
            'unlock_at': unlock_at.isoformat()
        }, room=current_user.username)
        return jsonify({'locked': False, 'unlock_at': unlock_at.isoformat(), 'seconds_remaining': 0})

    return jsonify({
        'locked': True,
        'unlock_at': unlock_at.isoformat(),
        'seconds_remaining': round(remaining, 1)
    })


@app.route('/api/burn_message/<int:message_id>', methods=['POST'])
@login_required
def burn_message(message_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'DB error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT sender, receiver, image_path, burn_after_view 
        FROM messages WHERE id = %s
    """, (message_id,))
    msg = cursor.fetchone()
    
    if not msg:
        conn.close()
        return jsonify({'success': False, 'error': 'Not authorized or not burnable'}), 403

    cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
    conn.commit()
    
    if msg['image_path'] and os.path.exists(msg['image_path']):
        try:
            os.remove(msg['image_path'])
        except:
            pass
    
    conn.close()

    socketio.emit('message_deleted', {'id': message_id}, room=msg['sender'])
    socketio.emit('message_deleted', {'id': message_id}, room=msg['receiver'])

    return jsonify({'success': True})




@app.route('/api/confirm_burn/<int:message_id>', methods=['POST'])
@login_required
def confirm_burn(message_id):
    """
    Burn After View: Delete message when receiver closes the decrypt modal
    This is called automatically when the modal is closed after viewing a burn_after_view message
    Deletes the message and cover image for BOTH sender and receiver
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    # Fetch message details
    cursor.execute("""
        SELECT id, sender, receiver, image_path, burn_after_view, viewed
        FROM messages 
        WHERE id = %s
    """, (message_id,))
    
    msg = cursor.fetchone()
    
    if not msg:
        conn.close()
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    # Authorization: only receiver can burn (or sender can view their sent message)
    if msg['receiver'] != current_user.username and msg['sender'] != current_user.username:
        conn.close()
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
    
    # Only delete if it's actually a burn_after_view message that has been viewed
    if not msg['burn_after_view']:
        conn.close()
        return jsonify({'success': False, 'error': 'Not a burn after view message'}), 400
    
    # Delete the message from database
    cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
    conn.commit()
    
    # Delete the image file from disk
    if msg['image_path'] and os.path.exists(msg['image_path']):
        try:
            os.remove(msg['image_path'])
            print(f"🔥 BURNED: Deleted image file: {msg['image_path']}")
        except Exception as e:
            print(f"⚠️ Failed to delete image file: {e}")
    
    conn.close()
    
    # Emit SocketIO event to BOTH sender and receiver to remove the message from their UI
    socketio.emit('message_deleted', {
        'id': message_id,
        'reason': 'burn_after_view'
    }, room=msg['sender'])
    
    socketio.emit('message_deleted', {
        'id': message_id,
        'reason': 'burn_after_view'
    }, room=msg['receiver'])
    
    print(f"🔥 BURNED: Message {message_id} deleted for both {msg['sender']} and {msg['receiver']}")
    
    return jsonify({'success': True, 'message': 'Message burned successfully'})
@app.route('/downloads/extracted/<filename>')
@login_required
def download_extracted(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        return "File not found", 404
    return send_file(path, as_attachment=True)

## 4. Create Screenshot Destruction Endpoint:

@app.route('/api/screenshot_destruct/<int:message_id>', methods=['POST'])
@login_required
def screenshot_destruct(message_id):
    """
    Self-destruct message when screenshot is detected.
    Immediately deletes message from database and notifies sender.
    """
    try:
        data = request.get_json()
        reason = data.get('reason', 'Unknown')
        user_agent = data.get('user_agent', 'Unknown')

        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        cursor = conn.cursor(dictionary=True)

        # Fetch message details
        cursor.execute("""
            SELECT id, sender, receiver, image_path, screenshot_protect
            FROM messages 
            WHERE id = %s
        """, (message_id,))

        msg = cursor.fetchone()

        if not msg:
            conn.close()
            return jsonify({'success': False, 'error': 'Message not found'}), 404

        # Authorization: only receiver or sender can trigger
        if msg['receiver'] != current_user.username and msg['sender'] != current_user.username:
            conn.close()
            return jsonify({'success': False, 'error': 'Not authorized'}), 403

        # Check if message has screenshot protection enabled
        if not msg['screenshot_protect']:
            conn.close()
            return jsonify({'success': False, 'error': 'Message not screenshot-protected'}), 400

        # Log the screenshot event
        cursor.execute("""
            INSERT INTO screenshot_events 
            (message_id, detected_by, sender, receiver, detection_reason, user_agent, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, (message_id, current_user.username, msg['sender'], msg['receiver'], reason, user_agent))

        # Delete the message permanently
        cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
        conn.commit()

        # Delete the image file
        if msg['image_path'] and os.path.exists(msg['image_path']):
            try:
                os.remove(msg['image_path'])
                print(f"🗑️ Deleted stego image: {msg['image_path']}")
            except Exception as e:
                print(f"Warning: Could not delete image file: {e}")

        conn.close()

        # Emit real-time notifications via SocketIO
        socketio.emit('message_deleted', {
            'id': message_id,
            'reason': 'screenshot_detected'
        }, room=msg['sender'])

        socketio.emit('message_deleted', {
            'id': message_id,
            'reason': 'screenshot_detected'
        }, room=msg['receiver'])

        # Send special notification to sender
        socketio.emit('screenshot_alert', {
            'message_id': message_id,
            'detected_by': current_user.username,
            'reason': reason,
            'timestamp': datetime.datetime.now().isoformat()
        }, room=msg['sender'])

        print(f"💥 MESSAGE {message_id} SELF-DESTRUCTED - Screenshot by {current_user.username}")
        print(f"   Reason: {reason}")
        print(f"   Sender: {msg['sender']} (notified)")
        print(f"   Receiver: {msg['receiver']}")

        return jsonify({
            'success': True,
            'message': 'Message self-destructed successfully',
            'sender_notified': True
        })

    except Exception as e:
        print(f"❌ Screenshot destruct error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

## 5. Add Screenshot Events History Endpoint (optional):
    
@app.route('/api/screenshot_events', methods=['GET'])
@login_required
def get_screenshot_events():
    """
    Get screenshot detection history for the current user's messages.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)

    # Get events where user is either sender or receiver
    cursor.execute("""
        SELECT id, message_id, detected_by, sender, receiver, 
               detection_reason, timestamp
        FROM screenshot_events
        WHERE sender = %s OR receiver = %s
        ORDER BY timestamp DESC
        LIMIT 50
    """, (current_user.username, current_user.username))

    events = cursor.fetchall()
    conn.close()

    # Format timestamps
    for event in events:
        if event.get('timestamp'):
            event['timestamp'] = event['timestamp'].isoformat()

    return jsonify(events)

    
# ============================================
# SOCKETIO EVENTS
# ============================================

@socketio.on('connect')
def on_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('join')
def on_join(data):
    username = data['username']
    join_room(username)
    emit('user_status', {'username': username, 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        emit('user_status', {
            'username': current_user.username,
            'status': 'offline'
        }, broadcast=True)

@socketio.on('heartbeat')
def on_heartbeat():
    if current_user.is_authenticated:
        emit('user_status', {
            'username': current_user.username,
            'status': 'online'
        }, broadcast=True)

@socketio.on('typing_start')
def handle_typing_start(data):
    recipient = data['to']
    emit('user_typing', {'from': current_user.username}, room=recipient)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    recipient = data['to']
    emit('user_stop_typing', {'from': current_user.username}, room=recipient)

@socketio.on('mark_chat_read')
def on_mark_chat_read(data):
    partner = data.get('partner')
    if not partner or not current_user.is_authenticated:
        return
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE messages SET read_status = 'read', read_at = CURRENT_TIMESTAMP
            WHERE sender = %s AND receiver = %s AND read_status != 'read'
        """, (partner, current_user.username))
        conn.commit()
        
        cursor.execute("""
            SELECT id, read_status FROM messages 
            WHERE sender = %s AND receiver = %s 
            ORDER BY timestamp DESC LIMIT 5
        """, (partner, current_user.username))
        recent_msgs = [{'id': row[0], 'read_status': row[1]} for row in cursor.fetchall()]
        
        emit('read_receipt_update', {
            'partner': current_user.username,
            'messages': recent_msgs,
            'read_status': 'read'
        }, room=partner)
    finally:
        cursor.close()
        conn.close()

@socketio.on('join_chat')
def on_join_chat(data):
    partner = data.get('partner')
    if not partner or not current_user.is_authenticated:
        return
    join_room(partner)
    
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE messages SET read_status = 'delivered', delivered_at = CURRENT_TIMESTAMP
            WHERE sender = %s AND receiver = %s AND read_status = 'sent'
        """, (partner, current_user.username))
        conn.commit()
        
        cursor.execute("""
            SELECT id, sender, image_path, timestamp, read_status 
            FROM messages 
            WHERE (sender = %s AND receiver = %s) OR (sender = %s AND receiver = %s)
            ORDER BY timestamp DESC LIMIT 1
        """, (current_user.username, partner, partner, current_user.username))
        latest = cursor.fetchone()
        if latest:
            emit('new_message_update', {
                'id': latest[0],
                'sender': latest[1],
                'image_path': latest[2],
                'timestamp': latest[3].isoformat() if latest[3] else None,
                'read_status': latest[4]
            }, room=partner)
    finally:
        cursor.close()
        conn.close()


@app.route('/api/delete_message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()
   
    cursor.execute("SELECT sender, image_path FROM messages WHERE id=%s", (message_id,))
    row = cursor.fetchone()
   
    if not row:
        cursor.close(); conn.close()
        return jsonify({'success': False, 'message': 'Message not found'})

    sender, image_path = row
    if sender != current_user.username:
        cursor.close(); conn.close()
        return jsonify({'success': False, 'message': 'Not authorized'}), 403

    cursor.execute("DELETE FROM messages WHERE id=%s", (message_id,))
    conn.commit()
    cursor.close(); conn.close()

    if image_path and os.path.exists(image_path):
        os.remove(image_path)

    return jsonify({'success': True})


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route('/api/get_messages')
@login_required
def get_user_messages():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, sender as sender, image_path, timestamp FROM messages WHERE receiver = %s ORDER BY timestamp DESC", (current_user.username,))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({'messages': messages})

## 7. Add SocketIO handler for screenshot alerts:

@socketio.on('screenshot_alert_ack')
def handle_screenshot_alert_ack(data):
    """
    Handle acknowledgment from sender that they received screenshot alert.
    """
    message_id = data.get('message_id')
    print(f"📬 Sender acknowledged screenshot alert for message {message_id}")
    
    
 ##8 Add Force Logout SocketIO Handler
 
@socketio.on('deadman_force_disconnect')
def handle_deadman_disconnect():
    """
    Handle force disconnect when Dead Man's Switch is activated
    """
    if current_user.is_authenticated:
        print(f"🔌 Force disconnecting user {current_user.username} (Dead Man's Switch)")
        logout_user()
    
# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    init_db()
    print("="*60)
    print("Server starting at http://127.0.0.1:5000")
    print("="*60 + "\n")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)