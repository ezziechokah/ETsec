import cv2
import numpy as np
import sqlite3
import os
from datetime import datetime, timedelta
import hashlib
import math
import json
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
from flask_socketio import SocketIO, emit
import threading
import time

app = Flask(__name__)
app.secret_key = 'etsec_secure_key_2024'
app.config['SECRET_KEY'] = 'etsec_secret'
socketio = SocketIO(app)

class ETSecuritySystem:
    def __init__(self):
        # Use OpenCV's face detector
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.profile_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_profileface.xml')
        
        self.known_faces = {}  # name -> list of face templates
        self.blacklisted_names = set()
        
        # Multi-camera support
        self.cameras = {}  # camera_id -> {'source': source, 'status': 'active/disabled', 'name': name, 'type': 'usb/ip/phone'}
        self.camera_status = {}
        self.camera_threads = {}
        self.camera_feeds = {}
        
        self.failed_attempts = {}
        self.lockout_until = {}
        self.intruder_cooldown = {}  # Per camera cooldown
        
        # Create directories
        os.makedirs('captures', exist_ok=True)
        os.makedirs('templates', exist_ok=True)
        os.makedirs('static', exist_ok=True)
        os.makedirs('alerts', exist_ok=True)
        
        self.init_database()
        self.load_data()
        self.discover_cameras()
        
    def init_database(self):
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                     (id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, success INTEGER, ip_address TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS known_faces
                     (id INTEGER PRIMARY KEY, name TEXT, templates BLOB, registered_date TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS blacklisted_faces
                     (id INTEGER PRIMARY KEY, name TEXT, templates BLOB, blacklisted_date TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS interactions
                     (id INTEGER PRIMARY KEY, timestamp TEXT, name TEXT, status TEXT, image_path TEXT, distance REAL, camera_id TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS cameras
                     (id INTEGER PRIMARY KEY, camera_id TEXT, name TEXT, source TEXT, type TEXT, status TEXT, added_date TEXT)''')
        
        # Create admin user
        hashed_pw = hashlib.sha256('ezzietech'.encode()).hexdigest()
        c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', hashed_pw, 'admin'))
        
        conn.commit()
        conn.close()
    
    def discover_cameras(self):
        """Auto-discover available cameras"""
        self.cameras = {}
        
        # Check for USB/webcams (0, 1, 2, etc.)
        for i in range(5):  # Check first 5 camera indices
            try:
                cap = cv2.VideoCapture(i)
                if cap.isOpened():
                    camera_id = f"cam_{i}"
                    self.cameras[camera_id] = {
                        'source': i,
                        'status': 'active',
                        'name': f"Camera {i}",
                        'type': 'usb'
                    }
                    self.camera_status[camera_id] = 'active'
                    cap.release()
            except:
                pass
        
        # If no cameras found, add a default message
        if not self.cameras:
            print("No cameras detected. Please connect cameras via Iriun or USB.")
        
        # Load saved cameras from database
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        c.execute("SELECT camera_id, name, source, type, status FROM cameras")
        for row in c.fetchall():
            if row[0] not in self.cameras:
                self.cameras[row[0]] = {
                    'source': row[2],
                    'status': row[4],
                    'name': row[1],
                    'type': row[3]
                }
                self.camera_status[row[0]] = row[4]
        conn.close()
    
    def add_camera(self, camera_id, source, name, camera_type='usb'):
        """Add a new camera to the system"""
        self.cameras[camera_id] = {
            'source': source,
            'status': 'active',
            'name': name,
            'type': camera_type
        }
        self.camera_status[camera_id] = 'active'
        
        # Save to database
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO cameras (camera_id, name, source, type, status, added_date) VALUES (?, ?, ?, ?, ?, ?)",
                  (camera_id, name, str(source), camera_type, 'active', datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return True
    
    def remove_camera(self, camera_id):
        """Remove a camera from the system"""
        if camera_id in self.cameras:
            del self.cameras[camera_id]
            del self.camera_status[camera_id]
            
            # Remove from database
            conn = sqlite3.connect('etsec.db')
            c = conn.cursor()
            c.execute("DELETE FROM cameras WHERE camera_id=?", (camera_id,))
            conn.commit()
            conn.close()
            return True
        return False
    
    def toggle_camera(self, camera_id):
        """Enable or disable a camera"""
        if camera_id in self.cameras:
            if self.camera_status[camera_id] == 'active':
                self.camera_status[camera_id] = 'disabled'
                self.cameras[camera_id]['status'] = 'disabled'
            else:
                self.camera_status[camera_id] = 'active'
                self.cameras[camera_id]['status'] = 'active'
            
            # Update database
            conn = sqlite3.connect('etsec.db')
            c = conn.cursor()
            c.execute("UPDATE cameras SET status=? WHERE camera_id=?", 
                     (self.camera_status[camera_id], camera_id))
            conn.commit()
            conn.close()
            return True
        return False
    
    def load_data(self):
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        
        # Load known faces
        c.execute("SELECT name, templates FROM known_faces")
        for name, templates_blob in c.fetchall():
            import pickle
            self.known_faces[name] = pickle.loads(templates_blob)
        
        conn.close()
    
    def extract_face_features(self, face_img):
        """Extract features from face image for comparison"""
        resized = cv2.resize(face_img, (100, 100))
        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
        gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        magnitude = np.sqrt(gx**2 + gy**2)
        features = magnitude.flatten()
        return features
    
    def compare_faces(self, face1_features, face2_features):
        """Compare two face feature vectors"""
        if len(face1_features) != len(face2_features):
            return 1.0
        distance = np.linalg.norm(face1_features - face2_features)
        similarity = 1.0 / (1.0 + distance / 1000)
        return similarity
    
    def register_face(self, name, face_img, camera_id):
        """Register a new face in the system"""
        features = self.extract_face_features(face_img)
        
        if name not in self.known_faces:
            self.known_faces[name] = []
        
        self.known_faces[name].append(features)
        
        # Save to database
        import pickle
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        c.execute("INSERT INTO known_faces (name, templates, registered_date) VALUES (?, ?, ?)",
                  (name, pickle.dumps(self.known_faces[name]), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        # Save the face image
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = f"captures/registered_{name}_{timestamp}.jpg"
        cv2.imwrite(image_path, face_img)
        
        return True
    
    def recognize_face(self, face_img):
        """Recognize a face from image"""
        if not self.known_faces:
            return None, 1.0
        
        features = self.extract_face_features(face_img)
        best_match = None
        best_similarity = 0
        
        for name, templates in self.known_faces.items():
            for template in templates:
                similarity = self.compare_faces(features, template)
                if similarity > best_similarity and similarity > 0.45:
                    best_similarity = similarity
                    best_match = name
        
        if best_match and best_match in self.blacklisted_names:
            return f"BLACKLISTED_{best_match}", best_similarity
        
        return best_match, best_similarity
    
    def calculate_distance(self, face_width, frame_width):
        """Estimate distance based on face size"""
        if face_width == 0:
            return 10.0
        distance = (0.15 * frame_width) / (2 * face_width * math.tan(math.radians(30)))
        return min(10.0, max(0.5, distance))
    
    def save_interaction(self, name, status, image_path, distance, camera_id):
        conn = sqlite3.connect('etsec.db')
        c = conn.cursor()
        c.execute("INSERT INTO interactions (timestamp, name, status, image_path, distance, camera_id) VALUES (?, ?, ?, ?, ?, ?)",
                  (datetime.now().isoformat(), name, status, image_path, distance, camera_id))
        conn.commit()
        conn.close()
    
    def send_whatsapp_alert(self, phone_number, image_path, person_name, camera_id):
        """Send alert with camera info"""
        alert_file = f"alerts/alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(alert_file, 'w') as f:
            f.write(f"INTRUSION ALERT!\n")
            f.write(f"Camera: {camera_id}\n")
            f.write(f"Person: {person_name}\n")
            f.write(f"Time: {datetime.now()}\n")
            f.write(f"Image: {image_path}\n")
            f.write(f"WhatsApp Number: {phone_number}\n")
            f.write(f"\nPlease send this image to {phone_number} on WhatsApp\n")
        
        print(f"\n[ALERT] Camera {camera_id}: Intrusion detected! Check {alert_file}")
        return True
    
    def process_frame(self, frame, camera_id):
        """Process a single frame for face detection and recognition"""
        if self.camera_status.get(camera_id) != 'active':
            return frame
        
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 5, minSize=(60, 60))
        
        for (x, y, w, h) in faces:
            distance = self.calculate_distance(w, frame.shape[1])
            face_roi = frame[y:y+h, x:x+w]
            person_name, confidence = self.recognize_face(face_roi)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            image_filename = f"captures/{camera_id}_{timestamp}.jpg"
            cv2.imwrite(image_filename, face_roi)
            
            # Per-camera cooldown tracking
            if camera_id not in self.intruder_cooldown:
                self.intruder_cooldown[camera_id] = {}
            
            if person_name and not person_name.startswith("BLACKLISTED"):
                color = (0, 255, 0)
                label = f"Welcome {person_name}! ({distance:.1f}m)"
                self.save_interaction(person_name, "ACCESS_GRANTED", image_filename, distance, camera_id)
                
            elif person_name and person_name.startswith("BLACKLISTED"):
                actual_name = person_name.replace("BLACKLISTED_", "")
                if distance < 2.0:
                    color = (0, 0, 255)
                    label = f"ALARM! {actual_name} - INTRUDER!"
                    
                    last_alert = self.intruder_cooldown[camera_id].get('last_alert')
                    if not last_alert or (datetime.now() - last_alert).seconds > 30:
                        self.send_whatsapp_alert("+255759105607", image_filename, actual_name, camera_id)
                        self.intruder_cooldown[camera_id]['last_alert'] = datetime.now()
                        self.save_interaction(actual_name, "INTRUSION_ALERT", image_filename, distance, camera_id)
                else:
                    color = (0, 0, 255)
                    label = f"{actual_name} - ACCESS DENIED (Stay {distance:.1f}m away)"
                    self.save_interaction(actual_name, "ACCESS_DENIED", image_filename, distance, camera_id)
            else:
                if distance < 2.0:
                    color = (0, 0, 255)
                    label = "ALARM! UNKNOWN INTRUDER!"
                    
                    last_alert = self.intruder_cooldown[camera_id].get('last_alert')
                    if not last_alert or (datetime.now() - last_alert).seconds > 30:
                        self.send_whatsapp_alert("+255759105607", image_filename, "UNKNOWN_PERSON", camera_id)
                        self.intruder_cooldown[camera_id]['last_alert'] = datetime.now()
                        self.save_interaction("UNKNOWN", "INTRUSION_ALERT", image_filename, distance, camera_id)
                else:
                    color = (0, 0, 255)
                    label = f"UNKNOWN - ACCESS DENIED (Stay {distance:.1f}m away)"
                    self.save_interaction("UNKNOWN", "ACCESS_DENIED", image_filename, distance, camera_id)
            
            cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)
            cv2.putText(frame, label, (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
            cv2.putText(frame, f"Cam: {camera_id}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        return frame

# Initialize system
et_system = ETSecuritySystem()

# HTML Template for Multi-Camera Dashboard
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ETsec Multi-Camera Security System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .status { color: #27ae60; margin-top: 10px; }
        .camera-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; }
        .camera-card { background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .camera-header { background: #2c3e50; color: white; padding: 15px; display: flex; justify-content: space-between; align-items: center; }
        .camera-name { font-weight: bold; font-size: 16px; }
        .camera-feed { width: 100%; height: 400px; background: #000; object-fit: cover; }
        .status-badge { padding: 5px 10px; border-radius: 5px; font-size: 12px; font-weight: bold; }
        .status-active { background: #27ae60; }
        .status-disabled { background: #e74c3c; }
        .btn { padding: 5px 15px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; margin: 0 5px; }
        .btn-on { background: #27ae60; color: white; }
        .btn-off { background: #e74c3c; color: white; }
        .btn-danger { background: #c0392b; color: white; }
        .section { background: white; border-radius: 10px; padding: 20px; margin-top: 20px; }
        .nav-tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab { padding: 10px 20px; background: #ecf0f1; cursor: pointer; border-radius: 5px; }
        .tab.active { background: #3498db; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .add-camera-form { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
        .add-camera-form input, .add-camera-form select { padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .btn-primary { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ETsec Multi-Camera Security System</h1>
            <p class="status">System Active | {{ camera_count }} Camera(s) Online</p>
        </div>
        
        <div class="nav-tabs">
            <div class="tab active" onclick="showTab('cameras')">Live Cameras</div>
            <div class="tab" onclick="showTab('addcam')">Add Camera</div>
            <div class="tab" onclick="showTab('faces')">Face Management</div>
            <div class="tab" onclick="showTab('logs')">Activity Logs</div>
            <div class="tab" onclick="showTab('guide')">System Guide</div>
        </div>
        
        <!-- Cameras Tab -->
        <div id="cameras-tab" class="tab-content active">
            <div class="camera-grid" id="cameraGrid">
                {% for cam_id, cam_info in cameras.items() %}
                <div class="camera-card">
                    <div class="camera-header">
                        <span class="camera-name">{{ cam_info.name }}</span>
                        <span class="status-badge {{ 'status-active' if camera_status[cam_id] == 'active' else 'status-disabled' }}">
                            {{ 'ACTIVE' if camera_status[cam_id] == 'active' else 'DISABLED' }}
                        </span>
                        <div>
                            <button class="btn {{ 'btn-off' if camera_status[cam_id] == 'active' else 'btn-on' }}" 
                                    onclick="toggleCamera('{{ cam_id }}')">
                                {{ 'Turn Off' if camera_status[cam_id] == 'active' else 'Turn On' }}
                            </button>
                            <button class="btn btn-danger" onclick="removeCamera('{{ cam_id }}')">Remove</button>
                        </div>
                    </div>
                    <img id="feed-{{ cam_id }}" class="camera-feed" src="/video_feed/{{ cam_id }}" alt="Camera Feed">
                </div>
                {% endfor %}
            </div>
            {% if cameras|length == 0 %}
            <div class="section">
                <p>No cameras detected. Please add cameras using the "Add Camera" tab.</p>
                <p>For Iriun phone cameras: They appear as regular USB cameras (Camera 0, 1, 2, etc.)</p>
            </div>
            {% endif %}
        </div>
        
        <!-- Add Camera Tab -->
        <div id="addcam-tab" class="tab-content">
            <div class="section">
                <h3>Add New Camera</h3>
                <div class="add-camera-form">
                    <input type="text" id="camName" placeholder="Camera Name (e.g., Front Door)">
                    <select id="camSource">
                        <option value="0">Camera 0 (USB/Webcam)</option>
                        <option value="1">Camera 1</option>
                        <option value="2">Camera 2</option>
                        <option value="3">Camera 3</option>
                        <option value="4">Camera 4</option>
                    </select>
                    <select id="camType">
                        <option value="usb">USB Camera</option>
                        <option value="phone">Phone (Iriun)</option>
                        <option value="ip">IP Camera</option>
                    </select>
                    <button class="btn-primary" onclick="addCamera()">Add Camera</button>
                </div>
                <div id="addCamResult"></div>
                
                <h3 style="margin-top: 30px;">Camera Setup Guide</h3>
                <h4>For Phone Cameras (Iriun):</h4>
                <ol>
                    <li>Install Iriun Webcam app on your phone (Google Play/App Store)</li>
                    <li>Install Iriun Webcam on your laptop from iriun.com</li>
                    <li>Connect both devices to the same WiFi network</li>
                    <li>Open Iriun on both devices</li>
                    <li>Your phone will appear as Camera 0, 1, or 2 in the system</li>
                    <li>Add it using the form above with the correct camera number</li>
                </ol>
                
                <h4>For Multiple Phones:</h4>
                <p>You can connect multiple phones simultaneously. Each phone will appear as a different camera number. Add each one separately.</p>
            </div>
        </div>
        
        <!-- Face Management Tab -->
        <div id="faces-tab" class="tab-content">
            <div class="section">
                <h3>Register New Person</h3>
                <select id="registerCamera" style="width: 100%; padding: 10px; margin: 10px 0;">
                    {% for cam_id, cam_info in cameras.items() %}
                    <option value="{{ cam_id }}">{{ cam_info.name }}</option>
                    {% endfor %}
                </select>
                <input type="text" id="personName" placeholder="Person's Full Name" style="width: 100%; padding: 10px; margin: 10px 0;">
                <button class="btn-primary" onclick="registerFace()">Capture & Register Face</button>
                <div id="registerResult"></div>
            </div>
            <div class="section">
                <h3>Registered People ({{ known_faces_count }})</h3>
                <div id="knownPeopleList"></div>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div id="logs-tab" class="tab-content">
            <div class="section">
                <h3>Recent Interactions</h3>
                <table style="width: 100%;">
                    <thead>
                        <tr><th>Time</th><th>Camera</th><th>Person</th><th>Status</th><th>Distance</th></tr>
                    </thead>
                    <tbody id="interactionsBody"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Guide Tab -->
        <div id="guide-tab" class="tab-content">
            <div class="section">
                <h3>ETsec Multi-Camera System Guide</h3>
                
                <h4>Adding Multiple Cameras:</h4>
                <ul>
                    <li><strong>USB Cameras:</strong> Plug in and they will be auto-detected</li>
                    <li><strong>Phone Cameras (Iriun):</strong> Connect via WiFi, they appear as USB cameras</li>
                    <li><strong>IP Cameras:</strong> Add using RTSP URL (e.g., rtsp://ip:port/stream)</li>
                    <li><strong>Up to 10 cameras</strong> can be added simultaneously</li>
                </ul>
                
                <h4>For Different Locations:</h4>
                <ul>
                    <li><strong>Homes:</strong> Front door, back door, garage</li>
                    <li><strong>Offices:</strong> Main entrance, reception, server room</li>
                    <li><strong>Retail:</strong> Entrance, checkout, storage areas</li>
                    <li><strong>Warehouses:</strong> Loading dock, entry gates, restricted zones</li>
                </ul>
                
                <h4>Camera Management:</h4>
                <ul>
                    <li>Each camera operates independently</li>
                    <li>Enable/disable cameras individually</li>
                    <li>Each camera has its own alert cooldown</li>
                    <li>All cameras log to the same database</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tabBtn => {
                tabBtn.classList.remove('active');
            });
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        function toggleCamera(cameraId) {
            fetch('/api/toggle_camera', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({camera_id: cameraId})
            }).then(() => {
                location.reload();
            });
        }
        
        function removeCamera(cameraId) {
            if(confirm('Are you sure you want to remove this camera?')) {
                fetch('/api/remove_camera', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({camera_id: cameraId})
                }).then(() => {
                    location.reload();
                });
            }
        }
        
        function addCamera() {
            const name = document.getElementById('camName').value;
            const source = document.getElementById('camSource').value;
            const type = document.getElementById('camType').value;
            
            if(!name) {
                alert('Please enter a camera name');
                return;
            }
            
            fetch('/api/add_camera', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, source: source, type: type})
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    document.getElementById('addCamResult').innerHTML = '<div class="alert alert-success">Camera added successfully!</div>';
                    setTimeout(() => location.reload(), 1500);
                } else {
                    document.getElementById('addCamResult').innerHTML = '<div class="alert alert-error">Failed to add camera</div>';
                }
            });
        }
        
        function registerFace() {
            const cameraId = document.getElementById('registerCamera').value;
            const name = document.getElementById('personName').value;
            
            if(!name) {
                alert('Please enter a name');
                return;
            }
            
            fetch('/api/register_face', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({camera_id: cameraId, name: name})
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    document.getElementById('registerResult').innerHTML = '<div class="alert alert-success">Face registered successfully!</div>';
                    document.getElementById('personName').value = '';
                    loadLogs();
                } else {
                    document.getElementById('registerResult').innerHTML = '<div class="alert alert-error">Registration failed. Make sure face is visible.</div>';
                }
            });
        }
        
        function loadLogs() {
            fetch('/api/get_logs')
                .then(res => res.json())
                .then(data => {
                    const tbody = document.getElementById('interactionsBody');
                    tbody.innerHTML = '';
                    data.logs.forEach(log => {
                        tbody.innerHTML += `
                            <tr>
                                <td>${log.timestamp}</td>
                                <td>${log.camera_id || 'N/A'}</td>
                                <td>${log.name}</td>
                                <td>${log.status}</td>
                                <td>${log.distance ? log.distance.toFixed(2) + 'm' : 'N/A'}</td>
                            </tr>
                        `;
                    });
                });
        }
        
        // Auto-refresh
        setInterval(loadLogs, 5000);
        loadLogs();
    </script>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>ETsec Login</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-form { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.2); width: 350px; }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #2980b9; }
        .error { color: red; text-align: center; margin-top: 10px; }
        .logo { text-align: center; font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-form">
        <div class="logo">[ETsec]</div>
        <h2>ETsec Security System</h2>
        <form id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Login</button>
            <div id="errorMsg" class="error"></div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').onsubmit = async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const response = await fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            const data = await response.json();
            
            if(data.success) {
                window.location.href = '/dashboard';
            } else {
                document.getElementById('errorMsg').innerText = data.message;
            }
        };
    </script>
</body>
</html>
'''

# Save templates
with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(DASHBOARD_HTML)
with open('templates/login.html', 'w', encoding='utf-8') as f:
    f.write(LOGIN_HTML)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    current_time = datetime.now()
    
    if username in et_system.lockout_until:
        if current_time < et_system.lockout_until[username]:
            return jsonify({'success': False, 'message': 'Account locked. Try again later.'})
        else:
            del et_system.lockout_until[username]
            et_system.failed_attempts[username] = 0
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('etsec.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
    user = c.fetchone()
    conn.close()
    
    if user:
        et_system.failed_attempts[username] = 0
        session['logged_in'] = True
        return jsonify({'success': True})
    else:
        et_system.failed_attempts[username] = et_system.failed_attempts.get(username, 0) + 1
        attempts = et_system.failed_attempts[username]
        
        if attempts >= 3:
            if attempts == 3:
                et_system.lockout_until[username] = current_time + timedelta(minutes=1)
                msg = "Too many failed attempts. Locked for 1 minute."
            else:
                et_system.lockout_until[username] = current_time + timedelta(hours=24)
                msg = "Too many failed attempts. Locked for 24 hours."
        else:
            msg = f"Invalid credentials. {3-attempts} attempts remaining."
        
        return jsonify({'success': False, 'message': msg})

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html', 
                         cameras=et_system.cameras,
                         camera_status=et_system.camera_status,
                         camera_count=len(et_system.cameras),
                         known_faces_count=len(et_system.known_faces))

@app.route('/video_feed/<camera_id>')
def video_feed(camera_id):
    """Generate video feed from specific camera"""
    def generate():
        if camera_id not in et_system.cameras:
            return
        
        source = et_system.cameras[camera_id]['source']
        try:
            if isinstance(source, int):
                cap = cv2.VideoCapture(source)
            else:
                cap = cv2.VideoCapture(source)
            
            while True:
                if et_system.camera_status.get(camera_id) != 'active':
                    # Show offline message
                    frame = np.zeros((480, 640, 3), dtype=np.uint8)
                    cv2.putText(frame, f"Camera {camera_id} - DISABLED", (50, 240), 
                               cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                    ret, buffer = cv2.imencode('.jpg', frame)
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
                    time.sleep(0.1)
                    continue
                
                success, frame = cap.read()
                if not success:
                    break
                
                # Process frame for face detection
                frame = et_system.process_frame(frame, camera_id)
                
                # Encode to JPEG
                ret, buffer = cv2.imencode('.jpg', frame)
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            
            cap.release()
        except Exception as e:
            print(f"Error with camera {camera_id}: {e}")
    
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/add_camera', methods=['POST'])
def add_camera():
    if not session.get('logged_in'):
        return jsonify({'success': False})
    
    name = request.json.get('name')
    source = request.json.get('source')
    cam_type = request.json.get('type')
    
    # Convert source to int if it's a number
    try:
        source = int(source)
    except:
        pass
    
    camera_id = f"cam_{len(et_system.cameras)}_{name.replace(' ', '_')}"
    success = et_system.add_camera(camera_id, source, name, cam_type)
    
    return jsonify({'success': success})

@app.route('/api/remove_camera', methods=['POST'])
def remove_camera():
    if not session.get('logged_in'):
        return jsonify({'success': False})
    
    camera_id = request.json.get('camera_id')
    success = et_system.remove_camera(camera_id)
    return jsonify({'success': success})

@app.route('/api/toggle_camera', methods=['POST'])
def toggle_camera():
    if not session.get('logged_in'):
        return jsonify({'success': False})
    
    camera_id = request.json.get('camera_id')
    success = et_system.toggle_camera(camera_id)
    return jsonify({'success': success})

@app.route('/api/register_face', methods=['POST'])
def register_face():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    camera_id = request.json.get('camera_id')
    name = request.json.get('name')
    
    if camera_id not in et_system.cameras:
        return jsonify({'success': False, 'message': 'Camera not found'})
    
    source = et_system.cameras[camera_id]['source']
    cap = cv2.VideoCapture(source)
    ret, frame = cap.read()
    cap.release()
    
    if ret:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = et_system.face_cascade.detectMultiScale(gray, 1.1, 5)
        
        if len(faces) > 0:
            x, y, w, h = faces[0]
            face_roi = frame[y:y+h, x:x+w]
            success = et_system.register_face(name, face_roi, camera_id)
            if success:
                return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/api/get_logs')
def get_logs():
    conn = sqlite3.connect('etsec.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, camera_id, name, status, distance FROM interactions ORDER BY timestamp DESC LIMIT 100")
    logs = [{'timestamp': row[0], 'camera_id': row[1], 'name': row[2], 'status': row[3], 'distance': row[4]} for row in c.fetchall()]
    conn.close()
    return jsonify({'logs': logs})

@app.route('/api/status')
def status():
    return jsonify({
        'known_faces': len(et_system.known_faces),
        'cameras': et_system.camera_status,
        'camera_count': len(et_system.cameras)
    })

if __name__ == '__main__':
    print("="*60)
    print("ETsec Multi-Camera Security System Starting...")
    print("="*60)
    print("\nSystem Ready!")
    print("\nACCESS DASHBOARD:")
    print("   URL: http://localhost:5000")
    print("   Username: admin")
    print("   Password: ezzietech")
    print("\nMULTI-CAMERA SETUP:")
    print("   1. Install Iriun Webcam on laptop and phones")
    print("   2. Connect all devices to same WiFi")
    print("   3. Each phone becomes a separate camera")
    print("   4. Use 'Add Camera' tab to add each phone")
    print("\nCurrent Cameras Detected:", len(et_system.cameras))
    for cam_id, cam_info in et_system.cameras.items():
        print(f"   - {cam_info['name']} (Source: {cam_info['source']})")
    print("\nPress Ctrl+C to stop the system")
    print("="*60)
    
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)