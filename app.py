from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
import base64
import hashlib
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
ENCRYPTION_PASSWORD = os.environ.get('ENCRYPTION_PASSWORD', 'sreaty-tv-encryption-key')

class StreamEncryption:
    def __init__(self, password: str):
        self.password = password.encode()
        
    def _get_fernet(self, salt: bytes) -> Fernet:
        """Generate Fernet cipher with given salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return Fernet(key)
    
    def encrypt_link(self, original_link: str) -> str:
        """Encrypt M3U8 link with timestamp and salt"""
        try:
            # Add timestamp for expiration (24 hours)
            expiry = datetime.now() + timedelta(hours=24)
            
            # Create data structure
            data = {
                'link': original_link,
                'expiry': expiry.isoformat(),
                'created': datetime.now().isoformat()
            }
            
            # Generate random salt
            salt = secrets.token_bytes(16)
            
            # Encrypt data
            fernet = self._get_fernet(salt)
            encrypted_data = fernet.encrypt(json.dumps(data).encode())
            
            # Combine salt + encrypted data and encode
            combined = salt + encrypted_data
            encrypted_link = base64.urlsafe_b64encode(combined).decode()
            
            logger.info(f"Link encrypted successfully. Expires: {expiry}")
            return encrypted_link
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    def decrypt_link(self, encrypted_link: str) -> str:
        """Decrypt M3U8 link and validate expiration"""
        try:
            # Decode the encrypted link
            combined = base64.urlsafe_b64decode(encrypted_link.encode())
            
            # Extract salt and encrypted data
            salt = combined[:16]
            encrypted_data = combined[16:]
            
            # Decrypt data
            fernet = self._get_fernet(salt)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Parse data
            data = json.loads(decrypted_data.decode())
            
            # Check expiration
            expiry = datetime.fromisoformat(data['expiry'])
            if datetime.now() > expiry:
                raise ValueError("Link has expired")
            
            logger.info("Link decrypted successfully")
            return data['link']
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

# Initialize encryption handler
encryption_handler = StreamEncryption(ENCRYPTION_PASSWORD)

# Store for rate limiting (in production, use Redis)
request_cache = {}

def rate_limit_check(ip: str, limit: int = 10, window: int = 60) -> bool:
    """Simple rate limiting"""
    now = datetime.now()
    
    if ip not in request_cache:
        request_cache[ip] = []
    
    # Remove old requests
    request_cache[ip] = [req_time for req_time in request_cache[ip] 
                        if now - req_time < timedelta(seconds=window)]
    
    # Check limit
    if len(request_cache[ip]) >= limit:
        return False
    
    # Add current request
    request_cache[ip].append(now)
    return True

@app.route('/')
def index():
    """Serve the main HTML page"""
    # In production, serve from static files
    with open('sreaty_tv.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content

@app.route('/api/encrypt', methods=['POST'])
def encrypt_link():
    """Admin endpoint to encrypt M3U8 links"""
    try:
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip, limit=5, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        
        if not data or 'original_link' not in data:
            return jsonify({'error': 'Missing original_link parameter'}), 400
        
        original_link = data['original_link'].strip()
        
        # Validate M3U8 link format
        if not original_link.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid link format'}), 400
        
        if not (original_link.endswith('.m3u8') or 'm3u8' in original_link):
            return jsonify({'error': 'Link must be a valid M3U8 stream'}), 400
        
        # Encrypt the link
        encrypted_link = encryption_handler.encrypt_link(original_link)
        
        logger.info(f"Link encrypted for IP: {client_ip}")
        
        return jsonify({
            'success': True,
            'encrypted_link': encrypted_link,
            'expires_in_hours': 24
        })
        
    except Exception as e:
        logger.error(f"Encryption API error: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_link():
    """Decrypt M3U8 links for streaming"""
    try:
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip, limit=20, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        
        if not data or 'encrypted_link' not in data:
            return jsonify({'error': 'Missing encrypted_link parameter'}), 400
        
        encrypted_link = data['encrypted_link'].strip()
        quality = data.get('quality', 'auto')
        
        # Decrypt the link
        decrypted_link = encryption_handler.decrypt_link(encrypted_link)
        
        logger.info(f"Link decrypted for IP: {client_ip}, Quality: {quality}")
        
        return jsonify({
            'success': True,
            'decrypted_link': decrypted_link,
            'quality': quality
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Decryption API error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'Sreaty TV Backend'
    })

@app.route('/admin')
def admin_panel():
    """Admin panel for link management"""
    admin_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sreaty TV - Admin Panel</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 800px; 
                margin: 0 auto; 
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 { color: #333; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input[type="text"], textarea { 
                width: 100%; 
                padding: 10px; 
                border: 1px solid #ddd; 
                border-radius: 5px;
                font-size: 16px;
            }
            button { 
                background: #007bff; 
                color: white; 
                padding: 12px 24px; 
                border: none; 
                border-radius: 5px; 
                cursor: pointer;
                font-size: 16px;
            }
            button:hover { background: #0056b3; }
            .result { 
                margin-top: 20px; 
                padding: 15px; 
                background: #f8f9fa; 
                border-radius: 5px; 
                border-left: 4px solid #007bff;
            }
            .error { border-left-color: #dc3545; background: #f8d7da; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Sreaty TV Admin Panel</h1>
            
            <div class="form-group">
                <label for="originalLink">M3U8 Stream Link:</label>
                <input type="text" id="originalLink" placeholder="https://example.com/stream.m3u8">
            </div>
            
            <button onclick="encryptLink()">Encrypt Link</button>
            
            <div id="result"></div>
        </div>

        <script>
            async function encryptLink() {
                const link = document.getElementById('originalLink').value.trim();
                const resultDiv = document.getElementById('result');
                
                if (!link) {
                    resultDiv.innerHTML = '<div class="result error">Please enter a valid M3U8 link</div>';
                    return;
                }
                
                try {
                    const response = await fetch('/api/encrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ original_link: link })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        resultDiv.innerHTML = `
                            <div class="result">
                                <h3>✅ Link Encrypted Successfully!</h3>
                                <p><strong>Encrypted Link:</strong></p>
                                <textarea readonly style="height: 100px;">${data.encrypted_link}</textarea>
                                <p><small>⏰ Expires in ${data.expires_in_hours} hours</small></p>
                            </div>
                        `;
                    } else {
                        resultDiv.innerHTML = `<div class="result error">❌ ${data.error}</div>`;
                    }
                } catch (error) {
                    resultDiv.innerHTML = `<div class="result error">❌ Network error: ${error.message}</div>`;
                }
            }
            
            document.getElementById('originalLink').addEventListener('keyup', function(e) {
                if (e.key === 'Enter') encryptLink();
            });
        </script>
    </body>
    </html>
    """
    return admin_html

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500
port = int(os.environ.get('PORT', 5000))
if __name__ == '__main__':
    # Create HTML file for serving
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sreaty TV - Live Streaming</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #fff;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 20px 0;
        }

        .logo {
            font-size: 3rem;
            font-weight: bold;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .tagline {
            font-size: 1.2rem;
            opacity: 0.8;
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 30px;
        }

        .controls-panel {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .video-container {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            min-height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #fff;
        }

        .form-control {
            width: 100%;
            padding: 12px 16px;
            border: none;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            font-size: 16px;
            backdrop-filter: blur(5px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s ease;
        }

        .form-control:focus {
            outline: none;
            background: rgba(255, 255, 255, 0.2);
            border-color: #4ecdc4;
            box-shadow: 0 0 20px rgba(78, 205, 196, 0.3);
        }

        .form-control::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }

        .quality-selector {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .quality-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            cursor: pointer;
            transition: all 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .quality-btn:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-2px);
        }

        .quality-btn.active {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            box-shadow: 0 5px 15px rgba(78, 205, 196, 0.4);
        }

        .stream-btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            color: #fff;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 20px;
        }

        .stream-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(78, 205, 196, 0.4);
        }

        .stream-btn:active {
            transform: translateY(-1px);
        }

        #videoPlayer {
            width: 100%;
            height: 100%;
            border-radius: 15px;
            background: #000;
        }

        .video-placeholder {
            text-align: center;
            color: rgba(255, 255, 255, 0.6);
        }

        .video-placeholder i {
            font-size: 4rem;
            margin-bottom: 20px;
            display: block;
        }

        .admin-panel {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            margin-top: 30px;
        }

        .admin-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }

        .admin-toggle {
            background: none;
            border: 1px solid rgba(255, 255, 255, 0.3);
            color: #fff;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .admin-toggle:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .admin-content {
            display: none;
        }

        .admin-content.active {
            display: block;
        }

        .encrypted-link {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
            word-break: break-all;
            font-family: monospace;
        }

        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .logo {
                font-size: 2rem;
            }
            
            .quality-selector {
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">SREATY TV</div>
            <div class="tagline">By: Mohamed Alsariti</div>
        </div>

        <div class="main-content">
            <div class="controls-panel">
                <div class="form-group">
                    <label for="streamLink">Stream Link (M3U8)</label>
                    <input type="text" id="streamLink" class="form-control" placeholder="Enter encrypted stream link...">
                </div>

                <div class="form-group">
                    <label>Quality Settings</label>
                    <div class="quality-selector">
                        <button class="quality-btn active" data-quality="auto">Auto</button>
                        <button class="quality-btn" data-quality="1080p">1080p</button>
                        <button class="quality-btn" data-quality="720p">720p</button>
                        <button class="quality-btn" data-quality="480p">480p</button>
                        <button class="quality-btn" data-quality="360p">360p</button>
                    </div>
                </div>

                <button class="stream-btn" onclick="startStream()">
                    🎬 Start Streaming
                </button>
            </div>

            <div class="video-container">
                <div class="video-placeholder" id="placeholder">
                    <span style="font-size: 4rem;">📺</span>
                    <h3>Ready to Stream</h3>
                    <p>Enter your encrypted link and click start streaming</p>
                </div>
                <video id="videoPlayer" controls style="display: none;"></video>
            </div>
        </div>

    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.4.10/hls.min.js"></script>
    <script>
        let currentQuality = 'auto';
        let hls = null;

        // Quality selector functionality
        document.querySelectorAll('.quality-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.quality-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentQuality = this.dataset.quality;
            });
        });

        // Start streaming function
        async function startStream() {
            const streamLink = document.getElementById('streamLink').value.trim();
            
            if (!streamLink) {
                alert('Please enter a stream link');
                return;
            }

            try {
                // Decrypt the link first
                const decryptedLink = await decryptLink(streamLink);
                
                if (!decryptedLink) {
                    alert('Invalid or corrupted stream link');
                    return;
                }

                const video = document.getElementById('videoPlayer');
                const placeholder = document.getElementById('placeholder');
                
                // Show video player
                placeholder.style.display = 'none';
                video.style.display = 'block';

                // Initialize HLS player
                if (Hls.isSupported()) {
                    if (hls) {
                        hls.destroy();
                    }
                    
                    hls = new Hls({
                        enableWorker: true,
                        lowLatencyMode: true,
                        backBufferLength: 90
                    });
                    
                    hls.loadSource(decryptedLink);
                    hls.attachMedia(video);
                    
                    hls.on(Hls.Events.MANIFEST_PARSED, function() {
                        console.log('Stream loaded successfully');
                        video.play();
                    });

                    hls.on(Hls.Events.ERROR, function(event, data) {
                        console.error('HLS Error:', data);
                        alert('Error loading stream: ' + data.details);
                    });
                    
                } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                    video.src = decryptedLink;
                    video.addEventListener('loadedmetadata', function() {
                        video.play();
                    });
                } else {
                    alert('Your browser does not support HLS streaming');
                }
                
            } catch (error) {
                console.error('Streaming error:', error);
                alert('Failed to start stream: ' + error.message);
            }
        }

        // Decrypt link function (communicates with backend)
        async function decryptLink(encryptedLink) {
            try {
                const response = await fetch('/api/decrypt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        encrypted_link: encryptedLink,
                        quality: currentQuality
                    })
                });

                if (!response.ok) {
                    throw new Error('Decryption failed');
                }

                const data = await response.json();
                return data.decrypted_link;
            } catch (error) {
                console.error('Decryption error:', error);
                return null;
            }
        }

        // Admin panel toggle
        function toggleAdmin() {
            const adminContent = document.getElementById('adminContent');
            adminContent.classList.toggle('active');
        }

        // Encrypt link function (for admin)
        async function encryptLink() {
            const originalLink = document.getElementById('originalLink').value.trim();
            
            if (!originalLink) {
                alert('Please enter an original M3U8 link');
                return;
            }

            try {
                const response = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        original_link: originalLink
                    })
                });

                if (!response.ok) {
                    throw new Error('Encryption failed');
                }

                const data = await response.json();
                
                // Display encrypted result
                const resultDiv = document.getElementById('encryptedResult');
                resultDiv.innerHTML = `
                    <div class="encrypted-link">
                        <strong>Encrypted Link:</strong><br>
                        ${data.encrypted_link}
                    </div>
                `;
                
            } catch (error) {
                console.error('Encryption error:', error);
                alert('Failed to encrypt link: ' + error.message);
            }
        }

        // Handle Enter key in input fields
        document.getElementById('streamLink').addEventListener('keyup', function(event) {
            if (event.key === 'Enter') {
                startStream();
            }
        });

        document.getElementById('originalLink').addEventListener('keyup', function(event) {
            if (event.key === 'Enter') {
                encryptLink();
            }
        });
    </script>
</body>
</html>"""
    
    with open('sreaty_tv.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("🚀 Starting Sreaty TV Server...")
    print("📺 Main site: http://localhost:5000")
    print("🔐 Admin panel: http://localhost:5000/admin")
    print("📡 API endpoints: /api/encrypt, /api/decrypt")
    
    app.run(debug=False, host='0.0.0.0', port=port)
