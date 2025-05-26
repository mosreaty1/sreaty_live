from flask import Flask, request, jsonify, Response, render_template_string
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
import requests
import re
from urllib.parse import urljoin, urlparse, quote_plus, unquote_plus
import traceback

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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
    """Serve a simple test page with debugging info"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sreaty TV Debug</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; max-width: 800px; }
            h1 { color: #333; }
            .form-group { margin: 20px 0; }
            input, button { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; }
            input[type="text"] { width: 500px; }
            button { background: #007bff; color: white; cursor: pointer; }
            .result { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; word-break: break-all; }
            .error { background: #f8d7da; color: #721c24; }
            .debug { background: #e2e3e5; color: #383d41; font-family: monospace; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Sreaty TV Debug Panel</h1>
            
            <div class="form-group">
                <h3>1. Test Direct M3U8 URL</h3>
                <input type="text" id="directUrl" placeholder="Enter M3U8 URL to test directly">
                <button onclick="testDirect()">Test Direct</button>
            </div>
            
            <div class="form-group">
                <h3>2. Test Through Proxy</h3>
                <input type="text" id="proxyUrl" placeholder="Enter M3U8 URL to test through proxy">
                <button onclick="testProxy()">Test Proxy</button>
            </div>
            
            <div class="form-group">
                <h3>3. Encrypt Link</h3>
                <input type="text" id="encryptUrl" placeholder="Enter M3U8 URL to encrypt">
                <button onclick="encryptTest()">Encrypt</button>
            </div>
            
            <div class="form-group">
                <h3>4. Test Full Flow</h3>
                <input type="text" id="fullTestUrl" placeholder="Enter M3U8 URL for full test">
                <button onclick="fullTest()">Full Test</button>
            </div>
            
            <div id="result"></div>
        </div>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.4.10/hls.min.js"></script>
        <script>
            function showResult(content, isError = false) {
                const resultDiv = document.getElementById('result');
                resultDiv.innerHTML = `<div class="result ${isError ? 'error' : ''}">${content}</div>`;
            }
            
            function showDebug(content) {
                const resultDiv = document.getElementById('result');
                resultDiv.innerHTML += `<div class="result debug">${content}</div>`;
            }

            async function testDirect() {
                const url = document.getElementById('directUrl').value.trim();
                if (!url) return;
                
                showResult('Testing direct M3U8 access...');
                
                try {
                    const response = await fetch(url, { method: 'GET' });
                    showDebug(`Direct fetch status: ${response.status}`);
                    
                    if (response.ok) {
                        const text = await response.text();
                        showResult(`✅ Direct access works!<br>Status: ${response.status}<br>Content preview: ${text.substring(0, 200)}...`);
                    } else {
                        showResult(`❌ Direct access failed: ${response.status} ${response.statusText}`, true);
                    }
                } catch (error) {
                    showResult(`❌ Direct access error: ${error.message}`, true);
                }
            }

            async function testProxy() {
                const url = document.getElementById('proxyUrl').value.trim();
                if (!url) return;
                
                showResult('Testing proxy access...');
                
                try {
                    const proxyUrl = `/proxy?url=${encodeURIComponent(url)}`;
                    showDebug(`Proxy URL: ${proxyUrl}`);
                    
                    const response = await fetch(proxyUrl);
                    showDebug(`Proxy fetch status: ${response.status}`);
                    
                    if (response.ok) {
                        const text = await response.text();
                        showResult(`✅ Proxy access works!<br>Status: ${response.status}<br>Content preview: ${text.substring(0, 200)}...`);
                    } else {
                        const errorText = await response.text();
                        showResult(`❌ Proxy access failed: ${response.status}<br>Error: ${errorText}`, true);
                    }
                } catch (error) {
                    showResult(`❌ Proxy access error: ${error.message}`, true);
                }
            }

            async function encryptTest() {
                const url = document.getElementById('encryptUrl').value.trim();
                if (!url) return;
                
                try {
                    const response = await fetch('/api/encrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ original_link: url })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        showResult(`✅ Encryption successful!<br>Encrypted: ${data.encrypted_link}`);
                    } else {
                        showResult(`❌ Encryption failed: ${data.error}`, true);
                    }
                } catch (error) {
                    showResult(`❌ Encryption error: ${error.message}`, true);
                }
            }

            async function fullTest() {
                const url = document.getElementById('fullTestUrl').value.trim();
                if (!url) return;
                
                showResult('Starting full test flow...');
                
                try {
                    // Step 1: Encrypt
                    showDebug('Step 1: Encrypting URL...');
                    const encryptResponse = await fetch('/api/encrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ original_link: url })
                    });
                    
                    const encryptData = await encryptResponse.json();
                    if (!encryptData.success) {
                        throw new Error(`Encryption failed: ${encryptData.error}`);
                    }
                    
                    showDebug(`Encrypted link: ${encryptData.encrypted_link.substring(0, 50)}...`);
                    
                    // Step 2: Decrypt to get proxy URL
                    showDebug('Step 2: Decrypting to get proxy URL...');
                    const decryptResponse = await fetch('/api/decrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ encrypted_link: encryptData.encrypted_link })
                    });
                    
                    const decryptData = await decryptResponse.json();
                    if (!decryptData.success) {
                        throw new Error(`Decryption failed: ${decryptData.error}`);
                    }
                    
                    showDebug(`Proxy URL: ${decryptData.decrypted_link}`);
                    
                    // Step 3: Test HLS.js with proxy URL
                    showDebug('Step 3: Testing with HLS.js...');
                    
                    if (Hls.isSupported()) {
                        const hls = new Hls({
                            debug: true,
                            enableWorker: false
                        });
                        
                        hls.on(Hls.Events.MANIFEST_PARSED, function() {
                            showResult('✅ Full test successful! HLS manifest loaded.', false);
                            hls.destroy();
                        });
                        
                        hls.on(Hls.Events.ERROR, function(event, data) {
                            showResult(`❌ HLS Error: ${data.type} - ${data.details}`, true);
                            hls.destroy();
                        });
                        
                        hls.loadSource(decryptData.decrypted_link);
                    } else {
                        showResult('❌ HLS.js not supported in this browser', true);
                    }
                    
                } catch (error) {
                    showResult(`❌ Full test error: ${error.message}`, true);
                }
            }
        </script>
    </body>
    </html>
    """
    return html

@app.route('/api/encrypt', methods=['POST'])
def encrypt_link():
    """Admin endpoint to encrypt M3U8 links"""
    try:
        logger.info("=== ENCRYPT REQUEST ===")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Request data: {request.get_data()}")
        
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"Client IP: {client_ip}")
        
        if not rate_limit_check(client_ip, limit=10, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        logger.info(f"Parsed JSON: {data}")
        
        if not data or 'original_link' not in data:
            return jsonify({'error': 'Missing original_link parameter'}), 400
        
        original_link = data['original_link'].strip()
        logger.info(f"Original link: {original_link}")
        
        # Validate M3U8 link format
        if not original_link.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid link format'}), 400
        
        if not (original_link.endswith('.m3u8') or 'm3u8' in original_link):
            return jsonify({'error': 'Link must be a valid M3U8 stream'}), 400
        
        # Encrypt the link
        encrypted_link = encryption_handler.encrypt_link(original_link)
        logger.info(f"Encrypted link generated: {encrypted_link[:50]}...")
        
        result = {
            'success': True,
            'encrypted_link': encrypted_link,
            'expires_in_hours': 24
        }
        logger.info(f"Returning: {result}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Encryption API error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_link():
    """Decrypt M3U8 links and return proxy URL"""
    try:
        logger.info("=== DECRYPT REQUEST ===")
        logger.info(f"Request headers: {dict(request.headers)}")
        
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"Client IP: {client_ip}")
        
        if not rate_limit_check(client_ip, limit=20, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        logger.info(f"Decrypt request data: {data}")
        
        if not data or 'encrypted_link' not in data:
            return jsonify({'error': 'Missing encrypted_link parameter'}), 400
        
        encrypted_link = data['encrypted_link'].strip()
        quality = data.get('quality', 'auto')
        
        # Decrypt the link
        original_link = encryption_handler.decrypt_link(encrypted_link)
        logger.info(f"Decrypted original link: {original_link}")
        
        # Return proxy URL instead of original link
        proxy_base = request.url_root.rstrip('/')
        encoded_link = quote_plus(original_link)
        proxy_url = f"{proxy_base}/proxy?url={encoded_link}"
        
        logger.info(f"Generated proxy URL: {proxy_url}")
        
        result = {
            'success': True,
            'decrypted_link': proxy_url,
            'quality': quality
        }
        logger.info(f"Returning decrypt result: {result}")
        return jsonify(result)
        
    except ValueError as e:
        logger.error(f"Decryption validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Decryption API error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/proxy', methods=['GET', 'OPTIONS'])
def proxy():
    """
    Proxy M3U8 files and video segments with detailed logging
    """
    try:
        logger.info("=== PROXY REQUEST ===")
        logger.info(f"Method: {request.method}")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Args: {dict(request.args)}")
        logger.info(f"Remote addr: {request.remote_addr}")
        logger.info(f"URL root: {request.url_root}")
        
        if request.method == 'OPTIONS':
            logger.info("Handling OPTIONS preflight request")
            response = Response()
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add('Access-Control-Allow-Headers', "*")
            response.headers.add('Access-Control-Allow-Methods', "*")
            return response
        
        url = unquote_plus(request.args.get('url', ''))
        logger.info(f"Proxy URL parameter: {url}")
        
        if not url:
            logger.error("No URL parameter provided")
            return jsonify({'error': 'URL parameter is required'}), 400
        
        # Test if we can reach the URL
        logger.info(f"Attempting to fetch: {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        logger.info(f"Using headers: {headers}")
        
        response = requests.get(url, headers=headers, timeout=30, verify=True)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        logger.info(f"Content length: {len(response.content)} bytes")
        logger.info(f"Content preview: {response.content[:100]}")
        
        response.raise_for_status()
        
        # Check if it's an M3U8 file
        is_m3u8 = (response.content.startswith(b"#EXTM3U") or 
                   url.endswith('.m3u8') or 
                   'application/vnd.apple.mpegurl' in response.headers.get('content-type', ''))
        
        logger.info(f"Is M3U8: {is_m3u8}")
        
        if is_m3u8:
            # Process M3U8 content
            logger.info("Processing M3U8 content")
            m3u8_content = response.text.splitlines(keepends=False)
            proxy_base = f"{request.url_root.rstrip('/')}/proxy"
            
            logger.info(f"Original M3U8 lines: {len(m3u8_content)}")
            logger.info(f"First few lines: {m3u8_content[:5]}")
            
            # Convert relative URLs to absolute, then to proxy URLs
            processed_lines = []
            for line_num, line in enumerate(m3u8_content):
                line = line.strip()
                if line and not line.startswith('#'):
                    # This is a URL line (segment or sub-playlist)
                    logger.info(f"Processing URL line {line_num}: {line}")
                    
                    if not line.startswith('http'):
                        # Relative URL, make it absolute
                        absolute_url = urljoin(url, line)
                        logger.info(f"Made absolute: {absolute_url}")
                    else:
                        absolute_url = line
                    
                    # Create proxy URL
                    proxy_url = f"{proxy_base}?url={quote_plus(absolute_url)}"
                    logger.info(f"Created proxy URL: {proxy_url}")
                    processed_lines.append(proxy_url)
                else:
                    # Handle EXT-X-KEY URIs in the line itself
                    if 'URI="' in line:
                        logger.info(f"Processing EXT-X-KEY line: {line}")
                        # Extract and replace URI in EXT-X-KEY lines
                        uri_match = re.search(r'URI="([^"]*)"', line)
                        if uri_match:
                            original_uri = uri_match.group(1)
                            if not original_uri.startswith('http'):
                                absolute_uri = urljoin(url, original_uri)
                            else:
                                absolute_uri = original_uri
                            proxy_uri = f"{proxy_base}?url={quote_plus(absolute_uri)}"
                            line = line.replace(f'URI="{original_uri}"', f'URI="{proxy_uri}"')
                            logger.info(f"Updated EXT-X-KEY line: {line}")
                    
                    processed_lines.append(line)
            
            # Create response with proper M3U8 headers
            response_content = '\n'.join(processed_lines)
            logger.info(f"Final M3U8 content length: {len(response_content)}")
            logger.info(f"Final M3U8 preview: {response_content[:200]}")
            
            resp = Response(
                response_content,
                mimetype='application/vnd.apple.mpegurl'
            )
            
            # Add comprehensive CORS headers
            resp.headers.update({
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
                'Access-Control-Allow-Headers': 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, Range',
                'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Date, Server',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            })
            
            logger.info(f"Returning M3U8 response with headers: {dict(resp.headers)}")
            return resp
        
        else:
            # Handle video segments (TS files) and other content
            logger.info("Processing non-M3U8 content (likely video segment)")
            
            content_type = response.headers.get('content-type', 'application/octet-stream')
            
            # Set appropriate content type for video segments
            if url.endswith('.ts'):
                content_type = 'video/mp2t'
            elif url.endswith('.m4s'):
                content_type = 'video/mp4'
            
            logger.info(f"Using content type: {content_type}")
            
            resp = Response(
                response.content,
                mimetype=content_type
            )
            
            resp.headers.update({
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
                'Access-Control-Allow-Headers': 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, Range',
                'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Date, Server, Accept-Ranges',
                'Cache-Control': 'public, max-age=3600',
                'Accept-Ranges': 'bytes'
            })
            
            logger.info("Returning video segment response")
            return resp
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for URL {url}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to fetch URL: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Proxy error for URL {url}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Proxy failed: {str(e)}'}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint with debug info"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'Sreaty TV Debug Backend',
        'environment': {
            'PORT': os.environ.get('PORT', 'Not set'),
            'RAILWAY_PORT': os.environ.get('RAILWAY_PORT', 'Not set'),
            'RAILWAY_PUBLIC_DOMAIN': os.environ.get('RAILWAY_PUBLIC_DOMAIN', 'Not set')
        }
    })

# Handle preflight OPTIONS requests globally
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        logger.info(f"Global OPTIONS handler for: {request.url}")
        response = Response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

# Apply CORS headers to all responses
@app.after_request
def apply_cors_headers(response):
    response.headers.update({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, Authorization, Range",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Date, Server, Accept-Ranges"
    })
    return response

@app.errorhandler(404)
def not_found(error):
    logger.error(f"404 error for: {request.url}")
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    return jsonify({'error': 'Internal server error'}), 500

port = int(os.environ.get('PORT', 5000))

if __name__ == '__main__':
    logger.info("🚀 Starting Sreaty TV Debug Server...")
    logger.info(f"📺 Debug page: http://localhost:{port}")
    logger.info(f"🔍 Environment variables:")
    logger.info(f"   PORT: {os.environ.get('PORT', 'Not set')}")
    logger.info(f"   RAILWAY_PORT: {os.environ.get('RAILWAY_PORT', 'Not set')}")
    logger.info(f"   RAILWAY_PUBLIC_DOMAIN: {os.environ.get('RAILWAY_PUBLIC_DOMAIN', 'Not set')}")
    
    app.run(debug=False, host='0.0.0.0', port=port)
