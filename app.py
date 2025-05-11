from flask import Flask, render_template, request, jsonify
import requests
import threading
import json
from urllib.parse import urlparse
import logging
from datetime import datetime
import os
import socket
from collections import deque

app = Flask(__name__)

# Use deque with max length to limit memory usage
intercepted_requests = deque(maxlen=100)
blocked_domains = set()
request_counter = 0

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create templates directory
os.makedirs('templates', exist_ok=True)

# Find available port
def find_available_port(start_port, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
    return None

# Helper function to normalize domain name for more reliable matching
def normalize_domain(domain):
    # Remove potential protocol
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    
    # Remove path components
    if '/' in domain:
        domain = domain.split('/', 1)[0]
    
    # Remove port number if present
    if ':' in domain:
        domain = domain.split(':', 1)[0]
    
    # Lowercase all text
    domain = domain.lower()
    
    # Optional: remove 'www.' prefix for more general blocking
    if domain.startswith('www.'):
        domain = domain[4:]
        
    return domain

# Function to check if a domain is blocked
def is_domain_blocked(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # First try exact match
    if domain in blocked_domains:
        logger.info(f"Domain {domain} is blocked (exact match)")
        return True
    
    # Then try normalized match
    normalized = normalize_domain(domain)
    if normalized in blocked_domains:
        logger.info(f"Domain {domain} is blocked (normalized as {normalized})")
        return True
    
    # Try checking if it's a subdomain of a blocked domain
    for blocked in blocked_domains:
        if domain.endswith('.' + blocked):
            logger.info(f"Domain {domain} is blocked (subdomain of {blocked})")
            return True
    
    logger.info(f"Domain {domain} is not blocked")
    return False

# Create simplified HTML template

@app.route('/')
def index():
    return render_template('index.html')

# WebSocket for real-time updates
from flask_sock import Sock
sock = Sock(app)
ws_clients = set()

@sock.route('/ws')
def websocket(ws):
    ws_clients.add(ws)
    try:
        while True:
            message = ws.receive()
            # Just keep connection alive
    except:
        pass
    finally:
        ws_clients.remove(ws)

def broadcast_update(data):
    for client in list(ws_clients):
        try:
            client.send(json.dumps(data))
        except:
            ws_clients.remove(client)

def broadcast_debug(message):
    broadcast_update({"type": "debug_info", "message": message})

# API routes
@app.route('/api/requests')
def get_requests():
    return jsonify(list(intercepted_requests))

@app.route('/api/request/<int:request_id>')
def get_request(request_id):
    for req in intercepted_requests:
        if req['id'] == request_id:
            return jsonify(req)
    return jsonify({"error": "Request not found"}), 404

@app.route('/api/blocked-domains')
def get_blocked_domains():
    return jsonify(list(blocked_domains))

@app.route('/api/block-domain', methods=['POST'])
def block_domain():
    data = request.json
    domain = data.get('domain', '').strip()
    if domain:
        normalized = normalize_domain(domain)
        blocked_domains.add(normalized)
        broadcast_update({"type": "blocked_domains", "domains": list(blocked_domains)})
        broadcast_debug(f"Added domain to block list: {normalized} (from input: {domain})")
    return jsonify({"success": True})

@app.route('/api/unblock-domain', methods=['POST'])
def unblock_domain():
    data = request.json
    domain = data.get('domain', '')
    if domain in blocked_domains:
        blocked_domains.remove(domain)
        broadcast_update({"type": "blocked_domains", "domains": list(blocked_domains)})
        broadcast_debug(f"Removed domain from block list: {domain}")
    return jsonify({"success": True})

@app.route('/api/test-blocking', methods=['POST'])
def test_blocking():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({"blocked": False, "message": "No URL provided"})
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    normalized = normalize_domain(domain)
    
    is_blocked = is_domain_blocked(url)
    
    message = f"Domain: {domain}, Normalized: {normalized}"
    return jsonify({
        "blocked": is_blocked,
        "message": message,
        "details": {
            "original": domain,
            "normalized": normalized,
            "blocked_domains": list(blocked_domains)
        }
    })

@app.route('/api/forge-request', methods=['POST'])
def forge_request():
    global request_counter
    
    data = request.json
    method = data.get('method', 'GET')
    url = data.get('url', '')
    headers = data.get('headers', {})
    body = data.get('body', '')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Process request
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    req_data = {
        "id": request_counter,
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "timestamp": timestamp,
        "source": "Forged",
        "response": None
    }
    
    # Check if domain is blocked
    if is_domain_blocked(url):
        req_data["response"] = {"error": f"Domain is blocked"}
        intercepted_requests.appendleft(req_data)
        request_counter += 1
        broadcast_update({"type": "request", "request": req_data})
        return jsonify({"error": f"Domain is blocked"}), 403
    
    # Make request
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=10
        )
        
        # Store response
        try:
            response_json = response.json()
        except:
            response_json = {"text": response.text[:1000]}
        
        req_data["response"] = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_json
        }
        
    except Exception as e:
        req_data["response"] = {"error": str(e)}
    
    intercepted_requests.appendleft(req_data)
    request_counter += 1
    broadcast_update({"type": "request", "request": req_data})
    
    return jsonify(req_data["response"])

# Proxy server class
class ProxyServer:
    def __init__(self, host='127.0.0.1', port=None):
        self.host = host
        self.port = port if port else find_available_port(8080)
        self.server = None
        self.thread = None
        self.running = False
    
    def start(self):
        if self.running:
            return {"success": False, "message": "Proxy already running"}
        
        if not self.port:
            return {"success": False, "message": "No available ports found"}
        
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class ProxyHandler(BaseHTTPRequestHandler):
            timeout = 10
            
            def log_message(self, format, *args):
                # Override to use our logger
                logger.info(format % args)
            
            def do_GET(self):
                self._handle_request('GET')
            
            def do_POST(self):
                self._handle_request('POST')
            
            def do_PUT(self):
                self._handle_request('PUT')
            
            def do_DELETE(self):
                self._handle_request('DELETE')
            
            def do_CONNECT(self):
                global request_counter, intercepted_requests
                
                host_port = self.path.split(':')
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 443
                
                full_url = f"https://{host}:{port}"
                
                req_data = {
                    "id": request_counter,
                    "method": "CONNECT",
                    "url": full_url,
                    "headers": dict(self.headers),
                    "body": "",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "Intercepted",
                    "response": {"info": "HTTPS connection tunneled"}
                }
                
                # Log the connection attempt
                logger.info(f"CONNECT request for {host}:{port}")
                broadcast_debug(f"CONNECT request for {host}:{port}")
                
                # Check if domain is blocked
                domain_blocked = False
                for blocked in blocked_domains:
                    # Try direct matching
                    if host == blocked:
                        domain_blocked = True
                        break
                    
                    # Try normalized domain matching
                    if normalize_domain(host) == blocked:
                        domain_blocked = True
                        break
                    
                    # Try subdomain matching
                    if host.endswith('.' + blocked):
                        domain_blocked = True
                        break
                
                if domain_blocked:
                    logger.info(f"Blocking connection to {host} - matched blocked domain")
                    broadcast_debug(f"BLOCKED connection to {host}")
                    
                    self.send_error(403, f"Domain {host} is blocked")
                    req_data["response"] = {"error": f"Domain {host} is blocked"}
                    intercepted_requests.appendleft(req_data)
                    request_counter += 1
                    broadcast_update({"type": "request", "request": req_data})
                    return
                
                try:
                    # Connect to remote server
                    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_socket.connect((host, port))
                    
                    # Send success response
                    self.send_response(200, 'Connection Established')
                    self.end_headers()
                    
                    # Log connection
                    intercepted_requests.appendleft(req_data)
                    request_counter += 1
                    broadcast_update({"type": "request", "request": req_data})
                    
                    # Set up tunneling
                    socket_tunnel(self.connection, remote_socket)
                    
                except Exception as e:
                    logger.error(f"Error connecting to {host}:{port} - {str(e)}")
                    self.send_error(500, str(e))
                    req_data["response"] = {"error": str(e)}
                    intercepted_requests.appendleft(req_data)
                    request_counter += 1
                    broadcast_update({"type": "request", "request": req_data})
            
            def _handle_request(self, method):
                global request_counter, intercepted_requests
                
                url = self.path
                if not url.startswith('http'):
                    url = 'http://' + self.headers.get('Host', '') + url
                
                # Parse headers
                headers = {k: v for k, v in self.headers.items()}
                
                # Get body
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ''
                
                # Log the request
                logger.info(f"{method} request for {url}")
                broadcast_debug(f"{method} request for {url}")
                
                # Create request data
                req_data = {
                    "id": request_counter,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": body,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "Intercepted",
                    "response": None
                }
                
                # Check if domain is blocked
                if is_domain_blocked(url):
                    logger.info(f"Blocking request to {url} - matched blocked domain")
                    broadcast_debug(f"BLOCKED request to {url}")
                    
                    self.send_response(403)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f"Domain is blocked".encode())
                    
                    req_data["response"] = {"error": f"Domain is blocked"}
                    intercepted_requests.appendleft(req_data)
                    request_counter += 1
                    broadcast_update({"type": "request", "request": req_data})
                    return
                
                # Forward request
                try:
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=body,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    # Send response to client
                    self.send_response(response.status_code)
                    for header, value in response.headers.items():
                        if header.lower() not in ('transfer-encoding', 'connection'):
                            self.send_header(header, value)
                    self.end_headers()
                    
                    if method != 'HEAD':
                        self.wfile.write(response.content)
                    
                    # Store response
                    try:
                        response_json = response.json()
                    except:
                        response_text = response.text[:500]
                        response_json = {"text": response_text}
                    
                    req_data["response"] = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response_json
                    }
                    
                except Exception as e:
                    logger.error(f"Error handling request to {url} - {str(e)}")
                    self.send_response(500)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f"Error: {str(e)}".encode())
                    
                    req_data["response"] = {"error": str(e)}
                
                intercepted_requests.appendleft(req_data)
                request_counter += 1
                broadcast_update({"type": "request", "request": req_data})
        
        # Create HTTPS tunnel
        def socket_tunnel(client, remote):
            client_to_remote = threading.Thread(
                target=forward_socket_data, 
                args=(client, remote),
                daemon=True
            )
            remote_to_client = threading.Thread(
                target=forward_socket_data, 
                args=(remote, client),
                daemon=True
            )
            
            client_to_remote.start()
            remote_to_client.start()
        
        def forward_socket_data(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.sendall(data)
            except:
                pass
        
        try:
            # Create server with address reuse
            class ReuseAddressHTTPServer(HTTPServer):
                allow_reuse_address = True
            
            self.server = ReuseAddressHTTPServer((self.host, self.port), ProxyHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            
            # Broadcast status
            # Broadcast status update
            status = {"running": True, "host": self.host, "port": self.port}
            broadcast_update({"type": "proxy_status", "status": status})
            
            logger.info(f"Proxy server started on {self.host}:{self.port}")
            broadcast_debug(f"Proxy server started on {self.host}:{self.port}")
            
            return {"success": True, "message": f"Proxy started on {self.host}:{self.port}"}
        except Exception as e:
            logger.error(f"Error starting proxy: {str(e)}")
            return {"success": False, "message": f"Error starting proxy: {str(e)}"}
    
    def stop(self):
        if self.server and self.running:
            self.server.shutdown()
            self.running = False
            
            # Broadcast status update
            status = {"running": False, "host": self.host, "port": self.port}
            broadcast_update({"type": "proxy_status", "status": status})
            
            logger.info("Proxy server stopped")
            broadcast_debug("Proxy server stopped")
            
            return {"success": True, "message": "Proxy server stopped"}
        return {"success": False, "message": "Proxy server not running"}

# Create proxy instance
proxy = ProxyServer()

@app.route('/api/proxy-status')
def proxy_status():
    return jsonify({
        "running": proxy.running,
        "host": proxy.host,
        "port": proxy.port
    })

@app.route('/api/toggle-proxy', methods=['POST'])
def toggle_proxy():
    data = request.json
    action = data.get('action')
    
    if action == 'start':
        result = proxy.start()
        return jsonify(result)
    elif action == 'stop':
        result = proxy.stop()
        return jsonify(result)
    else:
        return jsonify({"success": False, "message": "Invalid action"})

if __name__ == '__main__':
    flask_port = find_available_port(5000)
    print(f"Web Request Inspector available at: http://127.0.0.1:{flask_port}")
    app.run(host='127.0.0.1', port=flask_port)