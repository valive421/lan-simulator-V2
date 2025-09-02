# app.py (for Render deployment)
import socket
import threading
import json
import time
import os
from flask import Flask

# Create Flask app for health checks (required by Render)
app = Flask(__name__)

@app.route('/')
def health_check():
    return "Room Server is running"

def run_room_server():
    """Run the UDP room server"""
    host = '0.0.0.0'
    port = int(os.environ.get('PORT', 5000))
    
    server = RoomServer(host, port)
    if server.start():
        print(f"Room server started on {host}:{port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down server...")
            server.stop()
    else:
        print("Failed to start server")

class RoomServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.rooms = {}  # room_id -> {members: {peer_id: info}}
        self.socket = None
        self.running = False
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            # Start server threads
            threads = [
                threading.Thread(target=self._receive_loop),
                threading.Thread(target=self._cleanup_loop)
            ]
            
            for thread in threads:
                thread.daemon = True
                thread.start()
                
            print(f"✅ Room server started on {self.host}:{self.port}")
            print(f"📡 Server is ready for connections")
            return True
            
        except Exception as e:
            print(f"❌ Error starting server: {e}")
            return False
            
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
            print("🛑 Server stopped")
            
    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self._handle_message(data, addr)
            except:
                if self.running:
                    print("⚠️  Error receiving data")
                    
    def _handle_message(self, data, addr):
        try:
            message = json.loads(data.decode())
            action = message.get('action')
            room_id = message.get('room_id')
            peer_id = message.get('peer_id')
            
            if action == 'create_room':
                self._handle_create_room(message, addr)
            elif action == 'join_room':
                self._handle_join_room(message, addr)
            elif action == 'leave_room':
                self._handle_leave_room(message, addr)
            elif action == 'keepalive':
                self._handle_keepalive(message, addr)
            elif action == 'punch_request':
                self._handle_punch_request(message, addr)
            else:
                print(f"❓ Unknown action: {action} from {addr}")
                
        except json.JSONDecodeError:
            print(f"📨 Received non-JSON data from {addr}")
        except Exception as e:
            print(f"⚠️  Error handling message: {e}")
            
    def _handle_create_room(self, message, addr):
        room_id = message['room_id']
        peer_id = message['peer_id']
        username = message['username']
        
        if room_id not in self.rooms:
            self.rooms[room_id] = {'members': {}}
        
        # Add member to room
        self.rooms[room_id]['members'][peer_id] = {
            'username': username,
            'addr': addr,
            'last_seen': time.time()
        }
        
        # Send success response
        response = {
            'action': 'room_created',
            'room_id': room_id,
            'status': 'success'
        }
        self._send_message(response, addr)
        
        print(f"🏠 Room '{room_id}' created by {username} ({peer_id})")
        
    def _handle_join_room(self, message, addr):
        room_id = message['room_id']
        peer_id = message['peer_id']
        username = message['username']
        
        if room_id not in self.rooms:
            # Room doesn't exist, create it
            self.rooms[room_id] = {'members': {}}
        
        # Add member to room
        self.rooms[room_id]['members'][peer_id] = {
            'username': username,
            'addr': addr,
            'last_seen': time.time()
        }
        
        # Send current members list
        members = {}
        for pid, info in self.rooms[room_id]['members'].items():
            if pid != peer_id:
                members[pid] = {
                    'username': info['username'],
                    'public_ip': info['addr'][0],
                    'public_port': info['addr'][1]
                }
        
        response = {
            'action': 'room_joined',
            'room_id': room_id,
            'members': members,
            'status': 'success'
        }
        self._send_message(response, addr)
        
        # Notify other members about new peer
        for pid, info in self.rooms[room_id]['members'].items():
            if pid != peer_id:
                notification = {
                    'action': 'peer_joined',
                    'room_id': room_id,
                    'peer_id': peer_id,
                    'username': username,
                    'public_ip': addr[0],
                    'public_port': addr[1]
                }
                self._send_message(notification, info['addr'])
        
        print(f"👤 User {username} joined room '{room_id}'")
        
    def _handle_leave_room(self, message, addr):
        room_id = message['room_id']
        peer_id = message['peer_id']
        
        if room_id in self.rooms and peer_id in self.rooms[room_id]['members']:
            # Remove member from room
            username = self.rooms[room_id]['members'][peer_id]['username']
            del self.rooms[room_id]['members'][peer_id]
            
            # Notify other members
            for pid, info in self.rooms[room_id]['members'].items():
                notification = {
                    'action': 'peer_left',
                    'room_id': room_id,
                    'peer_id': peer_id
                }
                self._send_message(notification, info['addr'])
            
            print(f"👋 User {username} left room '{room_id}'")
            
    def _handle_keepalive(self, message, addr):
        room_id = message['room_id']
        peer_id = message['peer_id']
        
        if room_id in self.rooms and peer_id in self.rooms[room_id]['members']:
            self.rooms[room_id]['members'][peer_id]['last_seen'] = time.time()
            self.rooms[room_id]['members'][peer_id]['addr'] = addr
            
    def _handle_punch_request(self, message, addr):
        room_id = message['room_id']
        target_peer = message['target_peer']
        source_peer = message['source_peer']
        
        if room_id in self.rooms and target_peer in self.rooms[room_id]['members']:
            # Relay punch request to target peer
            target_addr = self.rooms[room_id]['members'][target_peer]['addr']
            relay_msg = {
                'action': 'punch_request',
                'room_id': room_id,
                'source_peer': source_peer
            }
            self._send_message(relay_msg, target_addr)
            
            print(f"🔁 Relayed punch request from {source_peer} to {target_peer} in room '{room_id}'")
            
    def _send_message(self, message, addr):
        try:
            data = json.dumps(message).encode()
            self.socket.sendto(data, addr)
        except Exception as e:
            print(f"⚠️  Error sending message to {addr}: {e}")
            
    def _cleanup_loop(self):
        while self.running:
            try:
                current_time = time.time()
                rooms_to_remove = []
                
                for room_id, room_info in self.rooms.items():
                    peers_to_remove = []
                    
                    for peer_id, peer_info in room_info['members'].items():
                        if current_time - peer_info['last_seen'] > 60:  # 1 minute timeout
                            peers_to_remove.append(peer_id)
                    
                    # Remove stale peers
                    for peer_id in peers_to_remove:
                        username = room_info['members'][peer_id]['username']
                        del room_info['members'][peer_id]
                        print(f"🧹 Removed stale peer {username} from room '{room_id}'")
                    
                    # Remove empty rooms
                    if not room_info['members']:
                        rooms_to_remove.append(room_id)
                
                # Remove empty rooms
                for room_id in rooms_to_remove:
                    del self.rooms[room_id]
                    print(f"🧹 Removed empty room '{room_id}'")
                    
            except Exception as e:
                print(f"⚠️  Error in cleanup: {e}")
                
            time.sleep(30)  # Check every 30 seconds

if __name__ == "__main__":
    # Start both Flask app (for health checks) and UDP server
    from threading import Thread
    
    # Start UDP server in a separate thread
    udp_thread = Thread(target=run_room_server, daemon=True)
    udp_thread.start()
    
    # Start Flask app (main thread)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)