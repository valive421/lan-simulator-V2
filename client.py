import os
import sys
# --- Admin elevation for Windows (must be first) ---
def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

if os.name == 'nt' and not is_admin():
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"' + ' '.join(sys.argv) + '"', None, 1)
    sys.exit(0)

# lan_vpn_client_with_logging.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import socket
import select
import uuid
import subprocess
import os
import sys
import ctypes
from ctypes import *
import struct
import ipaddress
import netifaces
from datetime import datetime, timedelta
import traceback

# Try to load WinTun DLL
try:
    if hasattr(sys, 'frozen'):
        wintun = WinDLL("wintun.dll")
    else:
        wintun_path = os.path.join(os.path.dirname(__file__), "wintun.dll")
        if os.path.exists(wintun_path):
            wintun = WinDLL(wintun_path)
        else:
            wintun = WinDLL("wintun.dll")
except:
    wintun = None
    print("Warning: WinTun DLL not found. VPN functionality will be limited.")

# Debug logging
DEBUG_LOG_PATH = os.path.join(os.path.dirname(__file__), 'client_debug.log')
_log_lock = threading.Lock()

def debug(event, level='INFO', exc=None, extra=None):
    ts = datetime.now().isoformat()
    msg = f"{ts} [{level}] {event}"
    if extra is not None:
        msg += " | " + str(extra)
    print(msg)
    try:
        with _log_lock:
            with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(msg + '\n')
                if exc is not None:
                    if isinstance(exc, BaseException):
                        f.write(''.join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
                    else:
                        f.write(str(exc) + '\n')
    except Exception as e:
        print("Failed to write debug log:", e)

class WinTunManager:
    def __init__(self):
        self.adapter = None
        self.session = None
        self.read_wait_event = None
        
    def create_adapter(self, name="LANVPN", tunnel_type="LAN VPN Tunnel"):
        debug(f"create_adapter: attempting to create/open adapter '{name}'")
        if not wintun:
            debug("create_adapter: wintun DLL not loaded", level='ERROR')
            return False
            
        try:
            wintun.WintunCreateAdapter.restype = c_void_p
            wintun.WintunCreateAdapter.argtypes = [c_wchar_p, c_wchar_p, c_void_p]
            
            wintun.WintunOpenAdapter.restype = c_void_p
            wintun.WintunOpenAdapter.argtypes = [c_wchar_p]
            
            self.adapter = wintun.WintunOpenAdapter(name)
            if self.adapter:
                debug(f"Using existing WinTun adapter: {name}")
                return True
                
            self.adapter = wintun.WintunCreateAdapter(name, tunnel_type, None)
            ok = self.adapter is not None
            debug(f"create_adapter: created adapter={ok}")
            return ok
            
        except Exception as e:
            debug("Error creating WinTun adapter", level='ERROR', exc=e)
            return False
            
    def start_session(self, capacity=0x400000):
        debug("start_session: starting session")
        if not self.adapter:
            debug("start_session: no adapter available", level='ERROR')
            return False
            
        try:
            wintun.WintunStartSession.restype = c_void_p
            wintun.WintunStartSession.argtypes = [c_void_p, c_uint]
            debug(f"WintunStartSession func: {getattr(wintun, 'WintunStartSession', None)}")
            self.session = wintun.WintunStartSession(self.adapter, capacity)
            if self.session:
                wintun.WintunGetReadWaitEvent.restype = c_void_p
                wintun.WintunGetReadWaitEvent.argtypes = [c_void_p]
                self.read_wait_event = wintun.WintunGetReadWaitEvent(self.session)
            debug(f"start_session: session started={self.session is not None}")
            return self.session is not None
        except Exception as e:
            try:
                err = ctypes.windll.kernel32.GetLastError()
            except Exception:
                err = None
            debug("Error starting WinTun session", level='ERROR', exc=e, extra={'Win32LastError': err})
            return False
            
    def stop_session(self):
        if self.session:
            try:
                wintun.WintunEndSession.restype = None
                wintun.WintunEndSession.argtypes = [c_void_p]
                wintun.WintunEndSession(self.session)
            except Exception as e:
                debug("Error ending WinTun session", level='WARNING', exc=e)
            self.session = None
            debug("stop_session: session stopped")
            
    def receive_packet(self):
        if not self.session:
            return None
            
        try:
            wintun.WintunReceivePacket.restype = c_void_p
            wintun.WintunReceivePacket.argtypes = [c_void_p, POINTER(c_uint)]
            
            packet_size = c_uint(0)
            packet = wintun.WintunReceivePacket(self.session, byref(packet_size))
            if packet and packet_size.value > 0:
                packet_data = string_at(packet, packet_size.value)
                
                wintun.WintunReleaseReceivePacket.restype = None
                wintun.WintunReleaseReceivePacket.argtypes = [c_void_p, c_void_p]
                wintun.WintunReleaseReceivePacket(self.session, packet)
                
                return packet_data
        except Exception as e:
            debug("receive_packet: exception", level='ERROR', exc=e)
        return None
        
    def send_packet(self, packet_data):
        if not self.session:
            return False
            
        try:
            wintun.WintunAllocateSendPacket.restype = c_void_p
            wintun.WintunAllocateSendPacket.argtypes = [c_void_p, c_uint]
            
            wintun.WintunSendPacket.restype = None
            wintun.WintunSendPacket.argtypes = [c_void_p, c_void_p]
            
            packet_ptr = wintun.WintunAllocateSendPacket(self.session, len(packet_data))
            if packet_ptr:
                memmove(packet_ptr, packet_data, len(packet_data))
                wintun.WintunSendPacket(self.session, packet_ptr)
                return True
        except Exception as e:
            debug("send_packet: exception", level='ERROR', exc=e)
        return False

class VPNClient:
    def __init__(self, server_host, server_port, packet_callback=None):
        self.server_host = server_host
        self.server_port = server_port
        self.peer_id = str(uuid.uuid4())[:8]
        self.username = f"Player_{self.peer_id}"
        self.room_id = None
        self.room_members = {}
        self.connected_peers = {}
        
        self.udp_socket = None
        self.wintun = WinTunManager()
        self.running = False
        self.last_keepalive = time.time()
        self.packet_callback = packet_callback  # Callback for packet logging
        
    def start(self):
        try:
            debug("VPNClient.start: creating UDP socket")
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('0.0.0.0', 0))
            debug(f"VPNClient.start: UDP socket bound to {self.udp_socket.getsockname()}")
            
            # Use unique adapter name per client to avoid conflicts when multiple clients run on same host
            adapter_name = f"LANVPN-{self.peer_id}"
            debug(f"Attempting to create/open adapter with name: {adapter_name}")
            if not self.wintun.create_adapter(name=adapter_name):
                debug("Could not create WinTun adapter", level='WARNING')
            else:
                if not self.wintun.start_session():
                    debug("Could not start WinTun session", level='WARNING')
            
            
            self.running = True
            debug(f"VPNClient.start: running={self.running}, peer_id={self.peer_id}")
            
            threads = [
                threading.Thread(target=self._network_loop),
                threading.Thread(target=self._keepalive_loop)
            ]
            
            for thread in threads:
                thread.daemon = True
                thread.start()
                debug(f"VPNClient.start: started thread {thread.name}")
                
            debug(f"VPN client started for peer {self.peer_id}")
            return True
            
        except Exception as e:
            debug("Error starting VPN client", level='ERROR', exc=e)
            return False
            
    def stop(self):
        self.running = False
        debug("VPNClient.stop: stopping client")
        if self.udp_socket:
            try:
                self.udp_socket.close()
                debug("VPNClient.stop: UDP socket closed")
            except Exception as e:
                debug("VPNClient.stop: error closing socket", level='WARNING', exc=e)
        self.wintun.stop_session()
        
    def create_room(self, room_id, username):
        debug(f"create_room: room_id={room_id}, username={username}")
        self.room_id = room_id
        self.username = username
        self.room_members = {self.peer_id: {'username': username, 'addr': None}}

        message = {
            'action': 'create_room',
            'room_id': room_id,
            'peer_id': self.peer_id,
            'username': username,
            'port': self.udp_socket.getsockname()[1]
        }
        self._send_to_server(message)
        
    def join_room(self, room_id, username):
        debug(f"join_room: room_id={room_id}, username={username}")
        self.room_id = room_id
        self.username = username

        message = {
            'action': 'join_room',
            'room_id': room_id,
            'peer_id': self.peer_id,
            'username': username,
            'port': self.udp_socket.getsockname()[1]
        }
        self._send_to_server(message)
        
    def leave_room(self):
        debug(f"leave_room: leaving room {self.room_id}")
        if self.room_id:
            message = {
                'action': 'leave_room',
                'room_id': self.room_id,
                'peer_id': self.peer_id
            }
            self._send_to_server(message)
            self.room_id = None
            self.room_members = {}
            self.connected_peers = {}
            
    def _network_loop(self):
        while self.running:
            try:
                if not self.udp_socket:
                    debug("_network_loop: udp_socket is None", level='ERROR')
                    time.sleep(1)
                    continue

                readable, _, _ = select.select([self.udp_socket], [], [], 0.1)
                if self.udp_socket in readable:
                    try:
                        data, addr = self.udp_socket.recvfrom(65536)
                        debug(f"_network_loop: received {len(data)} bytes from {addr}")
                        self._handle_network_data(data, addr)
                    except Exception as e:
                        debug("_network_loop: recvfrom failed", level='ERROR', exc=e)
                
                if self.wintun.session:
                    packet = self.wintun.receive_packet()
                    if packet:
                        if self.packet_callback:
                            self.packet_callback("TUN->NET", packet, None)
                        for peer_id, peer_addr in self.connected_peers.items():
                            if peer_addr:
                                try:
                                    self.udp_socket.sendto(packet, peer_addr)
                                    debug(f"_network_loop: sent packet to peer {peer_id} at {peer_addr}")
                                except Exception as e:
                                    debug(f"_network_loop: sendto to {peer_addr} failed", level='ERROR', exc=e)
                
            except Exception as e:
                debug(f"Error in network loop: {e}", level='ERROR', exc=e)
                debug("_network_loop: outer exception", level='ERROR', exc=e)
                time.sleep(1)
                
    def _keepalive_loop(self):
        while self.running:
            try:
                if self.room_id and time.time() - self.last_keepalive > 30:
                    message = {
                        'action': 'keepalive',
                        'room_id': self.room_id,
                        'peer_id': self.peer_id
                    }
                    self._send_to_server(message)
                    self.last_keepalive = time.time()
            except:
                pass
            time.sleep(5)
            
    def _handle_network_data(self, data, addr):
        try:
            message = json.loads(data.decode())
            self._handle_control_message(message, addr)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if self.wintun.session:
                if self.packet_callback:
                    self.packet_callback("NET->TUN", data, addr)
                self.wintun.send_packet(data)
        except Exception as e:
            print(f"Error handling network data: {e}")
            
    def _handle_control_message(self, message, addr):
        action = message.get('action')

        if action == 'room_created':
            debug("Room created successfully", level='INFO')

        elif action == 'room_joined':
            debug("Joined room successfully", level='INFO')
            raw_members = message.get('members', {})
            members = {}
            for pid, info in raw_members.items():
                members[pid] = {
                    'username': info.get('username'),
                    'addr': (info.get('public_ip'), info.get('public_port'))
                }
            self.room_members = members
            self._connect_to_peers()

        elif action == 'peer_list':
            debug("Received peer_list", extra=message)
            raw_members = message.get('members', {})
            members = {}
            for pid, info in raw_members.items():
                members[pid] = {
                    'username': info.get('username'),
                    'addr': (info.get('public_ip'), info.get('public_port'))
                }
            self.room_members = members
            self._connect_to_peers()

        elif action == 'peer_joined':
            peer_id = message.get('peer_id')
            username = message.get('username')
            peer_addr = (message.get('public_ip'), message.get('public_port'))

            self.room_members[peer_id] = {
                'username': username,
                'addr': peer_addr
            }
            debug(f"peer_joined: {peer_id} at {peer_addr}")
            self._initiate_punch(peer_id, peer_addr)

        elif action == 'peer_left':
            peer_id = message.get('peer_id')
            debug(f"peer_left: {peer_id}")
            if peer_id in self.room_members:
                del self.room_members[peer_id]
            if peer_id in self.connected_peers:
                del self.connected_peers[peer_id]

        elif action == 'punch_request':
            source_peer = message.get('source_peer')
            debug(f"punch_request from {source_peer}")
            if source_peer in self.room_members:
                response = {
                    'action': 'punch_response',
                    'room_id': self.room_id,
                    'peer_id': self.peer_id
                }
                self._send_message(response, self.room_members[source_peer]['addr'])

        elif action == 'punch_response':
            source_peer = message.get('peer_id')
            debug(f"punch_response from {source_peer}")
            if source_peer in self.room_members:
                self.connected_peers[source_peer] = self.room_members[source_peer]['addr']
                debug(f"Connected to peer: {source_peer}")

        else:
            debug("Unknown control message", level='WARNING', extra=message)
                
    def _connect_to_peers(self):
        for peer_id, info in self.room_members.items():
            if peer_id != self.peer_id and info.get('addr'):
                self._initiate_punch(peer_id, info['addr'])
                
    def _initiate_punch(self, peer_id, peer_addr):
        if peer_id in self.connected_peers:
            return
        debug(f"_initiate_punch: Connecting to {peer_id} at {peer_addr}")

        message = {
            'action': 'punch_request',
            'room_id': self.room_id,
            'source_peer': self.peer_id,
            'target_peer': peer_id
        }
        self._send_message(message, peer_addr)
        
    def _send_to_server(self, message):
        try:
            data = json.dumps(message).encode()
            self.udp_socket.sendto(data, (self.server_host, self.server_port))
        except Exception as e:
            debug(f"Error sending to server: {e}", level='ERROR', exc=e)
            
    def _send_message(self, message, addr):
        try:
            data = json.dumps(message).encode()
            self.udp_socket.sendto(data, addr)
        except Exception as e:
            debug(f"Error sending message: {e}", level='ERROR', exc=e)

class VPNGuiClient:
    def __init__(self, root, server_host, server_port):
        self.root = root
        self.server_host = server_host
        self.server_port = server_port
        self.vpn_client = VPNClient(server_host, server_port, self._packet_callback)
        
        self._setup_gui()
        self.vpn_client.start()
        
    def _setup_gui(self):
        self.root.title("LAN Over Internet - Packet Logger")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Create paned window for resizable panels
        paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for connection info
        top_frame = ttk.Frame(paned_window)
        paned_window.add(top_frame, weight=1)
        
        # Bottom frame for packet logging
        bottom_frame = ttk.Frame(paned_window)
        paned_window.add(bottom_frame, weight=2)
        
        # Setup top frame
        self._setup_connection_frame(top_frame)
        
        # Setup bottom frame
        self._setup_packet_log_frame(bottom_frame)
        
        # Start update loop
        self._update_ui_loop()
        
    def _setup_connection_frame(self, parent):
        # Title
        title_label = ttk.Label(parent, text="LAN Over Internet", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Connection info frame
        conn_frame = ttk.Frame(parent)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Username
        ttk.Label(conn_frame, text="Your Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(value=self.vpn_client.username)
        username_entry = ttk.Entry(conn_frame, textvariable=self.username_var, width=20)
        username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Room ID
        ttk.Label(conn_frame, text="Room ID:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.room_id_var = tk.StringVar()
        room_id_entry = ttk.Entry(conn_frame, textvariable=self.room_id_var, width=15)
        room_id_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(conn_frame)
        button_frame.grid(row=0, column=4, columnspan=2, padx=10)
        
        self.create_btn = ttk.Button(button_frame, text="Create Room", command=self._create_room)
        self.create_btn.pack(side=tk.LEFT, padx=5)
        
        self.join_btn = ttk.Button(button_frame, text="Join Room", command=self._join_room)
        self.join_btn.pack(side=tk.LEFT, padx=5)
        
        self.leave_btn = ttk.Button(button_frame, text="Leave Room", command=self._leave_room, state=tk.DISABLED)
        self.leave_btn.pack(side=tk.LEFT, padx=5)
        
        # Status
        ttk.Label(conn_frame, text="Status:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.status_var = tk.StringVar(value="Not connected")
        status_label = ttk.Label(conn_frame, textvariable=self.status_var, foreground="red")
        status_label.grid(row=1, column=1, columnspan=4, sticky=tk.W, pady=5)
        
        # Room members
        ttk.Label(conn_frame, text="Room Members:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.members_listbox = tk.Listbox(conn_frame, height=6)
        self.members_listbox.grid(row=2, column=1, columnspan=4, sticky=tk.W+tk.E, pady=5, padx=5)
        
        # Configure grid weights
        conn_frame.columnconfigure(1, weight=1)
        conn_frame.columnconfigure(3, weight=1)
        
    def _setup_packet_log_frame(self, parent):
        # Packet log
        ttk.Label(parent, text="Packet Log (NET->TUN: From Network to VPN, TUN->NET: From VPN to Network):", 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
        
        # Create frame for log controls
        log_control_frame = ttk.Frame(parent)
        log_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(log_control_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(log_control_frame, textvariable=self.filter_var, 
                                   values=["All", "NET->TUN", "TUN->NET", "Control"], width=10)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.set("All")
        
        ttk.Button(log_control_frame, text="Clear Log", command=self._clear_log).pack(side=tk.RIGHT, padx=5)
        
        # Packet log text area
        self.packet_log = scrolledtext.ScrolledText(parent, height=20, state=tk.DISABLED)
        self.packet_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for different packet types
        self.packet_log.tag_configure("NET->TUN", foreground="blue")
        self.packet_log.tag_configure("TUN->NET", foreground="green")
        self.packet_log.tag_configure("control", foreground="purple")
        
    def _packet_callback(self, direction, data, addr):
        """Callback for packet logging"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        if direction == "NET->TUN":
            # Network to VPN traffic
            packet_type = "NET->TUN"
            if len(data) > 100:  # Truncate large packets
                packet_info = f"{timestamp} - {packet_type} - {len(data)} bytes from {addr}"
                packet_hex = data[:50].hex() + "..." if len(data) > 50 else data.hex()
            else:
                packet_info = f"{timestamp} - {packet_type} - {len(data)} bytes from {addr}: {data.hex()}"
                packet_hex = data.hex()
        else:
            # VPN to Network traffic
            packet_type = "TUN->NET"
            if len(data) > 100:  # Truncate large packets
                packet_info = f"{timestamp} - {packet_type} - {len(data)} bytes"
                packet_hex = data[:50].hex() + "..." if len(data) > 50 else data.hex()
            else:
                packet_info = f"{timestamp} - {packet_type} - {len(data)} bytes: {data.hex()}"
                packet_hex = data.hex()
        
        # Update UI in thread-safe way
        self.root.after(0, self._add_packet_to_log, packet_type, packet_info, packet_hex)
        
    def _add_packet_to_log(self, packet_type, packet_info, packet_hex):
        """Add packet to log in UI thread"""
        current_filter = self.filter_var.get()
        
        if current_filter == "All" or current_filter == packet_type:
            self.packet_log.config(state=tk.NORMAL)
            self.packet_log.insert(tk.END, packet_info + "\n", packet_type)
            
            # Add hex dump for non-control packets
            if packet_type != "control":
                hex_lines = [packet_hex[i:i+32] for i in range(0, len(packet_hex), 32)]
                for line in hex_lines:
                    formatted_line = "    " + " ".join([line[i:i+2] for i in range(0, len(line), 2)]) + "\n"
                    self.packet_log.insert(tk.END, formatted_line, packet_type)
            
            self.packet_log.see(tk.END)
            self.packet_log.config(state=tk.DISABLED)
            
    def _clear_log(self):
        """Clear the packet log"""
        self.packet_log.config(state=tk.NORMAL)
        self.packet_log.delete(1.0, tk.END)
        self.packet_log.config(state=tk.DISABLED)
        
    def _create_room(self):
        username = self.username_var.get().strip()
        room_id = self.room_id_var.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter your name")
            return
            
        if not room_id:
            messagebox.showerror("Error", "Please enter a room ID")
            return
            
        self.vpn_client.create_room(room_id, username)
        self.status_var.set(f"Connected to room: {room_id}")
        self.leave_btn.config(state=tk.NORMAL)
        self.create_btn.config(state=tk.DISABLED)
        self.join_btn.config(state=tk.DISABLED)
        self._add_packet_to_log("control", f"Created room: {room_id}", "")
        
    def _join_room(self):
        username = self.username_var.get().strip()
        room_id = self.room_id_var.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter your name")
            return
            
        if not room_id:
            messagebox.showerror("Error", "Please enter a room ID")
            return
            
        self.vpn_client.join_room(room_id, username)
        self.status_var.set(f"Connected to room: {room_id}")
        self.leave_btn.config(state=tk.NORMAL)
        self.create_btn.config(state=tk.DISABLED)
        self.join_btn.config(state=tk.DISABLED)
        self._add_packet_to_log("control", f"Joined room: {room_id}", "")
        
    def _leave_room(self):
        self.vpn_client.leave_room()
        self.status_var.set("Not connected")
        self.leave_btn.config(state=tk.DISABLED)
        self.create_btn.config(state=tk.NORMAL)
        self.join_btn.config(state=tk.NORMAL)
        self.members_listbox.delete(0, tk.END)
        self._add_packet_to_log("control", "Left room", "")
        
    def _update_ui_loop(self):
        self.members_listbox.delete(0, tk.END)
        for peer_id, info in self.vpn_client.room_members.items():
            username = info.get('username', 'Unknown')
            status = "✓" if peer_id in self.vpn_client.connected_peers else "⌛"
            self.members_listbox.insert(tk.END, f"{status} {username} ({peer_id})")
        
        if self.vpn_client.room_id:
            connected_count = len(self.vpn_client.connected_peers)
            total_count = len(self.vpn_client.room_members)
            self.status_var.set(f"Room: {self.vpn_client.room_id} - {connected_count}/{total_count} connected")
        
        self.root.after(1000, self._update_ui_loop)
        
    def on_closing(self):
        self.vpn_client.stop()
        self.root.destroy()

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

def main():
    # --- Admin elevation for Windows ---
    if os.name == 'nt' and not is_admin():
        import sys
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"' + ' '.join(sys.argv) + '"', None, 1)
        sys.exit(0)

    # Ensure WinTun DLL is loaded before proceeding
    global wintun
    if not wintun:
        messagebox.showerror("WinTun DLL Error", "WinTun DLL not found or failed to load. Please ensure wintun.dll is in the same directory and matches your Python architecture.")
        sys.exit(1)

    server_host = "127.0.0.1"  # Replace with your server IP
    server_port = 5000

    root = tk.Tk()
    app = VPNGuiClient(root, server_host, server_port)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()