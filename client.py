import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import socket
import select
import uuid
import subprocess
import ctypes
from ctypes import *
import struct
import ipaddress
from datetime import datetime
import traceback

# -----------------------------
# Windows / WinTun bootstrap
# -----------------------------

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


if os.name == "nt" and not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(f'"{x}"' for x in sys.argv), None, 1
    )
    sys.exit(0)

try:
    if getattr(sys, "frozen", False):
        wintun = WinDLL("wintun.dll")
    else:
        wintun_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll")
        wintun = WinDLL(wintun_path if os.path.exists(wintun_path) else "wintun.dll")
except Exception:
    wintun = None

DEBUG_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_debug.log")
_log_lock = threading.Lock()

# Explicit framing: never try to parse arbitrary game packets as JSON.
CONTROL_MAGIC = b"LVC1"
DATA_MAGIC = b"LVD1"
RELAY_MAGIC = b"LVR1"
PEER_ID_LEN = 8
OVERLAY_MTU = 1350

PUNCH_INTERVAL = 0.25
PUNCH_DURATION = 8.0
PEER_KEEPALIVE = 5.0
SERVER_KEEPALIVE = 15.0
PEER_TIMEOUT = 20.0
MAX_UDP = 65535


def debug(event, level="INFO", exc=None, extra=None):
    msg = f"{datetime.now().isoformat()} [{level}] {event}"
    if extra is not None:
        msg += f" | {extra}"
    print(msg)
    try:
        with _log_lock, open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
            if exc is not None:
                f.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    except Exception:
        pass


def pack_control(message):
    return CONTROL_MAGIC + json.dumps(message, separators=(",", ":")).encode("utf-8")


def unpack_control(data):
    if not data.startswith(CONTROL_MAGIC):
        return None
    try:
        return json.loads(data[len(CONTROL_MAGIC):].decode("utf-8"))
    except Exception:
        return None


def pack_data(peer_id, packet):
    return DATA_MAGIC + peer_id.encode("ascii")[:PEER_ID_LEN].ljust(PEER_ID_LEN, b"_") + packet


def unpack_data(data):
    if not data.startswith(DATA_MAGIC) or len(data) < 4 + PEER_ID_LEN:
        return None, None
    peer_id = data[4:4 + PEER_ID_LEN].decode("ascii", errors="ignore").rstrip("_")
    return peer_id, data[4 + PEER_ID_LEN:]


def pack_relay(target_peer, source_peer, packet):
    return RELAY_MAGIC + target_peer.encode("ascii")[:PEER_ID_LEN].ljust(PEER_ID_LEN, b"_") + \
        source_peer.encode("ascii")[:PEER_ID_LEN].ljust(PEER_ID_LEN, b"_") + packet


class WinTunManager:
    def __init__(self):
        self.adapter = None
        self.session = None
        self.read_wait_event = None

    def create_adapter(self, name, tunnel_type="LAN VPN Tunnel"):
        if not wintun:
            debug("WinTun DLL could not be loaded", "ERROR")
            return False
        try:
            wintun.WintunOpenAdapter.restype = c_void_p
            wintun.WintunOpenAdapter.argtypes = [c_wchar_p]
            wintun.WintunCreateAdapter.restype = c_void_p
            wintun.WintunCreateAdapter.argtypes = [c_wchar_p, c_wchar_p, c_void_p]

            self.adapter = wintun.WintunOpenAdapter(name)
            if not self.adapter:
                self.adapter = wintun.WintunCreateAdapter(name, tunnel_type, None)
            return bool(self.adapter)
        except Exception as e:
            debug("WinTun adapter creation failed", "ERROR", e)
            return False

    def start_session(self, capacity=0x400000):
        if not self.adapter:
            return False
        try:
            wintun.WintunStartSession.restype = c_void_p
            wintun.WintunStartSession.argtypes = [c_void_p, c_uint]
            self.session = wintun.WintunStartSession(self.adapter, capacity)
            if self.session:
                wintun.WintunGetReadWaitEvent.restype = c_void_p
                wintun.WintunGetReadWaitEvent.argtypes = [c_void_p]
                self.read_wait_event = wintun.WintunGetReadWaitEvent(self.session)
            return bool(self.session)
        except Exception as e:
            debug("WinTun session start failed", "ERROR", e)
            return False

    def stop_session(self):
        if self.session:
            try:
                wintun.WintunEndSession.restype = None
                wintun.WintunEndSession.argtypes = [c_void_p]
                wintun.WintunEndSession(self.session)
            except Exception as e:
                debug("WinTunEndSession failed", "WARNING", e)
        self.session = None

    def receive_packet(self):
        if not self.session:
            return None
        try:
            size = c_uint(0)
            wintun.WintunReceivePacket.restype = c_void_p
            wintun.WintunReceivePacket.argtypes = [c_void_p, POINTER(c_uint)]
            ptr = wintun.WintunReceivePacket(self.session, byref(size))
            if ptr and size.value:
                data = string_at(ptr, size.value)
                wintun.WintunReleaseReceivePacket.restype = None
                wintun.WintunReleaseReceivePacket.argtypes = [c_void_p, c_void_p]
                wintun.WintunReleaseReceivePacket(self.session, ptr)
                return data
        except Exception as e:
            debug("WinTun receive failed", "ERROR", e)
        return None

    def send_packet(self, data):
        if not self.session:
            return False
        try:
            wintun.WintunAllocateSendPacket.restype = c_void_p
            wintun.WintunAllocateSendPacket.argtypes = [c_void_p, c_uint]
            wintun.WintunSendPacket.restype = None
            wintun.WintunSendPacket.argtypes = [c_void_p, c_void_p]
            ptr = wintun.WintunAllocateSendPacket(self.session, len(data))
            if not ptr:
                return False
            memmove(ptr, data, len(data))
            wintun.WintunSendPacket(self.session, ptr)
            return True
        except Exception as e:
            debug("WinTun send failed", "ERROR", e)
            return False


class VPNClient:
    def __init__(self, server_host, server_port, packet_callback=None):
        self.server_host = server_host
        self.server_port = int(server_port)
        self.peer_id = str(uuid.uuid4()).replace("-", "")[:8]
        self.username = f"Player_{self.peer_id}"
        self.room_id = None

        # peer_id -> {username, addr, overlay_ip, last_rx, state}
        self.room_members = {}
        self.connected_peers = {}
        self.peer_paths = {}  # peer_id -> "direct" or "relay"
        self.punch_threads = {}

        self.udp_socket = None
        self.wintun = WinTunManager()
        self.running = False
        self.last_server_keepalive = 0.0
        self.packet_callback = packet_callback
        self.overlay_ip = None
        self.overlay_prefix = 24
        self.adapter_name = f"LANVPN-{self.peer_id}"

    def start(self):
        if os.name != "nt":
            debug("This client requires Windows", "ERROR")
            return False
        if not wintun:
            debug("wintun.dll is unavailable", "ERROR")
            return False

        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Keep the same local UDP socket for the whole session. The rendezvous
            # server observes the NAT mapping created by this socket.
            self.udp_socket.bind(("0.0.0.0", 0))
            debug(f"[START] UDP socket bound: local={self.udp_socket.getsockname()}")
            debug(f"[START] HARD-CODED SERVER: host={self.server_host!r} port={self.server_port}")
            debug(f"[START] Server endpoint: {(self.server_host, self.server_port)}")

            if not self.wintun.create_adapter(self.adapter_name):
                return False
            if not self.wintun.start_session():
                return False

            self.running = True
            threading.Thread(target=self._network_loop, daemon=True, name="lanvpn-network").start()
            threading.Thread(target=self._keepalive_loop, daemon=True, name="lanvpn-keepalive").start()
            return True
        except Exception as e:
            debug("Client start failed", "ERROR", e)
            return False

    def stop(self):
        self.running = False
        for t in list(self.punch_threads.values()):
            t.join(timeout=0.2)
        self.punch_threads.clear()
        self.wintun.stop_session()
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except Exception:
                pass
        self.udp_socket = None

    # -----------------------------
    # WinTun / Windows networking
    # -----------------------------

    def configure_virtual_network(self, overlay_ip, prefix=24):
        self.overlay_ip = overlay_ip
        self.overlay_prefix = prefix

        if not overlay_ip:
            return False

        # Wintun is L3. Give Windows an address on the overlay so normal
        # applications/games can route IPv4 traffic through the adapter.
        ps = (
            "$ErrorActionPreference='Stop'; "
            f"$n='{self.adapter_name}'; "
            f"$ip='{overlay_ip}'; "
            f"Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.IPAddress -ne $ip} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
            f"if (-not (Get-NetIPAddress -InterfaceAlias $n -IPAddress $ip -ErrorAction SilentlyContinue)) "
            f"{{ New-NetIPAddress -InterfaceAlias $n -IPAddress $ip -PrefixLength {prefix} -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null }}; "
            f"Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -Dhcp Disabled -InterfaceMetric 5 -NlMtuBytes 1350 | Out-Null"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0:
                debug("Failed to configure WinTun IP", "ERROR", extra=result.stderr.strip())
                return False
            debug(f"Overlay configured: {overlay_ip}/{prefix} on {self.adapter_name}")
            return True
        except Exception as e:
            debug("WinTun IP configuration failed", "ERROR", e)
            return False

    # -----------------------------
    # Rendezvous / rooms
    # -----------------------------

    def create_room(self, room_id, username):
        debug(f"[ROOM] Create requested: room_id={room_id!r} username={username!r}")
        debug(f"[ROOM] Target server: {self.server_host}:{self.server_port}")
        self.room_id = room_id.strip()
        self.username = username.strip() or self.username
        self._send_to_server({
            "action": "create_room",
            "room_id": self.room_id,
            "peer_id": self.peer_id,
            "username": self.username
        })

    def join_room(self, room_id, username):
        debug(f"[ROOM] Join requested: room_id={room_id!r} username={username!r}")
        debug(f"[ROOM] Target server: {self.server_host}:{self.server_port}")
        self.room_id = room_id.strip()
        self.username = username.strip() or self.username
        self._send_to_server({
            "action": "join_room",
            "room_id": self.room_id,
            "peer_id": self.peer_id,
            "username": self.username
        })

    def leave_room(self):
        if self.room_id:
            self._send_to_server({
                "action": "leave_room",
                "room_id": self.room_id,
                "peer_id": self.peer_id
            })
        self.room_id = None
        self.room_members.clear()
        self.connected_peers.clear()
        self.peer_paths.clear()
        self.overlay_ip = None

    # -----------------------------
    # UDP loop / framing
    # -----------------------------

    def _network_loop(self):
        while self.running:
            try:
                readable, _, _ = select.select([self.udp_socket], [], [], 0.01)
                if self.udp_socket in readable:
                    data, addr = self.udp_socket.recvfrom(MAX_UDP)
                    debug(f"[UDP RX] bytes={len(data)} source={addr} magic={data[:4]!r}")
                    self._handle_udp(data, addr)

                # WintunReceivePacket is polled; never block the UDP socket.
                packet = self.wintun.receive_packet()
                if packet:
                    self._forward_tun_packet(packet)
            except (OSError, ValueError):
                if self.running:
                    time.sleep(0.05)
            except Exception as e:
                debug("Network loop error", "ERROR", e)
                time.sleep(0.1)

    def _handle_udp(self, data, addr):
        if data.startswith(CONTROL_MAGIC):
            message = unpack_control(data)
            if message:
                self._handle_control(message, addr)
            return

        if data.startswith(DATA_MAGIC):
            source_peer, packet = unpack_data(data)
            self._handle_peer_packet(source_peer, packet, addr, direct=True)
            return

        if data.startswith(RELAY_MAGIC):
            if len(data) >= 4 + PEER_ID_LEN * 2:
                target = data[4:4 + PEER_ID_LEN].decode("ascii", errors="ignore").rstrip("_")
                source = data[4 + PEER_ID_LEN:4 + PEER_ID_LEN * 2].decode("ascii", errors="ignore").rstrip("_")
                packet = data[4 + PEER_ID_LEN * 2:]
                if target == self.peer_id:
                    # This datagram came from the rendezvous server. It proves
                    # relay reachability, NOT direct peer reachability.
                    self._record_relay_peer(source)
                    self._handle_peer_packet(source, packet, addr, direct=False)
            return

        # Ignore unframed Internet traffic. This prevents a random IP packet
        # from being mistaken for control JSON.
        debug(f"Ignored unframed UDP packet from {addr}", "WARNING")

    def _handle_control(self, message, addr):
        action = message.get("action")
        debug(f"[CONTROL RX] source={addr} action={action!r} message={message}")

        if action in ("room_created", "room_joined", "peer_list"):
            members = message.get("members", {})
            self.room_members = {}
            for pid, info in members.items():
                if pid == self.peer_id:
                    self.overlay_ip = info.get("overlay_ip")
                    continue
                self.room_members[pid] = {
                    "username": info.get("username", pid),
                    "addr": self._valid_addr(info.get("public_ip"), info.get("public_port")),
                    "overlay_ip": info.get("overlay_ip"),
                    "last_rx": 0.0,
                    "state": "DISCOVERED"
                }
            own = message.get("self", {})
            if own.get("overlay_ip"):
                self.overlay_ip = own["overlay_ip"]

            if self.overlay_ip:
                self.configure_virtual_network(self.overlay_ip, message.get("prefix", 24))

            debug(f"Room ready; overlay={self.overlay_ip}; peers={len(self.room_members)}")
            for pid in self.room_members:
                self._start_punch(pid)
            return

        if action == "peer_joined":
            pid = message.get("peer_id")
            if not pid or pid == self.peer_id:
                return
            self.room_members[pid] = {
                "username": message.get("username", pid),
                "addr": self._valid_addr(message.get("public_ip"), message.get("public_port")),
                "overlay_ip": message.get("overlay_ip"),
                "last_rx": 0.0,
                "state": "DISCOVERED"
            }
            debug(f"Peer discovered: {pid} -> {self.room_members[pid]['addr']}")
            self._start_punch(pid)
            return

        if action == "peer_left":
            pid = message.get("peer_id")
            self.room_members.pop(pid, None)
            self.connected_peers.pop(pid, None)
            self.peer_paths.pop(pid, None)
            return

        if action == "punch":
            pid = message.get("peer_id")
            if not pid or pid == self.peer_id or not self.room_id:
                return
            # The source address from recvfrom() is authoritative. NAT may map
            # the same local port to a different public endpoint.
            self._record_direct_peer(pid, addr)
            self._send_message({
                "action": "punch_ack",
                "room_id": self.room_id,
                "peer_id": self.peer_id,
                "target_peer": pid
            }, addr)
            return

        if action == "punch_ack":
            pid = message.get("peer_id")
            if pid and pid != self.peer_id:
                self._record_direct_peer(pid, addr)
            return

        if action == "peer_ping":
            pid = message.get("peer_id")
            if pid and pid != self.peer_id:
                self._record_direct_peer(pid, addr)
                self._send_message({
                    "action": "peer_pong",
                    "room_id": self.room_id,
                    "peer_id": self.peer_id
                }, addr)
            return

        if action == "peer_pong":
            pid = message.get("peer_id")
            if pid and pid in self.room_members:
                self.room_members[pid]["last_rx"] = time.time()
                self._record_direct_peer(pid, addr)
            return

    def _record_direct_peer(self, peer_id, addr):
        if peer_id not in self.room_members and peer_id != self.peer_id:
            self.room_members[peer_id] = {
                "username": peer_id,
                "addr": addr,
                "overlay_ip": None,
                "last_rx": 0.0,
                "state": "CONNECTED"
            }
        elif peer_id in self.room_members:
            self.room_members[peer_id]["addr"] = addr
            self.room_members[peer_id]["last_rx"] = time.time()
            self.room_members[peer_id]["state"] = "CONNECTED"
        self.connected_peers[peer_id] = addr
        self.peer_paths[peer_id] = "direct"
        debug(f"Direct path confirmed: {peer_id} @ {addr}")

    def _record_relay_peer(self, peer_id):
        if peer_id == self.peer_id:
            return
        if peer_id in self.room_members:
            self.room_members[peer_id]["last_rx"] = time.time()
            self.room_members[peer_id]["state"] = "RELAY"
        self.connected_peers.pop(peer_id, None)
        self.peer_paths[peer_id] = "relay"
        debug(f"Relay path confirmed: {peer_id}")

    def _start_punch(self, peer_id):
        if peer_id in self.connected_peers or peer_id in self.punch_threads:
            return
        t = threading.Thread(target=self._punch_worker, args=(peer_id,), daemon=True)
        self.punch_threads[peer_id] = t
        t.start()

    def _punch_worker(self, peer_id):
        started = time.time()
        try:
            while self.running and time.time() - started < PUNCH_DURATION:
                if peer_id in self.connected_peers:
                    return
                info = self.room_members.get(peer_id)
                addr = info.get("addr") if info else None
                if addr:
                    self._send_message({
                        "action": "punch",
                        "room_id": self.room_id,
                        "peer_id": self.peer_id,
                        "target_peer": peer_id
                    }, addr)
                time.sleep(PUNCH_INTERVAL)

            # NATs that cannot form a direct mapping can still use the
            # rendezvous server as a UDP relay.
            if self.running and peer_id not in self.connected_peers:
                info = self.room_members.get(peer_id)
                if info:
                    info["state"] = "RELAY"
                    debug(f"No direct path to {peer_id}; relay fallback enabled", "WARNING")
        finally:
            pass

    def _valid_addr(self, public_ip, public_port):
        try:
            ip = ipaddress.ip_address(str(public_ip))
            port = int(public_port)
            if ip.version != 4 or not 1 <= port <= 65535:
                return None
            return str(ip), port
        except (ValueError, TypeError):
            return None

    def _send_message(self, message, addr):
        if not self.udp_socket or not addr:
            return False
        try:
            payload = pack_control(message)
            debug(f"[UDP TX] CONTROL bytes={len(payload)} destination={addr} action={message.get('action')}")
            sent = self.udp_socket.sendto(payload, addr)
            debug(f"[UDP TX] CONTROL sendto returned={sent} destination={addr}")
            return sent == len(payload)
        except OSError as e:
            debug(f"UDP send failed to {addr}", "WARNING", e)
            return False

    def _send_to_server(self, message):
        addr = (self.server_host, self.server_port)
        debug(f"[SERVER TX] destination={addr} message={message}")
        result = self._send_message(message, addr)
        debug(f"[SERVER TX] result={'SENT' if result else 'FAILED'} destination={addr}")
        return result

    def _keepalive_loop(self):
        last_peer_ping = 0.0
        while self.running:
            now = time.time()

            if self.room_id and now - self.last_server_keepalive >= SERVER_KEEPALIVE:
                self._send_to_server({
                    "action": "keepalive",
                    "room_id": self.room_id,
                    "peer_id": self.peer_id,
                    "username": self.username,
                })
                self.last_server_keepalive = now

            if self.room_id and now - last_peer_ping >= PEER_KEEPALIVE:
                for pid, info in list(self.room_members.items()):
                    addr = info.get("addr")
                    if addr:
                        self._send_message({
                            "action": "peer_ping",
                            "room_id": self.room_id,
                            "peer_id": self.peer_id,
                        }, addr)
                last_peer_ping = now

            cutoff = now - PEER_TIMEOUT
            for pid, info in list(self.room_members.items()):
                if info.get("last_rx", 0.0) and info["last_rx"] < cutoff:
                    self.connected_peers.pop(pid, None)
                    self.peer_paths.pop(pid, None)
                    info["state"] = "TIMEOUT"

            time.sleep(0.5)

    def _forward_tun_packet(self, packet):
        debug(f"[TUN RX] packet_received bytes={len(packet) if packet else 0}")
        if not packet or len(packet) > OVERLAY_MTU:
            if packet:
                debug(f"Dropped oversized WinTun packet ({len(packet)} bytes)", "WARNING")
            return

        try:
            if len(packet) < 20 or (packet[0] >> 4) != 4:
                return

            dst_ip = ipaddress.ip_address(packet[16:20])
            src_ip = ipaddress.ip_address(packet[12:16])
            debug(f"[ROUTE] IPv4 packet src={src_ip} dst={dst_ip} bytes={len(packet)}")
            targets = []

            if dst_ip == ipaddress.IPv4Address("255.255.255.255") or dst_ip.is_multicast:
                targets = list(self.room_members)
            else:
                for pid, info in self.room_members.items():
                    if info.get("overlay_ip") == str(dst_ip):
                        targets = [pid]
                        break

                if not targets and self.overlay_ip:
                    try:
                        overlay = ipaddress.ip_network(
                            f"{self.overlay_ip}/{self.overlay_prefix}", strict=False
                        )
                        if dst_ip in overlay:
                            targets = list(self.room_members)
                    except ValueError:
                        pass

            debug(f"[ROUTE] selected_peers={targets}")
            for pid in targets:
                self._send_tunnel_packet(pid, packet)
        except Exception as e:
            debug("WinTun forwarding failed", "ERROR", e)

    def _send_tunnel_packet(self, peer_id, packet):
        if len(packet) > OVERLAY_MTU:
            return False

        if self.peer_paths.get(peer_id) == "direct":
            addr = self.connected_peers.get(peer_id)
            if addr:
                try:
                    payload = pack_data(self.peer_id, packet)
                    debug(f"[PEER TX] DIRECT peer={peer_id} destination={addr} bytes={len(payload)}")
                    sent = self.udp_socket.sendto(payload, addr)
                    debug(f"[PEER TX] DIRECT result={sent} peer={peer_id}")
                    return sent == len(payload)
                except OSError as e:
                    debug(f"Direct send failed to {peer_id}", "WARNING", e)
                    self.connected_peers.pop(peer_id, None)
                    self.peer_paths[peer_id] = "relay"

        try:
            relay_addr = (self.server_host, self.server_port)
            payload = pack_relay(peer_id, self.peer_id, packet)
            debug(f"[PEER TX] RELAY target={peer_id} server={relay_addr} bytes={len(payload)}")
            sent = self.udp_socket.sendto(payload, relay_addr)
            debug(f"[PEER TX] RELAY result={sent} target={peer_id}")
            return sent == len(payload)
        except OSError as e:
            debug(f"Relay send failed to {peer_id}", "WARNING", e)
            return False

    def _handle_peer_packet(self, source_peer, packet, addr, direct=False):
        if not source_peer or source_peer == self.peer_id:
            return
        if len(packet) > OVERLAY_MTU:
            return

        if direct:
            self._record_direct_peer(source_peer, addr)
        else:
            self._record_relay_peer(source_peer)

        if self.wintun.session:
            self.wintun.send_packet(packet)

        if self.packet_callback:
            try:
                self.packet_callback(source_peer, packet)
            except Exception as e:
                debug("Packet callback failed", "WARNING", e)


class VPNApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LAN Simulator")
        self.root.geometry("720x520")
        self.client = None

        frame = ttk.Frame(root, padding=14)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="LAN Simulator",
                  font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(frame, text="WinTun overlay • direct P2P • relay fallback").pack(
            anchor="w", pady=(0, 12)
        )

        form = ttk.LabelFrame(frame, text="Connection", padding=10)
        form.pack(fill="x")

        self.server_var = tk.StringVar(value="80.225.223.253")
        self.port_var = tk.StringVar(value="5000")
        self.username_var = tk.StringVar(
            value=f"Player_{str(uuid.uuid4()).replace('-', '')[:8]}"
        )
        self.room_var = tk.StringVar()

        for row, (label, var) in enumerate([
            ("Server", self.server_var),
            ("UDP Port", self.port_var),
            ("Username", self.username_var),
            ("Room ID", self.room_var),
        ]):
            ttk.Label(form, text=label).grid(
                row=row, column=0, sticky="w", padx=(0, 10), pady=5
            )
            ttk.Entry(form, textvariable=var, width=42).grid(
                row=row, column=1, sticky="ew", pady=5
            )
        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=12)
        ttk.Button(buttons, text="Create Room", command=self.create_room).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="Join Room", command=self.join_room).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="Leave / Disconnect", command=self.leave_room).pack(
            side="left"
        )

        self.status = tk.StringVar(value="Disconnected")
        ttk.Label(frame, textvariable=self.status,
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

        log_frame = ttk.LabelFrame(frame, text="Log", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log = scrolledtext.ScrolledText(log_frame, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)

        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _append_log(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _ensure_client(self):
        if self.client and self.client.running:
            return True

        host = self.server_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
            if not host or not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid server", "Enter a valid server and UDP port.")
            return False

        debug(f"[GUI] Creating VPNClient with server={host!r}:{port}")
        self.client = VPNClient(host, port)
        debug(f"[GUI] VPNClient actual server_host={self.client.server_host!r} server_port={self.client.server_port}")
        debug("[GUI] Calling VPNClient.start()")
        if not self.client.start():
            self.client = None
            messagebox.showerror(
                "Client startup failed",
                "WinTun could not be started. Run as Administrator and ensure "
                "wintun.dll is beside client.py."
            )
            return False
        return True

    def create_room(self):
        debug("[GUI] CREATE ROOM button clicked")
        room = self.room_var.get().strip()
        if not room:
            messagebox.showerror("Room ID", "Enter a room ID.")
            return
        if self._ensure_client():
            debug(f"[GUI] Calling create_room(room={room!r})")
            self.client.create_room(room, self.username_var.get().strip())
            self.status.set(f"Creating room: {room}")

    def join_room(self):
        debug("[GUI] JOIN ROOM button clicked")
        room = self.room_var.get().strip()
        if not room:
            messagebox.showerror("Room ID", "Enter a room ID.")
            return
        if self._ensure_client():
            debug(f"[GUI] Calling join_room(room={room!r})")
            self.client.join_room(room, self.username_var.get().strip())
            self.status.set(f"Joining room: {room}")

    def leave_room(self):
        if self.client:
            try:
                self.client.leave_room()
                self.client.stop()
            except Exception as e:
                debug("Disconnect failed", "WARNING", e)
            self.client = None
        self.status.set("Disconnected")

    def close(self):
        self.leave_room()
        self.root.destroy()


def main():
    if os.name != "nt":
        print("This client requires Windows.")
        return
    root = tk.Tk()
    VPNApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
