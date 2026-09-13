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

# Optional Windows packet-capture dependency used only for LAN discovery bridging.
# PyDivert requires the WinDivert driver/DLL to be installed on Windows.
try:
    import pydivert
except ImportError:
    pydivert = None

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

# End-to-end diagnostic packet. It is embedded in a real IPv4/UDP packet,
# injected into WinTun, picked back up by the TUN reader, transported to a peer,
# detected before WinTun injection, and then injected into the peer's WinTun.
TEST_MAGIC = b"LANTEST1"
TEST_ACK_MAGIC = b"LANTACK1"
TEST_PORT = 47999
TEST_INTERVAL = 15.0
TEST_TIMEOUT = 12.0
TEST_PORT_BASE = 48000


class TrafficStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.started_at = time.time()
        self.reset_runtime()

    def reset_runtime(self):
        self.tun_rx_packets = 0
        self.tun_rx_bytes = 0
        self.tun_tx_packets = 0
        self.tun_tx_bytes = 0
        self.udp_tx_packets = 0
        self.udp_tx_bytes = 0
        self.udp_rx_packets = 0
        self.udp_rx_bytes = 0
        self.data_tx_packets = 0
        self.data_tx_bytes = 0
        self.data_rx_packets = 0
        self.data_rx_bytes = 0
        self.relay_tx_packets = 0
        self.relay_rx_packets = 0
        self.direct_tx_packets = 0
        self.direct_rx_packets = 0
        self.test_tx = 0
        self.test_picked = 0
        self.test_received = 0
        self.test_injected = 0
        self.test_ack_injected = 0
        self.test_ack_sent = 0
        self.test_ack_received = 0
        self.test_acked = 0
        self.test_ack_app_rx = 0
        self.test_app_rx = 0
        self.test_app_tx = 0
        self.test_failed = 0
        self.test_last_id = None
        self.test_last_result = "Not run"
        self.test_last_peer = None
        self.test_last_time = 0.0
        self.event_count = 0
        self.events = []
        self.peer_stats = {}

    def inc(self, **values):
        with self.lock:
            for key, value in values.items():
                setattr(self, key, getattr(self, key, 0) + value)

    def inc_peer(self, peer_id, **values):
        if not peer_id:
            return
        with self.lock:
            item = self.peer_stats.setdefault(peer_id, {"rx_packets": 0, "rx_bytes": 0, "tx_packets": 0, "tx_bytes": 0})
            for key, value in values.items():
                item[key] = item.get(key, 0) + value

    def snapshot_peer_stats(self):
        with self.lock:
            return {pid: dict(v) for pid, v in self.peer_stats.items()}

    def add_event(self, category, message, level="INFO"):
        item = {"time": time.time(), "category": category, "message": message, "level": level}
        with self.lock:
            self.event_count += 1
            self.events.append(item)
            if len(self.events) > 500:
                del self.events[:-500]

    def snapshot_events(self):
        with self.lock:
            return list(self.events)

    def snapshot(self):
        with self.lock:
            return dict(self.__dict__, lock=None)


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
        # Real application endpoint used by the E2E diagnostic responder.
        # ACKs are generated with normal UDP sendto(), never WintunSendPacket().
        self.test_socket = None
        self.wintun = WinTunManager()
        self.running = False
        self.last_server_keepalive = 0.0
        self.packet_callback = packet_callback
        self.overlay_ip = None
        self.overlay_prefix = 24
        # Every process gets its own persistent WinTun adapter.  The peer_id is
        # deliberately part of the adapter name so two clients started on the
        # same Windows machine never try to open the same adapter.
        self.adapter_name = f"LANVPN-{self.peer_id}"
        self.interface_index = None
        self.installed_peer_routes = set()
        self.stats = TrafficStats()
        self._test_counter = 0
        self._last_test_tick = 0.0
        self.capture_packets = False
        self._pending_test_ids = set()
        self._pending_test_lock = threading.Lock()

        # LAN discovery bridge state. This is deliberately additive: the
        # existing WinTun, P2P, relay, diagnostics, and routing code remains
        # unchanged.
        self.lan_bridge_enabled = True
        self._lan_bridge_thread = None
        self._lan_bridge_handle = None
        self._lan_bridge_stop = threading.Event()
        self._lan_bridge_lock = threading.Lock()
        self._lan_bridge_last_error_log = 0.0

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
        self._stop_lan_discovery_bridge()
        for t in list(self.punch_threads.values()):
            t.join(timeout=0.2)
        self.punch_threads.clear()
        self._remove_peer_routes()
        if self.test_socket:
            try:
                self.test_socket.close()
            except Exception:
                pass
        self.test_socket = None
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
            # Capture the Windows interface index.  It is required for explicit
            # /32 peer routes below.  A normal /24 route is ambiguous when two
            # WinTun adapters on the SAME Windows host use the same overlay.
            idx_ps = (
                f"$a=Get-NetAdapter -Name '{self.adapter_name}' -ErrorAction Stop; "
                "[Console]::Out.Write($a.ifIndex)"
            )
            idx_result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", idx_ps],
                capture_output=True, text=True, timeout=10
            )
            if idx_result.returncode != 0:
                debug("Could not determine WinTun interface index", "ERROR",
                      extra=idx_result.stderr.strip())
                return False
            self.interface_index = int(idx_result.stdout.strip())

            debug(
                f"Overlay configured: {overlay_ip}/{prefix} on {self.adapter_name} "
                f"(ifIndex={self.interface_index})"
            )
            return True
        except Exception as e:
            debug("WinTun IP configuration failed", "ERROR", e)
            return False

    def _install_peer_route(self, peer_id):
        """Force this client's peer IP into THIS client's WinTun adapter.

        Windows has one global routing table.  Two /24 WinTun interfaces on the
        same host therefore create an ambiguous route.  A /32 route has higher
        specificity and makes unicast traffic generated by this client enter
        its own virtual adapter, where _forward_tun_packet() can encapsulate it.

        This is especially important when two VPNClient processes are running on
        the same physical Windows machine.
        """
        if not self.interface_index:
            return False
        info = self.room_members.get(peer_id)
        peer_ip = info.get("overlay_ip") if info else None
        if not peer_ip:
            return False
        try:
            ipaddress.ip_address(peer_ip)
        except ValueError:
            return False
        if peer_ip == self.overlay_ip:
            return False

        ps = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$if={int(self.interface_index)}; "
            f"$dst='{peer_ip}/32'; "
            "Get-NetRoute -DestinationPrefix $dst -ErrorAction SilentlyContinue | "
            "Where-Object {$_.InterfaceIndex -eq $if} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
            "New-NetRoute -DestinationPrefix $dst -InterfaceIndex $if "
            "-NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null; "
            "[Console]::Out.Write('OK')"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "OK" in result.stdout:
                self.installed_peer_routes.add(peer_ip)
                debug(f"[ROUTE] Installed {peer_ip}/32 via {self.adapter_name} ifIndex={self.interface_index}")
                return True
            debug(f"[ROUTE] Failed to install {peer_ip}/32", "WARNING",
                  extra=result.stderr.strip())
        except Exception as e:
            debug(f"[ROUTE] Exception installing {peer_ip}/32", "WARNING", e)
        return False

    def _remove_peer_routes(self):
        if not self.interface_index:
            self.installed_peer_routes.clear()
            return
        for peer_ip in list(self.installed_peer_routes):
            ps = (
                "$ErrorActionPreference='SilentlyContinue'; "
                f"Remove-NetRoute -DestinationPrefix '{peer_ip}/32' "
                f"-InterfaceIndex {int(self.interface_index)} -Confirm:$false "
                "-ErrorAction SilentlyContinue"
            )
            try:
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-Command", ps],
                    capture_output=True, text=True, timeout=5
                )
            except Exception:
                pass
        self.installed_peer_routes.clear()

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
            "username": self.username,
            "local_port": self.udp_socket.getsockname()[1] if self.udp_socket else None
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
            "username": self.username,
            "local_port": self.udp_socket.getsockname()[1] if self.udp_socket else None
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
        if self.test_socket:
            try:
                self.test_socket.close()
            except Exception:
                pass
        self.test_socket = None
        self.overlay_ip = None

    def _get_test_port(self):
        """Return a deterministic diagnostic UDP port for this overlay address.

        Each overlay address gets its own port. This matters when two LAN
        Simulator clients run on the SAME Windows host: both cannot own
        0.0.0.0:47999, but their overlay addresses can still be distinct.
        The socket is deliberately bound to 0.0.0.0 rather than the WinTun
        address because Windows may reject bind(overlay_ip, ...) for a
        Wintun L3 interface (WSAEADDRNOTAVAIL / 10049).
        """
        if not self.overlay_ip:
            return None
        try:
            last_octet = int(str(self.overlay_ip).rsplit(".", 1)[1])
            if not 1 <= last_octet <= 254:
                raise ValueError("invalid overlay IPv4 address")
            return TEST_PORT_BASE + last_octet
        except Exception:
            return None

    def _ensure_test_responder(self):
        """Create a real UDP application endpoint for E2E diagnostics.

        IMPORTANT:
        - Bind to 0.0.0.0, not the WinTun overlay IP. Windows can report
          WSAEADDRNOTAVAIL (10049) when a UDP socket is explicitly bound to
          an address owned by a Wintun L3 adapter.
        - Use a deterministic per-overlay port so two simulator processes
          on the same Windows machine can coexist.
        - The socket is a normal Windows UDP application socket. It does not
          call WintunSendPacket.
        """
        if self.test_socket or not self.overlay_ip:
            return self.test_socket is not None

        test_port = self._get_test_port()
        if test_port is None:
            debug("[TEST] RESPONDER_BIND_FAILED invalid overlay/test port", "ERROR")
            self.stats.add_event("ERROR", "Diagnostic UDP responder could not determine a test port", "ERROR")
            return False

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Do NOT use SO_REUSEADDR here. If two processes accidentally
            # choose the same diagnostic port, we want Windows to reject the
            # second bind rather than silently share the endpoint.
            s.bind(("0.0.0.0", test_port))
            s.setblocking(False)
            self.test_socket = s

            debug(
                f"[TEST] RESPONDER_BOUND local=0.0.0.0:{test_port} "
                f"overlay={self.overlay_ip}"
            )
            self.stats.add_event(
                "TEST",
                f"Diagnostic UDP responder bound at 0.0.0.0:{test_port} "
                f"(overlay {self.overlay_ip})"
            )
            return True
        except OSError as e:
            debug(
                f"[TEST] RESPONDER_BIND_FAILED local=0.0.0.0:{test_port} "
                f"overlay={self.overlay_ip}",
                "ERROR",
                e,
            )
            self.stats.add_event(
                "ERROR",
                f"Diagnostic UDP responder bind failed at 0.0.0.0:{test_port}: {e}",
                "ERROR"
            )
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            return False

    def _handle_test_responder(self):
        if not self.test_socket:
            return
        while self.running:
            try:
                payload, addr = self.test_socket.recvfrom(2048)
            except BlockingIOError:
                return
            except OSError:
                return

            if payload.startswith(TEST_MAGIC):
                test_id = payload[len(TEST_MAGIC):].decode("ascii", errors="ignore")
                if not test_id:
                    continue

                self.stats.inc(test_app_rx=1)
                debug(f"[TEST] APP_RX id={test_id} src={addr} bytes={len(payload)}")
                self.stats.add_event(
                    "TRAFFIC",
                    f"APP RX TEST peer=- size={len(payload)+28} path=SOCKET"
                )
                self._emit_event("PACKET", {
                    "direction": "RX", "peer_id": "-", "size": len(payload) + 28,
                    "path": "SOCKET", "type": "TEST", "category": "TRAFFIC",
                    "message": f"RX TEST peer=- size={len(payload)+28} path=SOCKET"
                })

                # Generate the reverse packet as a real application would.
                # This sendto() must be routed by Windows into the sender's
                # /32 WinTun route; no WintunSendPacket shortcut is allowed.
                try:
                    ack_payload = TEST_ACK_MAGIC + test_id.encode("ascii")
                    # Reply to the exact source endpoint. The diagnostic
                    # TEST socket is a real application socket, so its source
                    # port is significant and must be preserved for the ACK.
                    sent = self.test_socket.sendto(ack_payload, addr)
                    self.stats.inc(test_app_tx=1, udp_tx_packets=1, udp_tx_bytes=sent)
                    debug(
                        f"[TEST] APP_SEND_ACK id={test_id} "
                        f"socket=0.0.0.0:{self._get_test_port()} "
                        f"dst={addr} bytes={sent}"
                    )
                    self.stats.add_event(
                        "TRAFFIC",
                        f"APP TX ACK peer=- size={sent+28} path=OS->WinTun"
                    )
                    self._emit_event("PACKET", {
                        "direction": "TX", "peer_id": "-", "size": sent + 28,
                        "path": "OS->WinTun", "type": "ACK", "category": "TRAFFIC",
                        "message": f"TX ACK peer=- size={sent+28} path=OS->WinTun"
                    })
                except OSError as e:
                    self.stats.inc(test_failed=1)
                    debug(f"[TEST] APP_SEND_ACK_FAILED id={test_id}", "ERROR", e)
                    self.stats.add_event("ERROR", f"Diagnostic ACK send failed: {e}", "ERROR")

            elif payload.startswith(TEST_ACK_MAGIC):
                # Final stage: the reverse ACK has traversed the peer tunnel,
                # been injected into this client's WinTun, and is now actually
                # delivered to the local UDP application socket.
                ack_id = payload[len(TEST_ACK_MAGIC):].decode("ascii", errors="ignore")
                if not ack_id:
                    continue

                self.stats.inc(test_ack_app_rx=1)
                peer_id = next(
                    (pid for pid, info in self.room_members.items()
                     if info.get("overlay_ip") == addr[0]),
                    "-"
                )
                debug(f"[TEST] ACK_APP_RX id={ack_id} src={addr}")
                self.stats.add_event(
                    "TRAFFIC",
                    f"APP RX ACK peer={peer_id} size={len(payload)+28} path=SOCKET"
                )
                self._emit_event("PACKET", {
                    "direction": "RX", "peer_id": peer_id, "size": len(payload) + 28,
                    "path": "SOCKET", "type": "ACK", "category": "TRAFFIC",
                    "message": f"RX ACK peer={peer_id} size={len(payload)+28} path=SOCKET"
                })

                with self._pending_test_lock:
                    is_pending = ack_id in self._pending_test_ids
                    if is_pending:
                        self._pending_test_ids.remove(ack_id)

                if is_pending:
                    self.stats.inc(test_acked=1)
                    self.stats.test_last_result = "PASS — complete bidirectional E2E"
                    self.stats.test_last_peer = peer_id
                    self.stats.test_last_id = ack_id
                    debug(f"[TEST] PASS id={ack_id} peer={peer_id}; ACK delivered to local application")
                    self.stats.add_event(
                        "TEST",
                        f"PASS: ACK {ack_id} reached the local UDP application"
                    )
                    self._emit_event("TEST_RESULT", {
                        "ok": True,
                        "test_id": ack_id,
                        "peer_id": peer_id,
                        "transport": self.peer_paths.get(peer_id, "unknown").upper(),
                        "reason": "TEST: local app → WinTun → peer transport → peer WinTun → peer app → reverse transport → local WinTun → local app"
                    })
                else:
                    debug(f"[TEST] STALE_ACK_APP_RX id={ack_id} src={addr}", "WARNING")

    # -----------------------------
    # LAN discovery bridge
    # -----------------------------

    @staticmethod
    def _rewrite_ipv4_source(packet, new_src):
        """Return an IPv4 UDP packet with its source address replaced.

        The UDP payload and ports are preserved. Because the UDP checksum uses
        the IPv4 source address in its pseudo-header, it is recalculated when
        the original packet has a non-zero UDP checksum.
        """
        if not packet or len(packet) < 20 or (packet[0] >> 4) != 4:
            return None

        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl + 8:
            return None

        if packet[9] != socket.IPPROTO_UDP:
            return None

        udp_off = ihl
        udp_len = struct.unpack("!H", packet[udp_off + 4:udp_off + 6])[0]
        if udp_len < 8 or len(packet) < udp_off + udp_len:
            return None

        out = bytearray(packet)
        src = ipaddress.IPv4Address(new_src).packed
        out[12:16] = src

        # Recalculate IPv4 header checksum.
        out[10:12] = b"\x00\x00"
        out[10:12] = struct.pack("!H", VPNClient._checksum(bytes(out[:ihl])))

        # Recalculate UDP checksum if the original packet used one.
        old_udp_sum = struct.unpack(
            "!H", out[udp_off + 6:udp_off + 8]
        )[0]
        if old_udp_sum != 0:
            out[udp_off + 6:udp_off + 8] = b"\x00\x00"
            pseudo = (
                src
                + bytes(out[16:20])
                + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
            )
            udp_sum = VPNClient._checksum(
                pseudo + bytes(out[udp_off:udp_off + udp_len])
            )
            out[udp_off + 6:udp_off + 8] = struct.pack(
                "!H", udp_sum or 0xFFFF
            )

        return bytes(out)

    def _start_lan_discovery_bridge(self):
        """Copy physical UDP broadcast/multicast packets into WinTun.

        The physical packet is restored to the normal Windows path. Only a
        rewritten COPY is injected into WinTun, so ordinary LAN operation is
        not interrupted.

        After entering WinTun, the packet follows the existing
        _forward_tun_packet() routing logic, including direct P2P and relay.
        """
        if not self.lan_bridge_enabled:
            return False

        if pydivert is None:
            debug(
                "[LAN-BRIDGE] PyDivert not installed; bridge unavailable",
                "WARNING",
            )
            return False

        if self._lan_bridge_thread and self._lan_bridge_thread.is_alive():
            return True

        if not self.interface_index or not self.overlay_ip:
            debug(
                "[LAN-BRIDGE] waiting for WinTun interface/overlay configuration"
            )
            return False

        self._lan_bridge_stop.clear()
        self._lan_bridge_thread = threading.Thread(
            target=self._lan_discovery_bridge_loop,
            daemon=True,
            name="lanvpn-discovery-bridge",
        )
        self._lan_bridge_thread.start()
        return True

    def _stop_lan_discovery_bridge(self):
        self._lan_bridge_stop.set()

        with self._lan_bridge_lock:
            handle = self._lan_bridge_handle

        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass

        thread = self._lan_bridge_thread
        if thread and thread.is_alive():
            thread.join(timeout=1.0)

        self._lan_bridge_thread = None

    def _lan_discovery_bridge_loop(self):
        """Capture outbound physical UDP and copy only discovery traffic.

        WinDivert captures the outbound packet before it leaves Windows. The
        original is ALWAYS reinjected first. We then create a separate raw-IP
        copy, rewrite its source address to the overlay address, and inject
        that copy into WinTun.
        """
        # IMPORTANT: exclude our own WinTun interface at the WinDivert filter
        # level.  If we capture every outbound UDP packet and then inject the
        # bridge copy into WinTun, that injected packet is itself outbound and
        # would be captured again, causing a very fast capture/reinject loop.
        # The old implementation tried to exclude WinTun after recv(), which
        # was too late because the packet had already been captured.
        try:
            tun_if = int(self.interface_index)
        except (TypeError, ValueError):
            tun_if = 0

        if tun_if > 0:
            filt = f"outbound and ip and udp and !loopback and !impostor and ifIdx != {tun_if}"
        else:
            filt = "outbound and ip and udp and !loopback and !impostor"

        try:
            handle = pydivert.WinDivert(
                filt, layer=pydivert.Layer.NETWORK
            )
            with self._lan_bridge_lock:
                self._lan_bridge_handle = handle

            handle.open()

            debug(
                f"[LAN-BRIDGE] ACTIVE physical UDP broadcast/multicast -> "
                f"WinTun {self.overlay_ip} ifIndex={self.interface_index}"
            )
            debug(f"[LAN-BRIDGE] WinDivert filter: {filt}")
            self.stats.add_event(
                "LAN-BRIDGE",
                "LAN discovery bridge active: UDP broadcast/multicast is copied into WinTun",
            )

            while self.running and not self._lan_bridge_stop.is_set():
                packet = None
                try:
                    packet = handle.recv()
                    if packet is None:
                        continue

                    raw = bytes(packet.raw)

                    # The filter already excludes our WinTun interface, so
                    # this packet is a physical/outbound packet.  Always put
                    # the original back onto the normal Windows path.
                    # Process a COPY only; never modify the captured object.
                    handle.send(packet, recalculate_checksum=False)

                    if not raw or len(raw) > OVERLAY_MTU:
                        continue
                    if len(raw) < 20 or (raw[0] >> 4) != 4:
                        continue

                    src_ip = ipaddress.IPv4Address(raw[12:16])
                    dst_ip = ipaddress.IPv4Address(raw[16:20])

                    # Only bridge LAN-style UDP discovery:
                    #   global IPv4 broadcast
                    #   IPv4 multicast
                    #   private directed broadcast (x.x.x.255)
                    is_discovery = (
                        dst_ip == ipaddress.IPv4Address("255.255.255.255")
                        or dst_ip.is_multicast
                        or (
                            dst_ip.is_private
                            and (int(dst_ip) & 0xFF) == 0xFF
                        )
                    )

                    # Do not access packet.address here. The installed
                    # PyDivert Packet class does not expose that attribute.
                    # The WinDivert filter handles WinTun exclusion instead.

                    if not is_discovery:
                        continue

                    rewritten = self._rewrite_ipv4_source(
                        raw, self.overlay_ip
                    )
                    if not rewritten or not self.wintun.session:
                        continue

                    if self.wintun.send_packet(rewritten):
                        self.stats.inc(
                            tun_tx_packets=1,
                            tun_tx_bytes=len(rewritten),
                        )
                        self._packet_event(
                            "TX",
                            None,
                            len(rewritten),
                            "LAN-BRIDGE",
                            "IP",
                        )
                        debug(
                            f"[LAN-BRIDGE] COPIED UDP {src_ip} -> {dst_ip} "
                            f"bytes={len(rewritten)} into {self.adapter_name}"
                        )
                        self.stats.add_event(
                            "LAN-BRIDGE",
                            f"Copied UDP discovery packet {src_ip} -> "
                            f"{dst_ip} ({len(rewritten)} bytes) into WinTun",
                        )
                    else:
                        debug(
                            "[LAN-BRIDGE] WinTun injection failed",
                            "WARNING",
                        )

                except Exception as e:
                    if not self._lan_bridge_stop.is_set():
                        # Include the real exception in the log.  Rate-limit
                        # repeated failures so a bad packet cannot flood the
                        # GUI/log and hide the first useful error.
                        now = time.monotonic()
                        last = getattr(self, "_lan_bridge_last_error_log", 0.0)
                        if now - last >= 1.0:
                            self._lan_bridge_last_error_log = now
                            debug(
                                f"[LAN-BRIDGE] packet processing failed: {type(e).__name__}: {e}",
                                "WARNING",
                                e,
                            )

                    # If an exception occurred before restoration in a future
                    # modification, make a best-effort attempt here.
                    if packet is not None:
                        try:
                            # A packet already restored may cause a harmless
                            # duplicate if this branch is reached; WinDivert
                            # will normally have consumed it already.
                            pass
                        except Exception:
                            pass

        except Exception as e:
            debug(
                "[LAN-BRIDGE] failed to start. Install WinDivert/PyDivert "
                "and run the client as Administrator.",
                "WARNING",
                e,
            )
            self.stats.add_event(
                "LAN-BRIDGE",
                f"LAN discovery bridge unavailable: {e}",
                "WARNING",
            )
        finally:
            with self._lan_bridge_lock:
                self._lan_bridge_handle = None

    # -----------------------------
    # Diagnostics / end-to-end test
    # -----------------------------

    def _emit_event(self, event, data=None):
        if self.packet_callback:
            try:
                self.packet_callback(event, data)
            except Exception as e:
                debug(f"Event callback failed: {event}", "WARNING", e)

    def _packet_event(self, direction, peer_id, size, path, packet_type="IP"):
        # Normal game traffic remains opt-in. Diagnostic TEST/ACK packets are
        # always captured so an E2E PASS is inspectable in the GUI.
        diagnostic = packet_type in ("TEST", "ACK")
        if not getattr(self, "capture_packets", False) and not diagnostic:
            return
        data = {
            "direction": direction, "peer_id": peer_id or "-", "size": size,
            "path": path, "type": packet_type,
            "category": "TRAFFIC",
            "message": f"{direction} {packet_type} peer={peer_id or '-'} size={size} path={path}"
        }
        self._emit_event("PACKET", data)
        # Events/Diagnostics gets the same metadata stream. Normal IP packets
        # are included only when capture is enabled; TEST/ACK are always kept.
        self.stats.add_event("TRAFFIC", data["message"])

    def _next_test_id(self):
        self._test_counter = (self._test_counter + 1) & 0xFFFFFFFF
        return f"{self.peer_id}-{self._test_counter:08x}"

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        total = sum(struct.unpack("!%dH" % (len(data)//2), data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def _build_test_ip_packet(self, dst_ip, test_id, magic=TEST_MAGIC):
        src = ipaddress.IPv4Address(self.overlay_ip or "10.250.107.254").packed
        dst = ipaddress.IPv4Address(dst_ip).packed
        payload = magic + test_id.encode("ascii")
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", TEST_PORT, TEST_PORT, udp_len, 0) + payload
        pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
        udp_checksum = self._checksum(pseudo + udp) or 0xFFFF
        udp = struct.pack("!HHHH", TEST_PORT, TEST_PORT, udp_len, udp_checksum) + payload
        total_len = 20 + len(udp)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len,
                             self._test_counter & 0xFFFF, 0, 64, socket.IPPROTO_UDP,
                             0, src, dst)
        checksum = self._checksum(header)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len,
                             self._test_counter & 0xFFFF, 0, 64, socket.IPPROTO_UDP,
                             checksum, src, dst)
        return header + udp

    def _extract_test_packet(self, packet):
        """Return (kind, test_id) for our diagnostic IP packets."""
        try:
            if len(packet) < 28 or (packet[0] >> 4) != 4:
                return None, None
            ihl = (packet[0] & 0x0F) * 4
            if len(packet) < ihl + 8 or packet[9] != socket.IPPROTO_UDP:
                return None, None
            src_port, dst_port = struct.unpack("!HH", packet[ihl:ihl+4])
            # The initial diagnostic packet is created by a normal Windows UDP
            # socket, so its source port is intentionally ephemeral.  Only the
            # destination port is fixed.  ACK packets built by us use TEST_PORT
            # for both ends, but the parser must accept the original packet too.
            if dst_port != TEST_PORT:
                return None, None
            udp_len = struct.unpack("!H", packet[ihl+4:ihl+6])[0]
            if udp_len < 8 or len(packet) < ihl + udp_len:
                return None, None
            body = packet[ihl+8:ihl+udp_len]
            if body.startswith(TEST_MAGIC):
                return "TEST", body[len(TEST_MAGIC):].decode("ascii", errors="ignore")
            if body.startswith(TEST_ACK_MAGIC):
                return "ACK", body[len(TEST_ACK_MAGIC):].decode("ascii", errors="ignore")
        except Exception:
            pass
        return None, None

    def _extract_test_id(self, packet):
        kind, test_id = self._extract_test_packet(packet)
        return test_id if kind == "TEST" else None

    def run_end_to_end_test(self):
        """Create a real UDP/IP packet through Windows, let WinTun pick it up,
        transport it to each peer, and verify the peer receives and injects it.

        The important detail is that we do NOT call WintunSendPacket here.
        The packet originates from a normal Windows UDP application socket
        bound to 0.0.0.0 on this client's diagnostic port. Windows routing
        must select the peer's /32 WinTun route and carry the packet through
        the real network stack.
        """
        if not self.running or not self.room_id or not self.wintun.session:
            self._emit_event("TEST_RESULT", {"ok": False, "reason": "Client/room/WinTun not ready"})
            return False
        peers = list(self.room_members.items())
        if not peers:
            self._emit_event("TEST_RESULT", {"ok": False, "reason": "No peers connected"})
            return False
        if not self.overlay_ip:
            self._emit_event("TEST_RESULT", {"ok": False, "reason": "Overlay IP is not configured"})
            return False

        any_sent = False
        sock = self.test_socket
        test_port = self._get_test_port()
        if sock is None or test_port is None:
            self._emit_event(
                "TEST_RESULT",
                {"ok": False, "reason": "Diagnostic UDP responder is not bound"}
            )
            return False

        # Use the SAME real application socket that will receive the
        # Use the SAME real application socket that will receive the
        # reverse ACK. It is bound to 0.0.0.0:<unique diagnostic port>.
        # Windows chooses the overlay source address from the routing
        local_port = test_port
        for pid, info in peers:
            dst = info.get("overlay_ip")
            if not dst:
                continue
            test_id = self._next_test_id()
            payload = TEST_MAGIC + test_id.encode("ascii")
            self.stats.inc(test_tx=1)
            self.stats.test_last_id = test_id
            self.stats.test_last_peer = pid
            self.stats.test_last_time = time.time()
            with self._pending_test_lock:
                self._pending_test_ids.add(test_id)
            peer_test_port = info.get("test_port")
            if not peer_test_port:
                # Backward-compatible deterministic calculation from the
                # peer overlay address.
                try:
                    peer_test_port = TEST_PORT_BASE + int(str(dst).rsplit(".", 1)[1])
                except Exception:
                    self.stats.inc(test_failed=1)
                    debug(f"[TEST] NO_PEER_TEST_PORT id={test_id} peer={pid} dst={dst}", "ERROR")
                    continue

            debug(
                f"[TEST] CREATE id={test_id} src=0.0.0.0:{local_port} "
                f"(overlay={self.overlay_ip}) dst={dst}:{peer_test_port} "
                f"payload_bytes={len(payload)}"
            )
            try:
                sent = sock.sendto(payload, (dst, int(peer_test_port)))
                self.stats.inc(udp_tx_packets=1, udp_tx_bytes=sent)
                if sent == len(payload):
                    any_sent = True
                    debug(f"[TEST] OS_SEND id={test_id} bytes={sent}; waiting for WinTun pickup")
                else:
                    self.stats.inc(test_failed=1)
            except OSError as e:
                self.stats.inc(test_failed=1)
                debug(f"[TEST] OS_SEND_FAILED id={test_id} dst={dst}", "ERROR", e)
        if any_sent:
            self.stats.test_last_result = "Waiting for WinTun pickup"
            self.stats.add_event("TEST", "Diagnostic UDP packet created by Windows; waiting for WinTun pickup")
            self._emit_event("DIAGNOSTIC_EVENT", {
                "category": "TEST",
                "message": "Diagnostic UDP packet created by Windows; waiting for WinTun pickup",
                "level": "INFO"
            })

            # Do not declare success merely because sendto() accepted the UDP
            # payload.  Success requires the packet to traverse WinTun, reach
            # the peer, be injected there, and return as an ACK.
            threading.Thread(target=self._test_timeout_worker, daemon=True,
                             name="lanvpn-e2e-timeout").start()
        else:
            self.stats.test_last_result = "Failed to create/send diagnostic packet"
            self._emit_event("TEST_RESULT", {
                "ok": False,
                "reason": "Could not create/send diagnostic UDP packet"
            })
        return any_sent

    def _test_timeout_worker(self):
        time.sleep(TEST_TIMEOUT)
        with self._pending_test_lock:
            pending = list(self._pending_test_ids)
            if not pending:
                return
            self._pending_test_ids.clear()
        self.stats.inc(test_failed=1)
        self.stats.test_last_result = "FAIL — ACK timeout"
        self.stats.add_event("TEST", "FAIL: no diagnostic ACK returned within timeout", "ERROR")
        self._emit_event("TEST_RESULT", {
            "ok": False,
            "test_id": pending[-1],
            "reason": f"No diagnostic ACK returned within {TEST_TIMEOUT:.0f} seconds"
        })

    # -----------------------------
    # UDP loop / framing
    # -----------------------------

    def _network_loop(self):
        while self.running:
            try:
                read_sockets = [self.udp_socket]
                if self.test_socket:
                    read_sockets.append(self.test_socket)
                readable, _, _ = select.select(read_sockets, [], [], 0.01)
                if self.udp_socket in readable:
                    data, addr = self.udp_socket.recvfrom(MAX_UDP)
                    self.stats.inc(udp_rx_packets=1, udp_rx_bytes=len(data))
                    debug(f"[UDP RX] bytes={len(data)} source={addr} magic={data[:4]!r}")
                    self._handle_udp(data, addr)

                if self.test_socket and self.test_socket in readable:
                    self._handle_test_responder()

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
            self.stats.inc(data_rx_packets=1, data_rx_bytes=len(packet or b""), direct_rx_packets=1)
            self.stats.inc_peer(source_peer, rx_packets=1, rx_bytes=len(packet or b""))
            self._packet_event("RX", source_peer, len(packet or b""), "DIRECT", self._extract_test_packet(packet)[0] if self._extract_test_packet(packet)[0] in ("TEST", "ACK") else "IP")
            self._handle_peer_packet(source_peer, packet, addr, direct=True)
            return

        if data.startswith(RELAY_MAGIC):
            if len(data) >= 4 + PEER_ID_LEN * 2:
                target = data[4:4 + PEER_ID_LEN].decode("ascii", errors="ignore").rstrip("_")
                source = data[4 + PEER_ID_LEN:4 + PEER_ID_LEN * 2].decode("ascii", errors="ignore").rstrip("_")
                packet = data[4 + PEER_ID_LEN * 2:]
                if target == self.peer_id:
                    self.stats.inc(data_rx_packets=1, data_rx_bytes=len(packet), relay_rx_packets=1)
                    self.stats.inc_peer(source, rx_packets=1, rx_bytes=len(packet))
                    self._packet_event("RX", source, len(packet), "RELAY", self._extract_test_packet(packet)[0] if self._extract_test_packet(packet)[0] in ("TEST", "ACK") else "IP")
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
                if not self.configure_virtual_network(self.overlay_ip, message.get("prefix", 24)):
                    return
                for pid in self.room_members:
                    self._install_peer_route(pid)

                # Real UDP application endpoint for the diagnostic test.
                self._ensure_test_responder()

                # Copy actual LAN broadcast/multicast discovery traffic into
                # WinTun. The existing P2P/relay path remains responsible for
                # transporting the copied packet to room peers.
                self._start_lan_discovery_bridge()

            debug(f"Room ready; overlay={self.overlay_ip}; peers={len(self.room_members)}")
            if self.packet_callback:
                try:
                    self.packet_callback("__ROOM_READY__", None)
                except Exception as e:
                    debug("Room-ready callback failed", "WARNING", e)
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
            self._install_peer_route(pid)
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
        was = self.peer_paths.get(peer_id)
        self.connected_peers[peer_id] = addr
        self.peer_paths[peer_id] = "direct"
        self._install_peer_route(peer_id)
        if was != "direct":
            debug(f"Direct path confirmed: {peer_id} @ {addr}")
            self.stats.add_event("CONNECTION", f"Direct path confirmed: {peer_id} @ {addr}")
            self._emit_event("DIAGNOSTIC_EVENT", {"category":"CONNECTION","message":f"Direct path confirmed: {peer_id}","level":"INFO"})

    def _record_relay_peer(self, peer_id):
        if peer_id == self.peer_id:
            return
        if peer_id in self.room_members:
            self.room_members[peer_id]["last_rx"] = time.time()
            self.room_members[peer_id]["state"] = "RELAY"
        self.connected_peers.pop(peer_id, None)
        was = self.peer_paths.get(peer_id)
        self.peer_paths[peer_id] = "relay"
        if was != "relay":
            debug(f"Relay path confirmed: {peer_id}")
            self.stats.add_event("CONNECTION", f"Relay path active: {peer_id}")
            self._emit_event("DIAGNOSTIC_EVENT", {"category":"CONNECTION","message":f"Relay path active: {peer_id}","level":"INFO"})

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
                    self.peer_paths[peer_id] = "relay"
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
            self.stats.inc(udp_tx_packets=1, udp_tx_bytes=sent)
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
        if packet:
            self.stats.inc(tun_rx_packets=1, tun_rx_bytes=len(packet))
            kind, diag_id = self._extract_test_packet(packet)
            self._packet_event("RX", None, len(packet), "TUN", kind if kind in ("TEST", "ACK") else "IP")
            test_id = self._extract_test_id(packet)
            if kind == "ACK":
                # An ACK injected by a peer into its WinTun adapter is an
                # outbound overlay packet.  If this client did not originate
                # the test, there is no local pending ID, so the ACK MUST be
                # allowed to continue through the normal routing/transport
                # path.  Only the originating client consumes the ACK as the
                # final E2E result.
                with self._pending_test_lock:
                    is_pending = diag_id in self._pending_test_ids
                if is_pending:
                    # This branch means an ACK somehow originated locally.
                    # Keep it routable; final success is recorded when the
                    # remote ACK is received and successfully injected below.
                    debug(f"[TEST] ACK_LOCAL_PICKUP id={diag_id}; routing ACK to peer")
                    self.stats.add_event("TEST", f"ACK packet picked up locally: {diag_id}; routing")
                else:
                    debug(f"[TEST] ACK_OUTBOUND id={diag_id} from WinTun; routing to peer")
                    self.stats.add_event("TEST", f"ACK picked up by WinTun and routed: {diag_id}")
                # Do not return.  ACK is a real overlay IP packet and must be
                # routed like ordinary traffic.
            if kind == "TEST":
                self.stats.inc(test_picked=1)
                debug(f"[TEST] PICKED id={diag_id} from WinTun")
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
                    self.stats.inc(udp_tx_packets=1, udp_tx_bytes=sent, data_tx_packets=1, data_tx_bytes=len(packet), direct_tx_packets=1)
                    self.stats.inc_peer(peer_id, tx_packets=1, tx_bytes=len(packet))
                    self._packet_event("TX", peer_id, len(packet), "DIRECT", self._extract_test_packet(packet)[0] if self._extract_test_packet(packet)[0] in ("TEST", "ACK") else "IP")
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
            self.stats.inc(udp_tx_packets=1, udp_tx_bytes=sent, data_tx_packets=1, data_tx_bytes=len(packet), relay_tx_packets=1)
            self.stats.inc_peer(peer_id, tx_packets=1, tx_bytes=len(packet))
            self._packet_event("TX", peer_id, len(packet), "RELAY", self._extract_test_packet(packet)[0] if self._extract_test_packet(packet)[0] in ("TEST", "ACK") else "IP")
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

        kind, diag_id = self._extract_test_packet(packet)
        test_id = diag_id if kind == "TEST" else None
        ack_id = diag_id if kind == "ACK" else None

        if test_id:
            self.stats.inc(test_received=1)
            self.stats.test_last_id = test_id
            self.stats.test_last_peer = source_peer
            self.stats.test_last_time = time.time()
            debug(f"[TEST] RECEIVED id={test_id} from={source_peer} transport={'DIRECT' if direct else 'RELAY'}")
            self.stats.add_event("TEST", f"Peer {source_peer} received diagnostic {test_id} via {'DIRECT' if direct else 'RELAY'}")

        # A diagnostic ACK is itself a normal overlay IP packet.  When it
        # arrives from the peer, inject it into THIS client's WinTun adapter.
        # This proves the reverse tunnel direction and delivers the ACK to the
        # originating client's Windows IP stack.
        if ack_id:
            self.stats.test_last_id = ack_id
            self.stats.test_last_peer = source_peer
            injected_ack = False
            if self.wintun.session:
                injected_ack = self.wintun.send_packet(packet)
            if injected_ack:
                self.stats.inc(test_ack_received=1, tun_tx_packets=1, tun_tx_bytes=len(packet))
                self._packet_event("TX", source_peer, len(packet), "TUN-INJECT-ACK", "ACK")
                debug(
                    f"[TEST] ACK_INJECT_LOCAL id={ack_id} peer={source_peer}; "
                    f"waiting for local UDP application delivery"
                )
                self.stats.add_event(
                    "TEST",
                    f"ACK {ack_id} injected into local WinTun; waiting for local application RX"
                )
            else:
                self.stats.inc(test_failed=1)
                debug(f"[TEST] ACK_INJECT_FAILED id={ack_id} peer={source_peer}", "ERROR")
                self.stats.add_event(
                    "ERROR",
                    f"ACK received from {source_peer} but local WinTun injection failed: {ack_id}",
                    "ERROR"
                )
                self._emit_event("TEST_RESULT", {
                    "ok": False,
                    "peer_id": source_peer,
                    "test_id": ack_id,
                    "reason": "Diagnostic ACK received but local WinTun injection failed"
                })
            return

        injected = False
        if self.wintun.session:
            injected = self.wintun.send_packet(packet)
            if injected:
                self.stats.inc(tun_tx_packets=1, tun_tx_bytes=len(packet))
                self._packet_event("TX", source_peer, len(packet), "TUN-INJECT", "TEST" if test_id else "IP")
                if test_id:
                    self.stats.inc(test_injected=1)
                    self.stats.test_last_result = f"Peer received via {'DIRECT' if direct else 'RELAY'}; diagnostic injected; generating reverse ACK"
                    debug(f"[TEST] INJECTED_REMOTE id={test_id} peer={source_peer} into WinTun")
                    self.stats.add_event("TEST", f"Diagnostic {test_id} injected into peer WinTun; creating reverse ACK")

                    # No ACK is injected with WintunSendPacket here.
                    # The TEST was injected above; Windows must deliver it to
                    # the real overlay UDP responder. That application socket
                    # creates the ACK with sendto(), which must then be picked
                    # up by WinTun and transported back normally.
                    debug(
                        f"[TEST] REMOTE_INJECTED id={test_id} peer={source_peer}; "
                        f"waiting for peer UDP responder at {self.overlay_ip}:{TEST_PORT}"
                    )
                    self.stats.add_event(
                        "TEST",
                        f"Diagnostic {test_id} injected into peer WinTun; waiting for peer application RX"
                    )
            elif test_id:
                self.stats.inc(test_failed=1)
                self.stats.test_last_result = "FAIL: remote WinTun injection"
                debug(f"[TEST] REMOTE_INJECT_FAILED id={test_id} peer={source_peer}", "ERROR")
                self._emit_event("TEST_RESULT", {"ok": False, "peer_id": source_peer, "test_id": test_id, "reason": "Remote WinTun injection failed"})

        if self.packet_callback:
            try:
                self.packet_callback(source_peer, packet)
            except Exception as e:
                debug("Packet callback failed", "WARNING", e)


class VPNApp:
    """Operator-focused GUI: summary counters by default, structured events on demand.

    Packet-level logging is deliberately opt-in so high-rate game traffic does not
    flood the UI. The E2E test produces only a small, ordered diagnostic trace.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("LAN Simulator — Network Diagnostics")
        self.root.geometry("980x760")
        self.root.minsize(820, 620)
        self.client = None
        self.event_rows = []
        self.event_filter = tk.StringVar(value="ALL")
        self.peer_filter = tk.StringVar(value="ALL")
        self.capture_packets = tk.BooleanVar(value=False)

        outer = ttk.Frame(root, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="LAN Simulator", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(outer, text="WinTun overlay • Direct P2P • Relay fallback • End-to-end diagnostics").pack(anchor="w", pady=(0, 10))

        form = ttk.LabelFrame(outer, text="Connection", padding=8)
        form.pack(fill="x")
        self.server_var = tk.StringVar(value="80.225.223.253")
        self.port_var = tk.StringVar(value="5000")
        self.username_var = tk.StringVar(value=f"Player_{str(uuid.uuid4()).replace('-', '')[:8]}")
        self.room_var = tk.StringVar()
        fields = [("Server", self.server_var), ("UDP Port", self.port_var), ("Username", self.username_var), ("Room ID", self.room_var)]
        for row, (label, var) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=3)
            ttk.Entry(form, textvariable=var, width=42).grid(row=row, column=1, sticky="ew", pady=3)
        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(outer); buttons.pack(fill="x", pady=8)
        ttk.Button(buttons, text="Create Room", command=self.create_room).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Join Room", command=self.join_room).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Leave / Disconnect", command=self.leave_room).pack(side="left", padx=(0, 16))
        ttk.Button(buttons, text="▶ Run Full End-to-End Test", command=self.run_test).pack(side="left")
        self.status = tk.StringVar(value="Disconnected")
        ttk.Label(outer, textvariable=self.status, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))

        self.tabs = ttk.Notebook(outer); self.tabs.pack(fill="both", expand=True)
        dash = ttk.Frame(self.tabs, padding=8); events = ttk.Frame(self.tabs, padding=8); packets = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(dash, text="Dashboard"); self.tabs.add(events, text="Events / Diagnostics"); self.tabs.add(packets, text="Packet Inspector")

        # Dashboard
        self.stats_var = tk.StringVar(value="Waiting for connection…")
        ttk.Label(dash, text="Live traffic (aggregated; safe for high packet rates)", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(dash, textvariable=self.stats_var, justify="left", font=("Consolas", 10)).pack(anchor="w", pady=(5, 10))
        ttk.Label(dash, text="Peers", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        peer_frame = ttk.Frame(dash); peer_frame.pack(fill="both", expand=True, pady=(5, 0))
        cols = ("peer", "overlay", "state", "path", "rx", "tx")
        self.peer_tree = ttk.Treeview(peer_frame, columns=cols, show="headings", height=8)
        headings = {"peer":"Peer ID", "overlay":"Overlay IP", "state":"State", "path":"Transport", "rx":"RX pkts", "tx":"TX pkts"}
        widths = {"peer":120, "overlay":120, "state":120, "path":100, "rx":100, "tx":100}
        for c in cols:
            self.peer_tree.heading(c, text=headings[c]); self.peer_tree.column(c, width=widths[c], anchor="center")
        self.peer_tree.pack(side="left", fill="both", expand=True)
        sb=ttk.Scrollbar(peer_frame, orient="vertical", command=self.peer_tree.yview); sb.pack(side="right", fill="y"); self.peer_tree.configure(yscrollcommand=sb.set)
        self.test_summary = tk.StringVar(value="E2E Test: Not run")
        ttk.Label(dash, textvariable=self.test_summary, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=8)
        self.test_detail = tk.StringVar(value="Test flow: created → WinTun pickup → transport → peer RX → WinTun injection → ACK")
        ttk.Label(dash, textvariable=self.test_detail, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 4))

        # Events
        top=ttk.Frame(events); top.pack(fill="x")
        ttk.Label(top,text="Filter:").pack(side="left")
        for value in ("ALL","TEST","CONNECTION","ERROR","TRAFFIC"):
            ttk.Radiobutton(top,text=value,variable=self.event_filter,value=value,command=self._render_events).pack(side="left", padx=3)
        ttk.Button(top,text="Clear",command=self._clear_events).pack(side="right")
        self.event_tree=ttk.Treeview(events,columns=("time","level","category","message"),show="headings")
        for c,w in (("time",95),("level",70),("category",110),("message",620)):
            self.event_tree.heading(c,text=c.title()); self.event_tree.column(c,width=w,anchor="w")
        self.event_tree.pack(fill="both",expand=True,pady=(8,0))

        # Packet inspector — explicit opt-in
        ttk.Checkbutton(packets,text="Capture packet metadata (does NOT dump payloads)",variable=self.capture_packets,command=self._toggle_capture).pack(anchor="w")
        ttk.Label(packets,text="Off by default for normal game traffic. E2E TEST/ACK packets are captured automatically.").pack(anchor="w",pady=(3,8))
        ptop=ttk.Frame(packets); ptop.pack(fill="x")
        ttk.Label(ptop,text="Peer:").pack(side="left")
        self.peer_combo=ttk.Combobox(ptop,textvariable=self.peer_filter,values=("ALL",),state="readonly",width=16)
        self.peer_combo.pack(side="left",padx=(5,12))
        self.peer_combo.bind("<<ComboboxSelected>>", lambda e: self._clear_packets())
        ttk.Button(ptop,text="Clear",command=self._clear_packets).pack(side="left")
        self.packet_tree=ttk.Treeview(packets,columns=("time","dir","peer","size","path","type"),show="headings")
        for c,w in (("time",95),("dir",55),("peer",110),("size",70),("path",90),("type",150)):
            self.packet_tree.heading(c,text=c.upper()); self.packet_tree.column(c,width=w,anchor="w")
        self.packet_tree.pack(fill="both",expand=True,pady=8)
        self.packet_hint=tk.StringVar(value="Normal packet capture is OFF • E2E TEST/ACK capture is always ON")
        ttk.Label(packets,textvariable=self.packet_hint).pack(anchor="w")

        self.root.after(500, self._refresh_diagnostics)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _append_event(self, category, message, level="INFO"):
        row=(datetime.now().strftime("%H:%M:%S.%f")[:-3],level,category,message)
        self.event_rows.append(row)
        if len(self.event_rows)>500: self.event_rows=self.event_rows[-500:]
        self._render_events()

    def _append_packet(self, data):
        pid=data.get("peer_id","-")
        filt=self.peer_filter.get()
        if filt != "ALL" and pid != filt:
            return
        self.packet_tree.insert("","end",values=(datetime.now().strftime("%H:%M:%S.%f")[:-3],data.get("direction",""),pid,data.get("size",0),data.get("path",""),data.get("type","IP")))
        children=self.packet_tree.get_children()
        if len(children)>1000:
            self.packet_tree.delete(children[0])
        if children: self.packet_tree.see(children[-1])

    def _render_events(self):
        self.event_tree.delete(*self.event_tree.get_children())
        f=self.event_filter.get()
        for row in self.event_rows[-500:]:
            if f != "ALL" and row[2] != f and not (f=="ERROR" and row[1] in ("ERROR","WARNING")):
                continue
            self.event_tree.insert("","end",values=row)
        children=self.event_tree.get_children()
        if children: self.event_tree.see(children[-1])

    def _clear_events(self): self.event_rows.clear(); self._render_events()
    def _clear_packets(self): self.packet_tree.delete(*self.packet_tree.get_children())
    def _toggle_capture(self):
        enabled=self.capture_packets.get()
        if self.client:
            self.client.capture_packets=enabled
        self.packet_hint.set("Packet metadata capture ON — max 1000 rows retained" if enabled else "Normal packet capture is OFF • E2E TEST/ACK capture is always ON")

    def _ensure_client(self):
        if self.client and self.client.running: return True
        host=self.server_var.get().strip()
        try:
            port=int(self.port_var.get().strip())
            if not host or not 1<=port<=65535: raise ValueError
        except ValueError:
            messagebox.showerror("Invalid server","Enter a valid server and UDP port."); return False
        self.client=VPNClient(host,port,packet_callback=self._client_event)
        self._seen_event_count=0
        self.client.capture_packets=self.capture_packets.get()
        if not self.client.start():
            self.client=None
            messagebox.showerror("Client startup failed","WinTun could not be started. Run as Administrator and ensure wintun.dll is beside client.py.")
            return False
        return True

    def _client_event(self,event,packet):
        # Network threads never touch Tk widgets directly.
        if event == "__ROOM_READY__": self.root.after(0,self._room_ready_ui)
        elif event == "TEST_RESULT": self.root.after(0,self._test_result_ui,packet or {})
        elif event in ("PEER_EVENT","DIAGNOSTIC_EVENT"):
            data=packet or {}
            self.root.after(0,self._append_event,data.get("category","CONNECTION"),data.get("message",event),data.get("level","INFO"))
        elif event == "PACKET":
            data=packet or {}
            if self.capture_packets.get():
                self.root.after(0,self._append_packet,data)

    def _room_ready_ui(self):
        if self.client and self.client.room_id:
            self.status.set(f"CONNECTED • Room {self.client.room_id} • {self.client.overlay_ip or 'pending'} • {len(self.client.room_members)} peer(s)")
            self._append_event("CONNECTION",f"Room ready: {self.client.room_id} / {self.client.overlay_ip or 'pending'}")

    def _refresh_diagnostics(self):
        c=self.client
        if c and c.running:
            st=c.stats.snapshot()
            elapsed=max(1.0,time.time()-st.get("started_at",time.time()))
            rxrate=st['tun_rx_bytes']/elapsed; txrate=st['tun_tx_bytes']/elapsed
            self.status.set(f"CONNECTED • Room {c.room_id} • {c.overlay_ip or 'pending'} • {len(c.room_members)} peer(s)")
            self.stats_var.set(
                f"TUN RX   {st['tun_rx_packets']:,} pkts  {st['tun_rx_bytes']:,} B     "
                f"TUN TX   {st['tun_tx_packets']:,} pkts  {st['tun_tx_bytes']:,} B\n"
                f"UDP RX   {st['udp_rx_packets']:,} pkts  {st['udp_rx_bytes']:,} B     "
                f"UDP TX   {st['udp_tx_packets']:,} pkts  {st['udp_tx_bytes']:,} B\n"
                f"DATA RX  {st['data_rx_packets']:,}       DATA TX  {st['data_tx_packets']:,}       "
                f"DIRECT RX/TX {st['direct_rx_packets']:,}/{st['direct_tx_packets']:,}     "
                f"RELAY RX/TX {st['relay_rx_packets']:,}/{st['relay_tx_packets']:,}\n"
                f"Average throughput since start: RX {rxrate/1024:.1f} KiB/s   TX {txrate/1024:.1f} KiB/s\n"
                f"E2E: created {st['test_tx']} → WinTun pickup {st['test_picked']} → peer RX {st['test_received']} → peer inject {st['test_injected']} → peer app RX {st['test_app_rx']} → peer app TX {st['test_app_tx']} → ACK WinTun RX/inject {st['test_ack_received']} → local app RX {st['test_ack_app_rx']} → failed {st['test_failed']}"
            )
            self.peer_tree.delete(*self.peer_tree.get_children())
            pids=list(c.room_members)
            combo_values=["ALL"]+pids
            self.peer_combo["values"]=combo_values
            if self.peer_filter.get() not in combo_values:
                self.peer_filter.set("ALL")
            peer_stats = c.stats.snapshot_peer_stats()
            for pid,info in c.room_members.items():
                path=c.peer_paths.get(pid,"checking")
                ps = peer_stats.get(pid, {})
                rx = ps.get("rx_packets", 0)
                tx = ps.get("tx_packets", 0)
                transport = {"direct":"DIRECT", "relay":"RELAY"}.get(path, path.upper())
                self.peer_tree.insert("","end",values=(pid,info.get("overlay_ip",""),info.get("state","DISCOVERED"),transport,rx,tx))
            self.test_summary.set(f"E2E Test: {st['test_last_result']}")
            self.test_detail.set(f"Test flow: created {st['test_tx']} • WinTun pickup {st['test_picked']} • peer RX {st['test_received']} • peer inject {st['test_injected']} • peer app RX {st['test_app_rx']} • peer app TX {st['test_app_tx']} • ACK WinTun RX/inject {st['test_ack_received']} • failed {st['test_failed']}")
            # Import new structured events from the client buffer without replaying them.
            events=getattr(c.stats,"snapshot_events",lambda:[])()
            seen=getattr(self,"_seen_event_count",0)
            for ev in events[seen:]:
                self._append_event(ev["category"],ev["message"],ev["level"])
            self._seen_event_count=len(events)
        else:
            self.stats_var.set("Waiting for connection…")
        self.root.after(500,self._refresh_diagnostics)

    def _test_result_ui(self,result):
        if result.get("ok"):
            self.test_summary.set(f"E2E Test: PASS — peer {result.get('peer_id','?')} via {result.get('transport','?')}")
            self._append_event("TEST",f"PASS: {result.get('reason','test completed')}")
        else:
            self.test_summary.set(f"E2E Test: FAIL — {result.get('reason','unknown error')}")
            self._append_event("ERROR",f"TEST FAILED: {result.get('reason','unknown error')}","ERROR")

    def run_test(self):
        if not self.client or not self.client.running:
            messagebox.showwarning("Not connected","Create or join a room first."); return
        self.tabs.select(1)
        self._append_event("TEST","Starting full end-to-end diagnostic…")
        threading.Thread(target=self.client.run_end_to_end_test,daemon=True,name="lanvpn-e2e-test").start()

    def create_room(self):
        room=self.room_var.get().strip()
        if not room: messagebox.showerror("Room ID","Enter a room ID."); return
        if self._ensure_client():
            self.client.create_room(room,self.username_var.get().strip()); self.status.set(f"Creating room: {room}")

    def join_room(self):
        room=self.room_var.get().strip()
        if not room: messagebox.showerror("Room ID","Enter a room ID."); return
        if self._ensure_client():
            self.client.join_room(room,self.username_var.get().strip()); self.status.set(f"Joining room: {room}")

    def leave_room(self):
        if self.client:
            try: self.client.leave_room(); self.client.stop()
            except Exception as e: debug("Disconnect failed","WARNING",e)
            self.client=None
        self.status.set("Disconnected")

    def close(self): self.leave_room(); self.root.destroy()

def main():
    if os.name != "nt":
        print("This client requires Windows.")
        return
    root = tk.Tk()
    VPNApp(root)
    root.mainloop()


def _ensure_windows_admin():
    """Restart this client elevated when WinDivert/WinTun needs Administrator.

    Uses the normal Windows UAC 'runas' verb. If the process is already
    elevated, it returns immediately. If UAC is cancelled, the caller exits.
    """
    if os.name != "nt":
        return True

    try:
        import ctypes
        import sys

        if ctypes.windll.shell32.IsUserAnAdmin():
            return True

        exe = sys.executable
        # When launched with `python script.py`, sys.executable is Python and
        # the script path must be passed as the first argument. When packaged
        # as an .exe, sys.executable is the executable itself.
        if getattr(sys, "frozen", False):
            params = " ".join(
                '"' + arg.replace('"', '\\"') + '"' for arg in sys.argv[1:]
            )
        else:
            script = os.path.abspath(sys.argv[0])
            args = [script] + sys.argv[1:]
            params = " ".join(
                '"' + arg.replace('"', '\\"') + '"' for arg in args
            )

        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            exe,
            params,
            os.path.dirname(os.path.abspath(sys.argv[0])),
            1,
        )

        if result <= 32:
            print(
                f"Administrator elevation failed/cancelled (ShellExecute={result}).",
                file=sys.stderr,
            )
            return False

        return False  # Elevated child was launched; current process must exit.
    except Exception as e:
        print(f"Could not request Administrator elevation: {e}", file=sys.stderr)
        return False



if __name__ == "__main__":
    if not _ensure_windows_admin():
        raise SystemExit(0)

    main()
