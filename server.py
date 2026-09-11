import json
import os
import socket
import threading
import time
import hashlib
from flask import Flask

# UDP_PORT must be publicly reachable over UDP.
# HTTP_PORT is only a health/status endpoint.
UDP_HOST = os.environ.get("UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.environ.get("UDP_PORT", "5000"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("PORT", "8080"))

CONTROL_MAGIC = b"LVC1"
RELAY_MAGIC = b"LVR1"
PEER_ID_LEN = 8
OVERLAY_MTU = 1350
MAX_UDP = 65535
PEER_TIMEOUT = 60


def pack_control(message):
    return CONTROL_MAGIC + json.dumps(message, separators=(",", ":")).encode("utf-8")


def unpack_control(data):
    if not data.startswith(CONTROL_MAGIC):
        return None
    try:
        return json.loads(data[len(CONTROL_MAGIC):].decode("utf-8"))
    except Exception:
        return None


app = Flask(__name__)


@app.route("/")
def health():
    return "LAN Simulator V2 rendezvous server is running"


class RoomServer:
    def __init__(self, host=UDP_HOST, port=UDP_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.lock = threading.RLock()
        self.rooms = {}

    @staticmethod
    def overlay_subnet(room_id):
        # Deterministic /24 per room. This is a prototype allocation strategy;
        # a production deployment should maintain a persistent collision-free allocator.
        octet = int(hashlib.sha256(room_id.encode("utf-8")).hexdigest()[:2], 16)
        if octet in (0, 1, 255):
            octet = 2
        return f"10.250.{octet}.0/24"

    def _allocate_overlay_ip(self, room, peer_id):
        used = {m["overlay_ip"] for m in room["members"].values()}
        subnet = room["subnet"].split("/")[0]
        base = subnet.rsplit(".", 1)[0]
        for n in range(1, 255):
            candidate = f"{base}.{n}"
            if candidate not in used:
                return candidate
        raise RuntimeError("Room is full")

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.running = True
        threading.Thread(target=self._receive_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        print(f"UDP rendezvous/relay listening on {self.host}:{self.port}")
        return True

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(MAX_UDP)
                if data.startswith(RELAY_MAGIC):
                    self._handle_relay(data, addr)
                elif data.startswith(CONTROL_MAGIC):
                    message = unpack_control(data)
                    if message:
                        self._handle_control(message, addr)
            except OSError:
                if self.running:
                    time.sleep(0.05)
            except Exception as e:
                print(f"UDP receive error: {e}")

    def _handle_control(self, message, addr):
        action = message.get("action")
        if action == "create_room":
            self._create_room(message, addr)
        elif action == "join_room":
            self._join_room(message, addr)
        elif action == "leave_room":
            self._leave_room(message, addr)
        elif action == "keepalive":
            self._keepalive(message, addr)

    def _create_room(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()
        username = str(message.get("username", peer_id)).strip()
        if not room_id or len(peer_id) != PEER_ID_LEN:
            return

        with self.lock:
            if room_id in self.rooms and self.rooms[room_id]["members"]:
                # Treat Create on an existing room as re-registration of this peer.
                room = self.rooms[room_id]
            else:
                room = {
                    "subnet": self.overlay_subnet(room_id),
                    "members": {}
                }
                self.rooms[room_id] = room

            if peer_id not in room["members"]:
                overlay_ip = self._allocate_overlay_ip(room, peer_id)
            else:
                overlay_ip = room["members"][peer_id]["overlay_ip"]

            room["members"][peer_id] = {
                "peer_id": peer_id,
                "username": username,
                "addr": addr,
                "overlay_ip": overlay_ip,
                "last_seen": time.time()
            }

            self._send_room_state(room, peer_id, "room_created")

            print(f"Room {room_id}: {username} ({peer_id}) @ {addr} -> {overlay_ip}")

    def _join_room(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()
        username = str(message.get("username", peer_id)).strip()
        if not room_id or len(peer_id) != PEER_ID_LEN:
            return

        with self.lock:
            room = self.rooms.get(room_id)
            if not room:
                self._send({"action": "error", "message": "Room does not exist"}, addr)
                return

            old = room["members"].get(peer_id)
            overlay_ip = old["overlay_ip"] if old else self._allocate_overlay_ip(room, peer_id)

            room["members"][peer_id] = {
                "peer_id": peer_id,
                "username": username,
                "addr": addr,
                "overlay_ip": overlay_ip,
                "last_seen": time.time()
            }

            self._send_room_state(room, peer_id, "room_joined")

            for pid, member in room["members"].items():
                if pid == peer_id:
                    continue
                self._send({
                    "action": "peer_joined",
                    "room_id": room_id,
                    "peer_id": peer_id,
                    "username": username,
                    "public_ip": addr[0],
                    "public_port": addr[1],
                    "overlay_ip": overlay_ip
                }, member["addr"])

            print(f"{username} joined {room_id} from {addr} -> {overlay_ip}")

    def _send_room_state(self, room, peer_id, action):
        members = {}
        for pid, member in room["members"].items():
            if pid == peer_id:
                continue
            members[pid] = {
                "username": member["username"],
                "public_ip": member["addr"][0],
                "public_port": member["addr"][1],
                "overlay_ip": member["overlay_ip"]
            }

        own = room["members"][peer_id]
        self._send({
            "action": action,
            "room_id": next(
                (rid for rid, r in self.rooms.items() if r is room), ""
            ),
            "members": members,
            "self": {
                "peer_id": peer_id,
                "overlay_ip": own["overlay_ip"]
            },
            "prefix": 24
        }, own["addr"])

    def _leave_room(self, message, addr):
        room_id = message.get("room_id")
        peer_id = message.get("peer_id")
        with self.lock:
            room = self.rooms.get(room_id)
            if not room or peer_id not in room["members"]:
                return
            del room["members"][peer_id]
            for member in room["members"].values():
                self._send({
                    "action": "peer_left",
                    "room_id": room_id,
                    "peer_id": peer_id
                }, member["addr"])
            if not room["members"]:
                del self.rooms[room_id]

    def _keepalive(self, message, addr):
        room_id = message.get("room_id")
        peer_id = message.get("peer_id")
        with self.lock:
            room = self.rooms.get(room_id)
            if not room or peer_id not in room["members"]:
                return
            member = room["members"][peer_id]
            # Always update to the actual observed source address.
            changed = member["addr"] != addr
            member["addr"] = addr
            member["last_seen"] = time.time()

            if changed:
                for pid, other in room["members"].items():
                    if pid != peer_id:
                        self._send({
                            "action": "peer_joined",
                            "room_id": room_id,
                            "peer_id": peer_id,
                            "username": member["username"],
                            "public_ip": addr[0],
                            "public_port": addr[1],
                            "overlay_ip": member["overlay_ip"]
                        }, other["addr"])

    def _find_member_by_addr(self, addr):
        for room_id, room in self.rooms.items():
            for peer_id, member in room["members"].items():
                if member["addr"] == addr:
                    return room_id, peer_id, member
        return None, None, None

    def _handle_relay(self, data, addr):
        if len(data) < 4 + PEER_ID_LEN * 2:
            return

        target = data[4:4 + PEER_ID_LEN].decode("ascii", errors="ignore").rstrip("_")
        source = data[4 + PEER_ID_LEN:4 + PEER_ID_LEN * 2].decode("ascii", errors="ignore").rstrip("_")
        payload = data[4 + PEER_ID_LEN * 2:]
        if len(payload) > OVERLAY_MTU:
            return

        with self.lock:
            room_id, source_id, source_member = self._find_member_by_addr(addr)
            if not room_id or source_id != source:
                return
            room = self.rooms[room_id]
            target_member = room["members"].get(target)
            if not target_member:
                return

            # The target receives LVR1 + target + source + payload.
            self._send_raw(
                data,
                target_member["addr"]
            )

    def _send(self, message, addr):
        self._send_raw(pack_control(message), addr)

    def _send_raw(self, data, addr):
        try:
            self.socket.sendto(data, addr)
        except OSError:
            pass

    def _cleanup_loop(self):
        while self.running:
            time.sleep(15)
            now = time.time()
            with self.lock:
                for room_id in list(self.rooms):
                    room = self.rooms[room_id]
                    stale = [
                        pid for pid, m in room["members"].items()
                        if now - m["last_seen"] > PEER_TIMEOUT
                    ]
                    for pid in stale:
                        del room["members"][pid]
                        for other in room["members"].values():
                            self._send({
                                "action": "peer_left",
                                "room_id": room_id,
                                "peer_id": pid
                            }, other["addr"])
                    if not room["members"]:
                        del self.rooms[room_id]


def run():
    udp = RoomServer()
    udp.start()

    # Health HTTP is deliberately separate from the UDP listener.
    # Hosting platforms must expose UDP_PORT directly; an HTTP-only service
    # cannot transparently expose this UDP socket.
    print(f"HTTP health endpoint on {HTTP_HOST}:{HTTP_PORT}")
    app.run(host=HTTP_HOST, port=HTTP_PORT, threaded=True)


if __name__ == "__main__":
    run()
