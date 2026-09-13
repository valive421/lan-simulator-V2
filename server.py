import json
import os
import socket
import threading
import time
import hashlib
import traceback
from flask import Flask

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

LOG_PREFIX = "[SERVER]"


def log(msg):
    print(f"{LOG_PREFIX} {msg}", flush=True)


def pack_control(message):
    return CONTROL_MAGIC + json.dumps(
        message, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def unpack_control(data):
    if not data.startswith(CONTROL_MAGIC):
        return None
    try:
        return json.loads(data[len(CONTROL_MAGIC):].decode("utf-8"))
    except Exception as e:
        log(f"[CONTROL] JSON decode error: {e}")
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

        threading.Thread(
            target=self._receive_loop,
            name="udp-receive",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._cleanup_loop,
            name="cleanup",
            daemon=True,
        ).start()

        log(f"UDP rendezvous/relay listening on {self.host}:{self.port}")
        return True

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

    def _receive_loop(self):
        log("UDP receive loop started")

        while self.running:
            try:
                data, addr = self.socket.recvfrom(MAX_UDP)

                log(
                    f"[UDP RX] bytes={len(data)} "
                    f"from={addr} "
                    f"magic={data[:4]!r}"
                )

                if data.startswith(RELAY_MAGIC):
                    self._handle_relay(data, addr)

                elif data.startswith(CONTROL_MAGIC):
                    message = unpack_control(data)

                    if message is not None:
                        log(
                            f"[CONTROL RX] from={addr} "
                            f"action={message.get('action')!r} "
                            f"message={message}"
                        )
                        self._handle_control(message, addr)
                    else:
                        log(f"[CONTROL RX] invalid packet from={addr}")

                else:
                    log(f"[UDP RX] unknown magic from={addr}: {data[:16]!r}")

            except OSError as e:
                if self.running:
                    log(f"[UDP RX] socket error: {e}")
                    time.sleep(0.05)

            except Exception as e:
                log(f"[UDP RX] EXCEPTION: {e}")
                traceback.print_exc()

    def _handle_control(self, message, addr):
        action = message.get("action")

        log(f"[CONTROL] dispatch action={action!r} addr={addr}")

        try:
            if action == "create_room":
                self._create_room(message, addr)

            elif action == "join_room":
                self._join_room(message, addr)

            elif action == "leave_room":
                self._leave_room(message, addr)

            elif action == "keepalive":
                self._keepalive(message, addr)

            else:
                log(f"[CONTROL] unknown action={action!r} from={addr}")
                self._send(
                    {
                        "action": "error",
                        "message": f"Unknown action: {action}",
                    },
                    addr,
                )

        except Exception as e:
            log(
                f"[CONTROL] EXCEPTION action={action!r} "
                f"from={addr}: {e}"
            )
            traceback.print_exc()

            try:
                self._send(
                    {
                        "action": "error",
                        "message": "Server error while processing request",
                    },
                    addr,
                )
            except Exception:
                pass

    def _create_room(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()
        username = str(message.get("username", peer_id)).strip()

        if not room_id or len(peer_id) != PEER_ID_LEN:
            log(
                f"[ROOM CREATE] invalid request "
                f"room_id={room_id!r} peer_id={peer_id!r}"
            )
            self._send(
                {
                    "action": "error",
                    "message": "Invalid room_id or peer_id",
                },
                addr,
            )
            return

        with self.lock:
            existing = self.rooms.get(room_id)

            if existing and existing["members"]:
                room = existing
                log(
                    f"[ROOM CREATE] room {room_id!r} already exists; "
                    f"treating request as peer re-registration"
                )
            else:
                room = {
                    "subnet": self.overlay_subnet(room_id),
                    "members": {},
                }
                self.rooms[room_id] = room
                log(
                    f"[ROOM CREATE] created room={room_id!r} "
                    f"subnet={room['subnet']}"
                )

            if peer_id not in room["members"]:
                overlay_ip = self._allocate_overlay_ip(room, peer_id)
            else:
                overlay_ip = room["members"][peer_id]["overlay_ip"]

            room["members"][peer_id] = {
                "peer_id": peer_id,
                "username": username,
                "addr": addr,
                "overlay_ip": overlay_ip,
                "last_seen": time.time(),
            }

            log(
                f"[ROOM CREATE] registered peer={peer_id} "
                f"user={username!r} addr={addr} overlay={overlay_ip}"
            )

            self._send_room_state(room, peer_id, "room_created")

            log(
                f"[ROOM CREATE] response sent for room={room_id!r} "
                f"peer={peer_id}"
            )

    def _join_room(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()
        username = str(message.get("username", peer_id)).strip()

        if not room_id or len(peer_id) != PEER_ID_LEN:
            log(
                f"[ROOM JOIN] invalid request "
                f"room_id={room_id!r} peer_id={peer_id!r}"
            )
            self._send(
                {
                    "action": "error",
                    "message": "Invalid room_id or peer_id",
                },
                addr,
            )
            return

        with self.lock:
            room = self.rooms.get(room_id)

            if not room:
                log(
                    f"[ROOM JOIN] room={room_id!r} does not exist "
                    f"requested by {addr}"
                )
                self._send(
                    {
                        "action": "error",
                        "message": "Room does not exist",
                    },
                    addr,
                )
                return

            old = room["members"].get(peer_id)

            if old:
                overlay_ip = old["overlay_ip"]
            else:
                overlay_ip = self._allocate_overlay_ip(room, peer_id)

            room["members"][peer_id] = {
                "peer_id": peer_id,
                "username": username,
                "addr": addr,
                "overlay_ip": overlay_ip,
                "last_seen": time.time(),
            }

            log(
                f"[ROOM JOIN] registered peer={peer_id} "
                f"user={username!r} addr={addr} overlay={overlay_ip}"
            )

            self._send_room_state(room, peer_id, "room_joined")

            for pid, member in room["members"].items():
                if pid == peer_id:
                    continue

                self._send(
                    {
                        "action": "peer_joined",
                        "room_id": room_id,
                        "peer_id": peer_id,
                        "username": username,
                        "public_ip": addr[0],
                        "public_port": addr[1],
                        "overlay_ip": overlay_ip,
                    },
                    member["addr"],
                )

            log(
                f"[ROOM JOIN] response sent to peer={peer_id}; "
                f"members={len(room['members'])}"
            )

    def _send_room_state(self, room, peer_id, action):
        members = {}

        for pid, member in room["members"].items():
            if pid == peer_id:
                continue

            members[pid] = {
                "username": member["username"],
                "public_ip": member["addr"][0],
                "public_port": member["addr"][1],
                "overlay_ip": member["overlay_ip"],
            }

        own = room["members"][peer_id]

        room_id = next(
            (
                rid
                for rid, candidate in self.rooms.items()
                if candidate is room
            ),
            "",
        )

        response = {
            "action": action,
            "room_id": room_id,
            "members": members,
            "self": {
                "peer_id": peer_id,
                "overlay_ip": own["overlay_ip"],
            },
            "prefix": 24,
        }

        log(
            f"[ROOM STATE] action={action!r} "
            f"room={room_id!r} peer={peer_id} "
            f"members={list(members.keys())} "
            f"self={response['self']}"
        )

        self._send(response, own["addr"])

    def _leave_room(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()

        with self.lock:
            room = self.rooms.get(room_id)

            if not room or peer_id not in room["members"]:
                log(
                    f"[ROOM LEAVE] unknown room/peer "
                    f"room={room_id!r} peer={peer_id!r}"
                )
                return

            del room["members"][peer_id]

            log(
                f"[ROOM LEAVE] peer={peer_id} left room={room_id!r}"
            )

            for member in room["members"].values():
                self._send(
                    {
                        "action": "peer_left",
                        "room_id": room_id,
                        "peer_id": peer_id,
                    },
                    member["addr"],
                )

            if not room["members"]:
                del self.rooms[room_id]
                log(f"[ROOM LEAVE] deleted empty room={room_id!r}")

    def _keepalive(self, message, addr):
        room_id = str(message.get("room_id", "")).strip()
        peer_id = str(message.get("peer_id", "")).strip()

        with self.lock:
            room = self.rooms.get(room_id)

            if not room or peer_id not in room["members"]:
                log(
                    f"[KEEPALIVE] ignored unknown room/peer "
                    f"room={room_id!r} peer={peer_id!r} addr={addr}"
                )
                return

            member = room["members"][peer_id]
            changed = member["addr"] != addr

            member["addr"] = addr
            member["last_seen"] = time.time()

            # Reply so the client can verify that the server is alive.
            self._send(
                {
                    "action": "keepalive_ack",
                    "room_id": room_id,
                    "peer_id": peer_id,
                },
                addr,
            )

            log(
                f"[KEEPALIVE] peer={peer_id} room={room_id!r} "
                f"addr={addr} changed={changed}"
            )

            if changed:
                for pid, other in room["members"].items():
                    if pid == peer_id:
                        continue

                    self._send(
                        {
                            "action": "peer_joined",
                            "room_id": room_id,
                            "peer_id": peer_id,
                            "username": member["username"],
                            "public_ip": addr[0],
                            "public_port": addr[1],
                            "overlay_ip": member["overlay_ip"],
                        },
                        other["addr"],
                    )

    def _find_member_by_addr(self, addr):
        for room_id, room in self.rooms.items():
            for peer_id, member in room["members"].items():
                if member["addr"] == addr:
                    return room_id, peer_id, member

        return None, None, None

    def _handle_relay(self, data, addr):
        if len(data) < 4 + PEER_ID_LEN * 2:
            log(f"[RELAY] packet too short from={addr}")
            return

        target = (
            data[
                4 : 4 + PEER_ID_LEN
            ].decode("ascii", errors="ignore").rstrip("_")
        )

        source = (
            data[
                4 + PEER_ID_LEN : 4 + PEER_ID_LEN * 2
            ].decode("ascii", errors="ignore").rstrip("_")
        )

        payload = data[4 + PEER_ID_LEN * 2:]

        if len(payload) > OVERLAY_MTU:
            log(
                f"[RELAY] payload too large from={addr}: "
                f"{len(payload)}"
            )
            return

        with self.lock:
            room_id, source_id, source_member = self._find_member_by_addr(addr)

            if not room_id or source_id != source:
                log(
                    f"[RELAY] rejected source={source} addr={addr} "
                    f"resolved_room={room_id} resolved_peer={source_id}"
                )
                return

            room = self.rooms[room_id]
            target_member = room["members"].get(target)

            if not target_member:
                log(
                    f"[RELAY] target peer={target} not found "
                    f"room={room_id!r}"
                )
                return

            log(
                f"[RELAY] room={room_id!r} "
                f"source={source} -> target={target} "
                f"payload={len(payload)} bytes"
            )

            self._send_raw(data, target_member["addr"])

    def _send(self, message, addr):
        data = pack_control(message)

        log(
            f"[UDP TX] CONTROL bytes={len(data)} "
            f"to={addr} action={message.get('action')!r}"
        )

        self._send_raw(data, addr)

    def _send_raw(self, data, addr):
        try:
            sent = self.socket.sendto(data, addr)
            log(f"[UDP TX] sendto returned={sent} to={addr}")
            return sent

        except OSError as e:
            log(
                f"[UDP TX ERROR] bytes={len(data)} "
                f"to={addr}: {e}"
            )
            return 0

        except Exception as e:
            log(
                f"[UDP TX EXCEPTION] bytes={len(data)} "
                f"to={addr}: {e}"
            )
            traceback.print_exc()
            return 0

    def _cleanup_loop(self):
        while self.running:
            time.sleep(15)
            now = time.time()

            with self.lock:
                for room_id in list(self.rooms):
                    room = self.rooms[room_id]

                    stale = [
                        pid
                        for pid, member in room["members"].items()
                        if now - member["last_seen"] > PEER_TIMEOUT
                    ]

                    for pid in stale:
                        del room["members"][pid]

                        log(
                            f"[CLEANUP] removing stale peer={pid} "
                            f"from room={room_id!r}"
                        )

                        for other in room["members"].values():
                            self._send(
                                {
                                    "action": "peer_left",
                                    "room_id": room_id,
                                    "peer_id": pid,
                                },
                                other["addr"],
                            )

                    if not room["members"]:
                        del self.rooms[room_id]
                        log(
                            f"[CLEANUP] deleted empty room={room_id!r}"
                        )


def run():
    udp = RoomServer()
    udp.start()

    log(
        f"HTTP health endpoint on {HTTP_HOST}:{HTTP_PORT}"
    )

    # Never let Flask spawn a reloader process under systemd. The UDP
    # listener runs in a background thread in this same process.
    app.run(
        host=HTTP_HOST,
        port=HTTP_PORT,
        threaded=True,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    run()
