# 🌐 LAN Over Internet - Virtual Gaming Network

A Python-based solution that creates a virtual LAN connection over the internet, enabling LAN-only games (like CS:GO, Age of Empires, etc.) to be played with friends remotely. Uses WinTun virtual network adapters and UDP hole punching for peer-to-peer connections.

## ✨ Features

- **🎮 LAN Gaming Over Internet**: Play LAN-only games with friends worldwide
- **🔗 Direct P2P Connections**: UDP hole punching for optimal latency
- **🖥️ WinTun Integration**: Modern Windows virtual network adapter support
- **📊 Real-time Packet Logging**: Monitor network traffic with detailed hex dumps
- **🛡️ Auto Admin Elevation**: Automatically requests administrator privileges
- **🔧 Multi-Client Support**: Run multiple game instances on the same machine
- **📈 Connection Status**: Live monitoring of peer connections and room members

## 🚀 Quick Start

### Prerequisites

- **Windows 10/11** (64-bit recommended)
- **Python 3.8+** with pip
- **Administrator privileges** (auto-requested)
- **WinTun Driver** (included as `wintun.dll`)

### Installation

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/valive421/lan-simulator-V2.git
   cd lan-simulator-V2
   ```

2. **Install Python dependencies**:
   ```bash
   pip install flask flask-socketio netifaces
   ```

3. **Download WinTun DLL**:
   - Download the latest `wintun.dll` from [WireGuard WinTun releases](https://www.wintun.net/)
   - Place `wintun.dll` in the same directory as `client.py`
   - **Important**: Ensure the DLL matches your Python architecture (64-bit Python = 64-bit DLL)

### Usage

#### 1. Start the Server

```bash
python server.py
```

Server will start on:
- **UDP**: `0.0.0.0:5000` (room management)
- **HTTP**: `127.0.0.1:5000` (health check)

#### 2. Start Client(s)

```bash
python client.py
```

- Client automatically requests admin elevation
- Creates a unique WinTun adapter per instance
- Opens GUI for room management

#### 3. Create/Join Room

1. **Host**: Enter room name → Click "Create Room"
2. **Players**: Enter same room name → Click "Join Room"
3. Wait for peer connections (green ✓ indicates connected)

#### 4. Start Your Game

- Configure your LAN game to use the virtual network
- Players should appear as if on the same local network

## 🖥️ GUI Interface

### Connection Panel
- **Your Name**: Display name for other players
- **Room ID**: Shared room identifier
- **Status**: Connection state and peer count
- **Room Members**: Live list of connected players

### Packet Logger
- **Real-time Traffic**: Monitor all network packets
- **Direction Filters**: NET→TUN (incoming) / TUN→NET (outgoing)
- **Hex Dumps**: Detailed packet inspection
- **Control Messages**: Room and connection events

## 🏗️ Architecture

```
┌─────────────┐    UDP     ┌─────────────┐    UDP     ┌─────────────┐
│   Client A  │◄──────────►│   Server    │◄──────────►│   Client B  │
│ (WinTun +   │   5000     │ (Flask +    │   5000     │ (WinTun +   │
│  GUI)       │            │  SocketIO)  │            │  GUI)       │
└─────────────┘            └─────────────┘            └─────────────┘
       │                                                       │
       └───────────────── Direct P2P UDP ─────────────────────┘
                        (After hole punching)
```

### Components

- **Server** (`server.py`): Room management and NAT traversal coordination
- **Client** (`client.py`): WinTun adapter management and P2P networking
- **WinTun**: Windows virtual network adapter for packet injection

### Network Flow

1. **Room Discovery**: Clients register with central server
2. **NAT Traversal**: Server coordinates UDP hole punching
3. **P2P Connection**: Direct client-to-client communication
4. **Packet Relay**: Game traffic flows through virtual adapters

## 🔧 Configuration

### Server Settings

Edit `server.py` to modify:
- **Port**: Change `PORT` environment variable or default `5000`
- **Cleanup Interval**: Adjust peer timeout (default: 60 seconds)

### Client Settings

Edit `client.py` constants:
- **Server Address**: Modify `server_host` in `main()`
- **Adapter Name**: Change `LANVPN` prefix
- **Keepalive Interval**: Adjust heartbeat frequency

### Advanced Options

```python
# Custom adapter configuration
adapter_name = f"LANVPN-{peer_id}"  # Unique per client
tunnel_type = "LAN VPN Tunnel"      # Adapter description
capacity = 0x400000                 # Session buffer size
```

## 🐛 Troubleshooting

### Common Issues

#### "Could not create WinTun adapter"
- **Cause**: Missing/incompatible `wintun.dll` or insufficient permissions
- **Solution**: 
  1. Ensure `wintun.dll` matches Python architecture (32/64-bit)
  2. Run as administrator
  3. Download latest WinTun from official source

#### "Session started=False"
- **Cause**: Adapter created but session initialization failed
- **Solution**: 
  1. Check Windows Event Viewer for driver errors
  2. Restart as administrator
  3. Try different adapter name

#### "Error in network loop: [WinError 10038]"
- **Cause**: Socket closed unexpectedly
- **Solution**: Restart client, check firewall settings

#### No peer connections
- **Cause**: NAT traversal failure or firewall blocking
- **Solution**: 
  1. Check Windows Firewall / antivirus
  2. Verify both clients can reach server
  3. Try different networks (mobile hotspot test)

### Debug Mode

Enable detailed logging by monitoring `client_debug.log`:

```bash
# Watch logs in real-time (PowerShell)
Get-Content client_debug.log -Wait -Tail 20
```

Key log events:
- `create_adapter: created adapter=True/False`
- `start_session: session started=True/False`
- `peer_joined:` / `Connected to peer:`
- `_network_loop: received/sent packet`

### Network Diagnostics

```bash
# Check WinTun adapters
ipconfig /all | findstr "LANVPN"

# Test connectivity
ping 127.0.0.1
netstat -an | findstr :5000
```

## 🎯 Game Compatibility

### Tested Games
- ✅ **Counter-Strike**: Source, 1.6, CS:GO (LAN mode)
- ✅ **Age of Empires II**: Definitive Edition
- ✅ **Warcraft III**: Classic and Reforged
- ✅ **StarCraft**: Brood War
- ⚠️ **Minecraft**: Java Edition (may need port configuration)

### Game Setup Tips

1. **Disable online matchmaking**: Use LAN/direct IP modes
2. **Configure game network**: Point to virtual adapter IP
3. **Host discovery**: Games should detect other players automatically
4. **Firewall**: Allow game through Windows Firewall

## 🛠️ Development

### Project Structure

```
lan-simulator-V2/
├── client.py          # Main client application
├── server.py          # Room coordination server
├── wintun.dll         # WinTun driver library
├── client_debug.log   # Debug output (generated)
├── README.md          # This file
└── requirements.txt   # Python dependencies
```

### Dependencies

```txt
flask>=2.0.0
flask-socketio>=5.0.0
netifaces>=0.11.0
```

### Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push branch: `git push origin feature-name`
5. Submit pull request

### Known Limitations

- **Windows Only**: Requires WinTun driver (Windows-specific)
- **Administrator Required**: Virtual adapter creation needs elevation
- **IPv4 Only**: Current implementation doesn't support IPv6
- **UDP Only**: No TCP relay support

## 📋 System Requirements

### Minimum
- **OS**: Windows 10 (1809+)
- **Python**: 3.8+
- **RAM**: 512 MB available
- **Network**: Broadband internet connection

### Recommended
- **OS**: Windows 11
- **Python**: 3.10+
- **RAM**: 2 GB available
- **Network**: Low-latency internet (< 100ms to peers)


## 🤝 Support

### Getting Help
- **Issues**: [GitHub Issues](https://github.com/valive421/lan-simulator-V2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/valive421/lan-simulator-V2/discussions)
- **Documentation**: This README and inline code comments

### Reporting Bugs
Please include:
- Windows version and Python version
- Complete error messages
- Steps to reproduce
- Contents of `client_debug.log` (first 100 lines)

---

**Made with ❤️ for the gaming community**

---

*Happy Gaming! 🎮*
