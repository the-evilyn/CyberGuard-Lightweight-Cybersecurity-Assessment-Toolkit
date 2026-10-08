import socket
import threading
from datetime import datetime

open_ports = []
lock = threading.Lock()

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            with lock:
                open_ports.append(port)
                print(f"  ✅ Port {port} is OPEN")
        sock.close()
    except:
        pass

def main():
    print("🌐 Port Scanner")
    print("=" * 40)
    print("⚠️  Only scan systems you own or have permission to scan!\n")

    host = input("Enter target host (IP or hostname): ")
    start_port = int(input("Start port (e.g. 1): "))
    end_port = int(input("End port (e.g. 1024): "))

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print("❌ Could not resolve hostname.")
        return

    print(f"\n🔍 Scanning {host} ({ip}) from port {start_port} to {end_port}")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 40)

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("-" * 40)
    if open_ports:
        print(f"\n✅ Scan complete. {len(open_ports)} open port(s) found: {sorted(open_ports)}")
    else:
        print("\n⚠️ No open ports found in the given range.")

if __name__ == "__main__":
    main()
