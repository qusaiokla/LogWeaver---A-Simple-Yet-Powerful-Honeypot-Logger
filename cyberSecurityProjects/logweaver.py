#!/usr/bin/env python3
"""
LogWeaver - A Simple Honeypot Logger
Author: AI Assistant
This script creates simple honeypots on various ports to log attack attempts.
"""

import socket
import threading
import time
from datetime import datetime

# Configuration - Edit these to your liking
HONEYPOTS = [
    {"port": 21, "name": "FTP", "banner": "220 FTP Ready.\r\n"},
    {"port": 22, "name": "SSH", "banner": "SSH-2.0-OpenSSH_8.4\r\n"},
    {"port": 80, "name": "HTTP", "banner": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"},
    {"port": 3389, "name": "RDP", "banner": "\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"}, # RDP hex banner
]
LOG_FILE = "honeypot.log"
BIND_IP = "0.0.0.0" # Listen on all network interfaces

def setup_logging():
    """Write a startup header to the log file."""
    with open(LOG_FILE, "a") as log:
        log.write(f"\n--- LogWeaver Honeypot Started [{get_timestamp()}] ---\n")
        log.write(f"Listening on ports: {[h['port'] for h in HONEYPOTS]}\n")
        log.write("---\n")
    print(f"[*] LogWeaver started. Logging to {LOG_FILE}")

def get_timestamp():
    """Return a formatted timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_event(message):
    """Log a message to both the file and the console."""
    timestamp = get_timestamp()
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    with open(LOG_FILE, "a") as log:
        log.write(log_entry + "\n")

def handle_connection(client_socket, honeypot_config):
    """Handle all interaction with a connected client."""
    service_name = honeypot_config["name"]
    client_ip, client_port = client_socket.getpeername()

    log_event(f"NEW_CONNECTION {service_name} - IP: {client_ip}:{client_port}")

    try:
        # Send a enticing banner to the client
        if honeypot_config["banner"]:
            client_socket.send(honeypot_config["banner"].encode())

        # Main loop to receive data from the client
        while True:
            data = client_socket.recv(1024) # Read up to 1KB of data
            if not data:
                break # Client disconnected

            # Decode and log the received data
            try:
                received_data = data.decode('utf-8').strip()
            except UnicodeDecodeError:
                received_data = str(data.hex()) # Log hex if not decodable

            log_event(f"DATA {service_name} - {client_ip} -> {received_data}")

            # Simple interaction logic for SSH/FTP
            if service_name == "SSH" and "ssh" in received_data.lower():
                client_socket.send(b"Password: ")
            elif service_name == "FTP" and "USER" in received_data:
                client_socket.send(b"331 Please specify the password.\r\n")
            elif service_name == "HTTP":
                client_socket.send(b"<html><body><h1>It works!</h1></body></html>")
                break # HTTP connections are typically short-lived

    except Exception as e:
        log_event(f"ERROR {service_name} - {client_ip}: {str(e)}")
    finally:
        client_socket.close()
        log_event(f"CLOSED {service_name} - IP: {client_ip}:{client_port}")

def start_honeypot(honeypot_config):
    """Start a single honeypot server on a specific port."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (BIND_IP, honeypot_config["port"])

    try:
        server_socket.bind(server_address)
        server_socket.listen(5)
        log_event(f"LISTENING - {honeypot_config['name']} honeypot on port {honeypot_config['port']}")

        while True:
            client_socket, client_address = server_socket.accept()
            # Spin off a new thread to handle the client so the server can keep listening
            client_handler = threading.Thread(
                target=handle_connection,
                args=(client_socket, honeypot_config)
            )
            client_handler.daemon = True
            client_handler.start()

    except Exception as e:
        log_event(f"FATAL - Failed to start {honeypot_config['name']} on {honeypot_config['port']}: {str(e)}")
    finally:
        server_socket.close()

def main():
    """Main function to start all honeypots."""
    setup_logging()
    threads = []

    # Create a thread for each honeypot service
    for honeypot in HONEYPOTS:
        thread = threading.Thread(target=start_honeypot, args=(honeypot,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        time.sleep(0.5) # Small delay to avoid log overlap

    log_event("[*] All honeypots are running. Press Ctrl+C to stop.")

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_event("[*] Shutting down LogWeaver.")

if __name__ == "__main__":
    main()