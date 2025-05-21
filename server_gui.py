import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import psutil
import ipaddress
import time

# --- WiFi IP ve Netmask al ---
def get_wifi_info():
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        if "Wi-Fi" in iface_name or "Wireless" in iface_name:
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    return addr.address, addr.netmask
    return None, None

# --- Broadcast yayını arka planda çalışsın ---
def send_broadcast(ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    broadcast_address = str(network.broadcast_address)

    UDP_IP = broadcast_address
    UDP_PORT = 5051
    MESSAGE = ip.encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
        print(f"Broadcast gönderildi: {MESSAGE}")
        time.sleep(2)

# --- Sunucu GUI uygulaması ---
class ServerApp:
    def __init__(self, master, host_ip):
        self.master = master
        master.title("Server - Mesajlaşma")

        self.chat_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=20, state='disabled')
        self.chat_area.pack(padx=10, pady=10)

        self.entry = tk.Entry(master, width=40)
        self.entry.pack(padx=10, side=tk.LEFT, expand=True)
        self.entry.bind('<Return>', self.send_message)

        self.send_button = tk.Button(master, text="Gönder", command=self.send_message)
        self.send_button.pack(padx=10, side=tk.LEFT)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host_ip, 5050))
        self.server_socket.listen(1)

        self.client_socket = None

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        self.append_message("Bağlantı bekleniyor...")
        self.client_socket, addr = self.server_socket.accept()
        self.append_message(f"Bağlandı: {addr}")
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    self.append_message(f"İstemci: {message}")
            except:
                break

    def send_message(self, event=None):
        message = self.entry.get()
        if message and self.client_socket:
            self.client_socket.send(message.encode())
            self.append_message(f"Sen: {message}")
            self.entry.delete(0, tk.END)

    def append_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

# --- Programı başlat ---
if __name__ == "__main__":
    ip, netmask = get_wifi_info()
    if not ip:
        print("Wi-Fi bağlantısı bulunamadı.")
        exit()

    # Broadcast yayını ayrı bir thread olarak başlat
    threading.Thread(target=send_broadcast, args=(ip, netmask), daemon=True).start()

    # GUI başlat
    root = tk.Tk()
    app = ServerApp(root, ip)
    root.mainloop()
