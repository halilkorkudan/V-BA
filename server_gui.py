import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import psutil
import ipaddress
import time
from datetime import datetime

broadcast_running = threading.Event()
broadcast_running.set()  # Başlangıçta yayın aktif


def get_wifi_info():
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        if "Wi-Fi" in iface_name or "Wireless" in iface_name:
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    return addr.address, addr.netmask
    return None, None


class ServerApp:
    def __init__(self, master, host_ip):
        self.master = master
        master.title("Server")
        master.geometry("700x500")
        master.configure(bg="#0B1D51")

        self.username = simpledialog.askstring("İsim Girişi", "Sunucu adı girin:", parent=master)
        if not self.username:
            self.username = "Sunucu"
        master.title(f"Server - {self.username}")

        self.font = ("Segoe UI", 11)

        self.main_frame = tk.Frame(master, bg="#FFE3A9")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.chat_area = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=20,
                                                   state='disabled', font=self.font,
                                                   bg="#FFFFFF", fg="#000000", bd=1, relief=tk.SOLID)
        self.chat_area.grid(row=0, column=0, columnspan=4, padx=5, pady=10, sticky="nsew")

        self.entry = tk.Entry(self.main_frame, font=self.font)
        self.entry.grid(row=1, column=0, padx=5, pady=10, sticky="ew", ipady=7)
        self.entry.bind('<Return>', self.send_message)

        self.send_button = tk.Button(self.main_frame, text="Gönder", command=self.send_message,
                                     font=("Segoe UI", 10, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5)
        self.send_button.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        self.refresh_button = tk.Button(self.main_frame, text="Yenile", command=self.refresh_broadcast, 
                                        font=("Segoe UI", 10, "bold"), bg="#4DA8DA", fg="white", padx=10, pady=5)
        self.refresh_button.grid(row=1, column=2, padx=5, pady=10, sticky="ew")

        self.exit_button = tk.Button(self.main_frame, text="Çıkış",
                                     font=("Segoe UI", 10, "bold"),
                                     bg="#FF4C4C", fg="white", padx=10, pady=5,
                                     command=self.master.quit)
        self.exit_button.grid(row=1, column=3, padx=5, pady=10, sticky="ew")

        self.emoji_frame = tk.Frame(self.main_frame, bg="#F0F0F0")
        self.emoji_frame.grid(row=2, column=0, columnspan=4, pady=(0, 10))

        emojis = ["😊", "😂", "😍", "👍", "🔥"]
        for i, emoji in enumerate(emojis):
            btn = tk.Button(self.emoji_frame, text=emoji, font=("Segoe UI", 12),
                            command=lambda e=emoji: self.insert_emoji(e), padx=5, pady=2)
            btn.grid(row=0, column=i, padx=3)

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=3)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(3, weight=1)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind((host_ip, 5050))
        except Exception as e:
            self.append_message(f"Bağlantı hatası: {e}")
            return

        self.server_socket.listen(1)
        self.client_socket = None
        self.client_name = "İstemci"

        threading.Thread(target=self.accept_connection, daemon=True).start()

        self.send_broadcast()  # Başlangıçta yayın başlat

    def insert_emoji(self, emoji):
        self.entry.insert(tk.END, emoji)
        self.entry.focus()

    def accept_connection(self):
        self.append_message("Bağlantı bekleniyor...")
        self.client_socket, addr = self.server_socket.accept()
        broadcast_running.clear()
        self.append_message(f"Bağlandı: {addr}")
        try:
            name_data = self.client_socket.recv(1024).decode()
            self.client_name = name_data
            self.append_message(f"{self.client_name} bağlandı.")
        except:
            self.append_message("İstemci ismi alınamadı.")
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if message:
                    self.append_message(message)
            except:
                break

    def send_message(self, event=None):
        message = self.entry.get().strip()
        if message and self.client_socket:
            timestamp = datetime.now().strftime("%H:%M")
            full_message = f"[{timestamp}] {self.username}: {message}"
            try:
                self.client_socket.sendall(full_message.encode('utf-8'))
            except:
                self.append_message("Mesaj gönderilemedi.")
            self.append_message(full_message)
            self.entry.delete(0, tk.END)

    def append_message(self, message):
        self.chat_area.config(state='normal')
        try:
            time_user, content = message.split(" : ", 1)
            if "] " in time_user:
                timestamp, username = time_user.split("] ")
                timestamp = timestamp.strip("[")
            else:
                username = time_user.strip()
                timestamp = ""

            time_line = f"[{timestamp}]\n"
            message_line = f"{username}: {content.strip()}\n\n"

            if username == self.username:
                self.chat_area.insert(tk.END, time_line, "right_time")
                self.chat_area.insert(tk.END, message_line, "right")
            else:
                self.chat_area.insert(tk.END, time_line, "left_time")
                self.chat_area.insert(tk.END, message_line, "left")

            self.chat_area.tag_config("left", justify='left', lmargin1=10, lmargin2=10, rmargin=100,
                                      foreground="#000000", font=("Segoe UI", 10))
            self.chat_area.tag_config("right", justify='right', rmargin=10, lmargin1=100, lmargin2=100,
                                      foreground="#007AFF", font=("Segoe UI", 10, "bold"))

            self.chat_area.tag_config("left", justify='left', lmargin1=10, lmargin2=10, rmargin=100,
                                      foreground="#000000", font=("Segoe UI", 11, "bold"))
            self.chat_area.tag_config("right", justify='right', rmargin=10, lmargin1=100, lmargin2=100,
                                      foreground="#007AFF", font=("Segoe UI", 11, "bold"))
            self.chat_area.tag_config("left_time", justify='left', lmargin1=10, lmargin2=10, rmargin=100,
                                      foreground="#666666", font=("Segoe UI", 8, "bold"))
            self.chat_area.tag_config("right_time", justify='right', rmargin=10, lmargin1=100, lmargin2=100,
                                      foreground="#666666", font=("Segoe UI", 8, "bold"))
        except Exception:
            self.chat_area.insert(tk.END, message + "\n", "left")

        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')


    def send_broadcast(self):
        ip, netmask = get_wifi_info()
        if not ip:
            self.append_message("Wi-Fi IP alınamadı, broadcast başlatılamadı.")
            return

        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        broadcast_address = str(network.broadcast_address)

        UDP_IP = broadcast_address
        UDP_PORT = 5051
        MESSAGE = ip.encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        broadcast_running.set()

        def broadcast_loop():
            while broadcast_running.is_set():
                try:
                    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
                    print(f"Broadcast gönderildi: {MESSAGE}")
                    time.sleep(2)
                except Exception as e:
                    print(f"Broadcast hatası: {e}")
                    break

        threading.Thread(target=broadcast_loop, daemon=True).start()

    def refresh_broadcast(self):
        broadcast_running.clear()
        time.sleep(0.5)
        self.send_broadcast()


if __name__ == "__main__":
    ip, netmask = get_wifi_info()
    if not ip:
        print("Wi-Fi bağlantısı bulunamadı.")
        exit()

    root = tk.Tk()
    app = ServerApp(root, ip)
    root.mainloop()
