import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

# --- UDP üzerinden sunucunun IP'sini alma fonksiyonu ---
def get_server_ip_via_udp():
    UDP_IP = ""
    UDP_PORT = 5051

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"UDP port {UDP_PORT} üzerinden dinleniyor (bir kez)...")
    data, addr = sock.recvfrom(1024)
    received_ip = data.decode()
    print(f"Gelen IP: {received_ip}")
    sock.close()
    return received_ip

# --- GUI sınıfı ---
class ClientApp:
    def __init__(self, master, server_ip):
        self.master = master
        master.title("İstemci - Mesajlaşma")
        
        self.chat_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=20, state='disabled')
        self.chat_area.pack(padx=10, pady=10)

        self.entry = tk.Entry(master, width=40)
        self.entry.pack(padx=10, side=tk.LEFT, expand=True)
        self.entry.bind('<Return>', self.send_message)

        self.send_button = tk.Button(master, text="Gönder", command=self.send_message)
        self.send_button.pack(padx=10, side=tk.LEFT)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((server_ip, 5050))
            self.append_message("Sunucuya bağlanıldı.")
        except:
            self.append_message("Bağlantı hatası!")
            return

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    self.append_message(f"Sunucu: {message}")
            except:
                break

    def send_message(self, event=None):
        message = self.entry.get()
        if message:
            self.client_socket.send(message.encode())
            self.append_message(f"Sen: {message}")
            self.entry.delete(0, tk.END)

    def append_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')


# --- Uygulamayı başlat ---
if __name__ == "__main__":
    server_ip = get_server_ip_via_udp()
    root = tk.Tk()
    app = ClientApp(root, server_ip)
    root.mainloop()
