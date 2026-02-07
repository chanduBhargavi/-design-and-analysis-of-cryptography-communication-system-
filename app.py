#!/usr/bin/env python3
"""
Secure AI Chat — with AI text emotion detection (Transformers -> NLTK -> fallback)
Features:
 - AI-based text emotion detection integrated into send/receive
 - Encrypted text packets using emotion-derived XOR key (demo)
 - File send/receive (saves to ./Received_Files/)
 - Steganography (LSB) for hiding/extracting text & files in images (PNG recommended)
 - Device-to-device stego: after creating a stego-image you can optionally send it directly to the peer
 - Encrypted chat logs (secure_chat.logx) saved as base64 encrypted lines
 - Decoy Mode: shows fake messages while storing real ones; restores original chat after Decoy toggled OFF
Notes:
 - For best accuracy install: pip install transformers torch
 - If transformers not installed, app will try NLTK VADER (pip install nltk + vader_lexicon)
 - If cryptography is installed, log encryption uses Fernet (recommended). Otherwise a PBKDF2->XOR fallback is used.
"""

import socket
import threading
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import os, time, random, hashlib, base64, json
from pathlib import Path

# Optional cryptography support for secure log encryption
USE_FERNET = False
FERNET_AVAILABLE = False
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    FERNET_AVAILABLE = True
except Exception:
    FERNET_AVAILABLE = False

# -------------------------
# Try to load transformers-based emotion classifier (preferred)
# -------------------------
TRANSFORMERS_AVAILABLE = False
VADER_AVAILABLE = False
TRANSFORMER_LABEL_MAP = {
    "joy": "happy",
    "happy": "happy",
    "sadness": "sad",
    "sad": "sad",
    "anger": "angry",
    "angry": "angry",
    "fear": "fear",
    "surprise": "surprise",
    "neutral": "neutral",
    "love": "happy"
}

try:
    from transformers import pipeline
    try:
        EMOTION_PIPELINE = pipeline("text-classification", model="j-hartmann/emotion-english-distilroberta-base", return_all_scores=False)
        TRANSFORMERS_AVAILABLE = True
    except Exception as e:
        print("Transformers pipeline not available or failed to load:", e)
        TRANSFORMERS_AVAILABLE = False
except Exception:
    TRANSFORMERS_AVAILABLE = False

# -------------------------
# Try to load NLTK VADER as fallback
# -------------------------
try:
    import nltk
    from nltk.sentiment.vader import SentimentIntensityAnalyzer
    try:
        nltk.data.find("sentiment/vader_lexicon.zip")
        VADER_AVAILABLE = True
    except LookupError:
        try:
            nltk.download("vader_lexicon")
            VADER_AVAILABLE = True
        except Exception as e:
            print("Could not download vader_lexicon:", e)
            VADER_AVAILABLE = False
except Exception:
    VADER_AVAILABLE = False

# -------------------------
# Emotion analysis function (tries transformers -> vader -> fallback)
# Returns one of: happy, sad, angry, fear, surprise, neutral
# -------------------------
def analyze_emotion(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return "neutral"

    if TRANSFORMERS_AVAILABLE:
        try:
            res = EMOTION_PIPELINE(text)
            label = res[0]["label"] if isinstance(res, list) else res["label"]
            label = label.lower()
            return TRANSFORMER_LABEL_MAP.get(label, "neutral")
        except Exception as e:
            print("Transformer detection error:", e)

    if VADER_AVAILABLE:
        try:
            sia = SentimentIntensityAnalyzer()
            scores = sia.polarity_scores(text)
            compound = scores.get("compound", 0.0)
            if compound >= 0.6:
                return "happy"
            elif compound <= -0.4:
                return "angry"
            elif -0.4 < compound < -0.1:
                return "sad"
            else:
                return "neutral"
        except Exception as e:
            print("VADER error:", e)

    t = text.lower()
    if any(w in t for w in ["happy", "joy", "yay", "awesome", "great", "love"]):
        return "happy"
    if any(w in t for w in ["sad", "unhappy", "depressed", "sorrow", "cry"]):
        return "sad"
    if any(w in t for w in ["angry", "mad", "furious", "hate", "annoyed"]):
        return "angry"
    if any(w in t for w in ["scared", "fear", "afraid", "panic"]):
        return "fear"
    if any(w in t for w in ["surprise", "surprised", "wow", "whoa"]):
        return "surprise"
    return "neutral"

# -------------------------
# XOR-based demo encryption (derive key from emotion + salt)
# -------------------------
SECRET_SALT = "qryptic_secret_salt_v1"

def derive_key_bytes(emotion, length=64):
    h = hashlib.sha256((emotion + SECRET_SALT).encode()).digest()
    if length <= len(h):
        return h[:length]
    out = bytearray(h)
    while len(out) < length:
        h = hashlib.sha256(h).digest()
        out.extend(h)
    return bytes(out[:length])

def xor_encrypt_bytes(data: bytes, emotion: str) -> bytes:
    key = derive_key_bytes(emotion, length=len(data))
    return bytes(b ^ k for b, k in zip(data, key))

def xor_decrypt_bytes(data: bytes, emotion: str) -> bytes:
    return xor_encrypt_bytes(data, emotion)

# -------------------------
# Simple AES/Fernet log encryption helpers (or fallback)
# -------------------------
LOG_FILE = "secure_chat.logx"
LOG_SALT_FILE = ".log_salt.bin"
# If cryptography available, we'll derive a Fernet key from password+salt
def ensure_log_salt():
    if not os.path.exists(LOG_SALT_FILE):
        with open(LOG_SALT_FILE, "wb") as f:
            f.write(os.urandom(16))
    with open(LOG_SALT_FILE, "rb") as f:
        return f.read()

def derive_fernet_key(password: str, salt: bytes):
    # returns urlsafe base64 32-byte key for Fernet
    if not FERNET_AVAILABLE:
        raise RuntimeError("Fernet not available")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key

# Fallback: derive XOR key from password using PBKDF2 and use it to XOR-encrypt lines
def derive_xor_key_from_password(password: str, salt: bytes, length=64):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=length)
    return dk

# Write an encrypted log line (each line stored as base64 of ciphertext)
def append_encrypted_log_line(line: str, password: str = None, fernet_obj: object = None, xor_key: bytes = None):
    """
    - If fernet_obj provided, use it to encrypt line and write base64.
    - Else if xor_key provided, XOR-line bytes with xor_key and write base64.
    - Else write plaintext (shouldn't happen).
    """
    if fernet_obj:
        token = fernet_obj.encrypt(line.encode("utf-8"))
        b64 = base64.b64encode(token).decode("ascii")
    elif xor_key:
        data = line.encode("utf-8")
        key = xor_key
        # repeat key to length of data
        full_key = (key * ((len(data)//len(key))+1))[:len(data)]
        cipher = bytes(a ^ b for a, b in zip(data, full_key))
        b64 = base64.b64encode(cipher).decode("ascii")
    else:
        # fallback (plaintext) - not recommended
        b64 = base64.b64encode(line.encode("utf-8")).decode("ascii")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(b64 + "\n")

def read_encrypted_log_lines():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    return lines

def decrypt_log_lines(lines, password: str = None, fernet_obj: object = None, xor_key: bytes = None):
    out = []
    for b64 in lines:
        try:
            data = base64.b64decode(b64.encode("ascii"))
            if fernet_obj:
                dec = fernet_obj.decrypt(data).decode("utf-8")
                out.append(dec)
            elif xor_key:
                key = xor_key
                full_key = (key * ((len(data)//len(key))+1))[:len(data)]
                plain = bytes(a ^ b for a, b in zip(data, full_key))
                out.append(plain.decode("utf-8", errors="ignore"))
            else:
                out.append(data.decode("utf-8", errors="ignore"))
        except Exception as e:
            out.append(f"[UNABLE TO DECRYPT LINE: {e}]")
    return out

# -------------------------
# Steganography LSB helpers (same as before)
# -------------------------
def _bytes_to_bitlist(b: bytes):
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def _bitlist_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        for bit in chunk:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def embed_bytes_in_image(carrier_path, payload_bytes: bytes, out_path):
    img = Image.open(carrier_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode else "RGB")
    has_alpha = (img.mode == "RGBA")
    pixels = list(img.getdata())
    total_channels = len(pixels) * (4 if has_alpha else 3)
    payload = len(payload_bytes).to_bytes(4, "big") + payload_bytes
    bits = _bytes_to_bitlist(payload)
    if len(bits) > total_channels:
        raise ValueError("Carrier image too small to hold payload (need {} bits, have {})".format(len(bits), total_channels))
    new_pixels = []
    bit_idx = 0
    for px in pixels:
        channels = list(px)
        for ch_i in range(3):  # only RGB
            if bit_idx < len(bits):
                channels[ch_i] = (channels[ch_i] & ~1) | bits[bit_idx]
                bit_idx += 1
        new_pixels.append(tuple(channels))
    img.putdata(new_pixels)
    img.save(out_path)
    return out_path

def extract_bytes_from_image(stego_path):
    img = Image.open(stego_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode else "RGB")
    pixels = list(img.getdata())
    bits = []
    for px in pixels:
        for ch_i in range(3):
            bits.append(px[ch_i] & 1)
    if len(bits) < 32:
        raise ValueError("Image doesn't contain embedded data")
    length_bits = bits[:32]
    length_bytes = _bitlist_to_bytes(length_bits)
    payload_len = int.from_bytes(length_bytes, "big")
    total_payload_bits = (4 + payload_len) * 8
    if total_payload_bits > len(bits):
        raise ValueError("Image does not contain enough bits for declared payload length")
    payload_bits = bits[32:32 + payload_len * 8]
    payload = _bitlist_to_bytes(payload_bits)
    return payload

# -------------------------
# Threat detector
# -------------------------
def ai_threat_detector(message):
    threats = ["hack", "malware", "attack", "virus", "ddos", "breach"]
    return any(word.lower() in message.lower() for word in threats)

# -------------------------
# Main Application
# -------------------------
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure AI Chat | Emotion-aware")
        self.root.geometry("1280x820")
        ctk.set_appearance_mode("dark")

        self.sock = None
        self.connected = False
        self.decoy = False
        self.server_socket = None
        self.stop_threads = False

        # Chat histories:
        # real_messages stores tuples: ("OUT"|"IN", timestamp, emotion, text)
        self.real_messages = []
        # fake_messages stores tuples for what was shown during decoy: ("OUT"|"IN", timestamp, fake_text)
        self.fake_messages = []

        # Log encryption helpers (set after asking user)
        self.log_password = None
        self.fernet = None
        self.xor_key = None
        self.log_salt = ensure_log_salt()

        # Prompt for log password (ask once)
        try:
            p = simpledialog.askstring("Chat log password", "Enter a password to encrypt your chat log.\n(Leave blank for auto-generated local key)", show="*")
            if p and p.strip():
                self.log_password = p.strip()
                if FERNET_AVAILABLE:
                    key = derive_fernet_key(self.log_password, self.log_salt)
                    self.fernet = Fernet(key)
                else:
                    # fallback xor key derived from password
                    self.xor_key = derive_xor_key_from_password(self.log_password, self.log_salt, length=64)
            else:
                # auto-generate local key (stored in hidden file)
                keyfile = ".local_log_key.bin"
                if os.path.exists(keyfile):
                    with open(keyfile, "rb") as f:
                        keydata = f.read()
                else:
                    keydata = os.urandom(32)
                    with open(keyfile, "wb") as f:
                        f.write(keydata)
                # try to use Fernet if available (derive from local blob)
                if FERNET_AVAILABLE:
                    # we derive a fernet key deterministically from keydata for convenience
                    key = base64.urlsafe_b64encode(hashlib.sha256(keydata).digest())
                    self.fernet = Fernet(key)
                else:
                    self.xor_key = hashlib.sha256(keydata).digest()

        except Exception as e:
            print("Log password prompt error:", e)

        # UI Frame
        self.main_frame = ctk.CTkFrame(root, corner_radius=12)
        self.main_frame.pack(fill="both", expand=True, padx=12, pady=12)

        # Canvas (background + animation)
        self.canvas = tk.Canvas(self.main_frame, bg="#000013", highlightthickness=0)
        self.canvas.place(relx=0.5, rely=0.26, anchor="center", width=1000, height=280)
        self.bg_img = None
        self.load_crypto_background()

        # Cubes animation
        self.cubes = []
        for _ in range(10):
            size = random.randint(16, 50)
            x = random.randint(0, 1000)
            y = random.randint(0, 280)
            depth = random.randint(1, 6)
            speed = random.uniform(0.6, 2.0)
            cube = {"x": x, "y": y, "size": size, "depth": depth, "speed": speed}
            self.cubes.append(cube)
        self.animate_3d()

        # Chat box
        self.chat_box = ctk.CTkTextbox(self.main_frame, width=980, height=300, fg_color="#0A0A12", text_color="white")
        self.chat_box.place(relx=0.5, rely=0.58, anchor="center")
        self.chat_box.configure(state="disabled")

        # Input & controls
        self.msg_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Type message here...", width=720)
        self.msg_entry.place(relx=0.32, rely=0.85)

        send_btn = ctk.CTkButton(self.main_frame, text="Send", width=120, command=self.send_msg)
        send_btn.place(relx=0.72, rely=0.85)

        file_btn = ctk.CTkButton(self.main_frame, text="📁 Send File", width=130, command=self.send_file)
        file_btn.place(relx=0.20, rely=0.92)

        decoy_btn = ctk.CTkButton(self.main_frame, text="🛡 Decoy Mode", width=150, command=self.toggle_decoy)
        decoy_btn.place(relx=0.35, rely=0.92)

        self.ip_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Enter IP", width=260)
        self.ip_entry.place(relx=0.52, rely=0.92)

        connect_btn = ctk.CTkButton(self.main_frame, text="Connect", width=120, command=self.connect)
        connect_btn.place(relx=0.72, rely=0.92)

        host_btn = ctk.CTkButton(self.main_frame, text="Start Server", width=150, command=self.host)
        host_btn.place(relx=0.85, rely=0.92)

        # Stego controls (right)
        stego_frame = ctk.CTkFrame(self.main_frame, width=250, corner_radius=8)
        stego_frame.place(relx=0.93, rely=0.35, anchor="ne")
        ctk.CTkLabel(stego_frame, text="Steganography").pack(pady=(8,4))
        ctk.CTkButton(stego_frame, text="Hide Text in Image", width=200, command=self.stego_hide_text).pack(pady=6)
        ctk.CTkButton(stego_frame, text="Extract Text from Image", width=200, command=self.stego_extract_text).pack(pady=6)
        ctk.CTkButton(stego_frame, text="Hide File in Image", width=200, command=self.stego_hide_file).pack(pady=6)
        ctk.CTkButton(stego_frame, text="Extract File from Image", width=200, command=self.stego_extract_file).pack(pady=6)
        ctk.CTkButton(stego_frame, text="Show Secure Log", width=200, command=self.show_secure_log).pack(pady=(12,6))

        Path("Received_Files").mkdir(exist_ok=True)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # UI helpers
    def load_crypto_background(self):
        try:
            img_path = "crypto_bg.jpg"
            img = Image.open(img_path)
            img = img.resize((1000, 280), Image.LANCZOS)
            self.bg_img = ImageTk.PhotoImage(img)
            self.canvas.create_image(0, 0, anchor="nw", image=self.bg_img)
        except Exception as e:
            self.canvas.create_rectangle(0, 0, 1000, 280, fill="#000013", outline="")
            print("Background not loaded:", e)

    def animate_3d(self):
        self.canvas.delete("all")
        if self.bg_img:
            self.canvas.create_image(0, 0, anchor="nw", image=self.bg_img)
        else:
            self.canvas.create_rectangle(0, 0, 1000, 280, fill="#000013", outline="")
        for cube in self.cubes:
            scale = 1 + cube["depth"] * 0.18
            size = cube["size"] * scale
            x1 = cube["x"]
            y1 = cube["y"]
            x2 = x1 + size
            y2 = y1 + size
            shade = int(100 + cube["depth"] * 18)
            color = f"#{shade:02x}{shade:02x}ff"
            self.canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline="cyan", width=2)
            cube["y"] += cube["speed"]
            if cube["y"] > 300:
                cube["y"] = -50
                cube["x"] = random.randint(0, 950)
        self.root.after(40, self.animate_3d)

    def show(self, text):
        try:
            self.chat_box.configure(state="normal")
            self.chat_box.insert("end", text)
            self.chat_box.see("end")
            self.chat_box.configure(state="disabled")
        except Exception as e:
            print("UI update error:", e)

    # PRIVATE: write to log (encrypted)
    def _log_line(self, direction, ts, emotion, text):
        # line format: JSON for easier parsing later
        payload = {"ts": ts, "dir": direction, "emotion": emotion, "text": text}
        line = json.dumps(payload, ensure_ascii=False)
        # append encrypted line
        if self.fernet:
            append_encrypted_log_line(line, fernet_obj=self.fernet)
        elif self.xor_key:
            append_encrypted_log_line(line, xor_key=self.xor_key)
        else:
            append_encrypted_log_line(line)

    # Networking
    def host(self):
        threading.Thread(target=self.server_thread, daemon=True).start()
        self.show("🟢 Hosting server...\nWaiting for connection...\n")

    def server_thread(self):
        try:
            server = socket.socket()
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("", 5555))
            server.listen(1)
            self.server_socket = server
            conn, addr = server.accept()
            self.sock = conn
            self.connected = True
            self.show(f"✔ Connected to {addr}\n")
            threading.Thread(target=self.receive, daemon=True).start()
        except Exception as e:
            print("Server error:", e)
            self.show("❌ Server error.\n")

    def connect(self):
        if self.connected:
            self.show("Already connected.\n")
            return
        try:
            client = socket.socket()
            client.connect((self.ip_entry.get().strip(), 5555))
            self.sock = client
            self.connected = True
            self.show("✔ Connected to host\n")
            threading.Thread(target=self.receive, daemon=True).start()
        except Exception as e:
            print("Connect error:", e)
            messagebox.showerror("Connection Error", "Could not connect to server")

    # helper to send bytes as a file over the socket
    def send_bytes_as_file(self, filename: str, data: bytes):
        if not self.connected or not self.sock:
            self.show("⚠ Not connected.\n")
            return False
        try:
            header = f"[FILE]|{filename}|{len(data)}\n".encode()
            self.sock.sendall(header)
            # send in chunks
            sent = 0
            chunk_size = 4096
            while sent < len(data):
                chunk = data[sent:sent+chunk_size]
                self.sock.sendall(chunk)
                sent += len(chunk)
            self.show(f"📁 Stego image sent: {filename} ({len(data)} bytes)\n")
            return True
        except Exception as e:
            print("Send bytes as file error:", e)
            self.show("❌ Failed to send stego image.\n")
            return False

    # Send / Receive
    def send_msg(self):
        if not self.connected:
            self.show("⚠ Not connected.\n")
            return
        text = self.msg_entry.get().strip()
        if not text:
            return

        emotion = analyze_emotion(text)
        if self.decoy:
            payload_text = "I am busy right now."
            display_emotion = "neutral"
        else:
            payload_text = text
            display_emotion = emotion

        if ai_threat_detector(text):
            self.show("⚠ Threat Alert Detected!\n")

        payload_bytes = payload_text.encode("utf-8")
        enc_bytes = xor_encrypt_bytes(payload_bytes, display_emotion)
        b64 = base64.b64encode(enc_bytes).decode("ascii")
        packet = f"[E_TXT]|{display_emotion}|{b64}\n".encode("utf-8")
        try:
            self.sock.sendall(packet)
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            # Store real message (original text) regardless of decoy ON
            self.real_messages.append(("OUT", ts, emotion, text))
            # Save encrypted log (we log the real text)
            self._log_line("OUT", ts, emotion, text)

            # If decoy, we store fake message shown in UI too
            if self.decoy:
                fake = f"🟣 You (neutral): I am busy right now.\n"
                self.fake_messages.append(("OUT", ts, "I am busy right now."))
                self.show(fake)
            else:
                self.show(f"🟣 You ({display_emotion}): {payload_text}\n")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            print("Send message error:", e)
            self.show("❌ Failed to send message.\n")

    def receive(self):
        buffer = b""
        try:
            while True:
                if not self.sock:
                    break
                data = self.sock.recv(4096)
                if not data:
                    break
                buffer += data

                while True:
                    if buffer.startswith(b"[FILE]|"):
                        newline_index = buffer.find(b"\n")
                        if newline_index == -1:
                            break
                        header = buffer[:newline_index].decode(errors="ignore")
                        parts = header.split("|")
                        if len(parts) < 3:
                            buffer = buffer[newline_index+1:]
                            continue
                        filename = parts[1]
                        try:
                            filesize = int(parts[2])
                        except:
                            filesize = 0
                        folder = Path("Received_Files")
                        folder.mkdir(exist_ok=True)
                        file_path = folder / filename
                        buffer = buffer[newline_index+1:]
                        received = 0
                        with open(file_path, "wb") as f:
                            if buffer:
                                write_bytes = buffer[:filesize]
                                f.write(write_bytes)
                                received += len(write_bytes)
                                buffer = buffer[len(write_bytes):]
                            while received < filesize:
                                chunk = self.sock.recv(min(4096, filesize - received))
                                if not chunk:
                                    break
                                f.write(chunk)
                                received += len(chunk)
                        self.show(f"📥 File received: {filename}\nSaved at: {file_path}\n")

                        # Prompt user to attempt extraction if it's an image
                        try:
                            ext = file_path.suffix.lower()
                            if ext in (".png", ".bmp", ".jpg", ".jpeg"):
                                do_extract = messagebox.askyesno("Stego image received", f"Received image '{filename}'. Try to auto-extract hidden data?")
                                if do_extract:
                                    try:
                                        payload = extract_bytes_from_image(str(file_path))
                                        # try to decode as text with known emotions
                                        for e in ("happy","sad","angry","fear","surprise","neutral"):
                                            try:
                                                dec = xor_decrypt_bytes(payload, e)
                                                txt = dec.decode("utf-8")
                                                if txt and len(txt) > 0:
                                                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                                                    # store as real incoming
                                                    self.real_messages.append(("IN", ts, e, txt))
                                                    self._log_line("IN", ts, e, txt)
                                                    if self.decoy:
                                                        # store fake shown message
                                                        self.fake_messages.append(("IN", ts, "Okay, talk later."))
                                                        self.show(f"🟡 Friend (neutral): Okay, talk later.\n")
                                                    else:
                                                        self.show(f"🕵 Received hidden text (assumed {e}): {txt}\n")
                                                    break
                                            except Exception:
                                                pass
                                        else:
                                            # couldn't decode as text — ask to save binary
                                            save_binary = messagebox.askyesno("Extracted payload", "Hidden payload couldn't be auto-decoded as text. Save as file?")
                                            if save_binary:
                                                save_path = filedialog.asksaveasfilename(initialfile="extracted_payload.bin")
                                                if save_path:
                                                    with open(save_path, "wb") as out_f:
                                                        out_f.write(payload)
                                                    self.show(f"🕵 Extracted payload saved to {save_path}\n")
                                    except Exception as e:
                                        messagebox.showerror("Stego extraction error", f"Could not extract from received image: {e}")
                        except Exception:
                            pass

                        continue

                    if buffer.startswith(b"[E_TXT]|"):
                        newline_index = buffer.find(b"\n")
                        if newline_index == -1:
                            break
                        line = buffer[:newline_index].decode(errors="ignore")
                        buffer = buffer[newline_index+1:]
                        try:
                            _, emo, b64 = line.split("|", 2)
                            enc = base64.b64decode(b64.encode("ascii"))
                            dec = xor_decrypt_bytes(enc, emo)
                            text = dec.decode("utf-8", errors="ignore")
                            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                            # store real incoming message (we assume emo is the transmitted emotion)
                            self.real_messages.append(("IN", ts, emo, text))
                            self._log_line("IN", ts, emo, text)
                            if self.decoy:
                                # Show fake message instead and store fake history
                                fake_shown = f"🟡 Friend (neutral): Okay, talk later.\n"
                                self.fake_messages.append(("IN", ts, "Okay, talk later."))
                                self.show(fake_shown)
                            else:
                                self.show(f"🟡 Friend ({emo}): {text}\n")
                        except Exception as e:
                            print("Decryption/display error:", e)
                            self.show("⚠ Received malformed encrypted text.\n")
                        continue

                    try:
                        text = buffer.decode(errors="ignore")
                    except:
                        text = ""
                    if text:
                        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        # store plain incoming text
                        self.real_messages.append(("IN", ts, "neutral", text))
                        self._log_line("IN", ts, "neutral", text)
                        if self.decoy:
                            self.fake_messages.append(("IN", ts, text))
                            self.show(f"🟡 Friend (neutral): Okay, talk later.\n")
                        else:
                            self.show(f"🟡 Friend: {text}\n")
                    buffer = b""
                    break
        except Exception as e:
            print("Receive error:", e)
        finally:
            self.connected = False
            try:
                if self.sock:
                    self.sock.close()
            except:
                pass
            self.sock = None
            self.show("🔴 Disconnected.\n")

    def send_file(self):
        if not self.connected or not self.sock:
            self.show("⚠ Not connected.\n")
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        filename = os.path.basename(path)
        filesize = os.path.getsize(path)
        try:
            header = f"[FILE]|{filename}|{filesize}\n".encode()
            self.sock.sendall(header)
            time.sleep(0.05)
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            self.show(f"📁 File sent: {filename} ({filesize} bytes)\n")
        except Exception as e:
            print("Send file error:", e)
            self.show("❌ Failed to send file.\n")

    def toggle_decoy(self):
        previous = self.decoy
        self.decoy = not self.decoy
        self.show(f"🔁 Decoy Mode: {'ON' if self.decoy else 'OFF'}\n")
        if previous and not self.decoy:
            # decoy was ON and now turned OFF -> restore real messages to chat box
            self._restore_real_messages_to_ui()

    def _restore_real_messages_to_ui(self):
        """Replace the chat_box contents with the real chat history."""
        try:
            self.chat_box.configure(state="normal")
            self.chat_box.delete("1.0", tk.END)
            for direction, ts, emo, txt in self.real_messages:
                if direction == "OUT":
                    self.chat_box.insert("end", f"🟣 You ({emo}) [{ts}]: {txt}\n")
                else:
                    self.chat_box.insert("end", f"🟡 Friend ({emo}) [{ts}]: {txt}\n")
            self.chat_box.see("end")
            self.chat_box.configure(state="disabled")
            # clear fake_messages since we replaced UI
            self.fake_messages.clear()
        except Exception as e:
            print("Restore UI error:", e)

    # Stego commands
    def stego_hide_text(self):
        carrier = filedialog.askopenfilename(title="Choose carrier image (PNG recommended)", filetypes=[("Images",".png;.bmp;.jpg;.jpeg")])
        if not carrier:
            return
        text = simpledialog.askstring("Text to hide", "Enter the text you want to hide:")
        if text is None:
            return
        emotion = analyze_emotion(text)
        payload = text.encode("utf-8")
        enc_payload = xor_encrypt_bytes(payload, emotion)
        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")], title="Save stego image as")
        if not out_path:
            return
        try:
            embed_bytes_in_image(carrier, enc_payload, out_path)
            self.show(f"🔒 Text hidden in image and saved to: {out_path} (emotion: {emotion})\n")
            # Offer to send to peer
            if self.connected and messagebox.askyesno("Send stego image?", "Send the created stego-image to connected peer?"):
                with open(out_path, "rb") as f:
                    data = f.read()
                self.send_bytes_as_file(os.path.basename(out_path), data)
        except Exception as e:
            messagebox.showerror("Stego error", f"Could not embed text: {e}")

    def stego_extract_text(self):
        stego = filedialog.askopenfilename(title="Choose stego image", filetypes=[("Images",".png;.bmp;.jpg;.jpeg")])
        if not stego:
            return
        try:
            payload = extract_bytes_from_image(stego)
            for e in ("happy","sad","angry","fear","surprise","neutral"):
                try:
                    dec = xor_decrypt_bytes(payload, e)
                    txt = dec.decode("utf-8")
                    if txt and len(txt) > 0:
                        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        self.real_messages.append(("IN", ts, e, txt))
                        self._log_line("IN", ts, e, txt)
                        self.show(f"🕵 Extracted text (assumed {e}): {txt}\n")
                        return
                except Exception:
                    pass
            b64 = base64.b64encode(payload).decode()
            self.show(f"⚠ Could not auto-decrypt stego payload. Base64 preview:\n{b64[:200]}...\n")
            chosen = simpledialog.askstring("Emotion", "Enter emotion used to encrypt (happy/sad/angry/fear/surprise/neutral):")
            if chosen:
                try:
                    dec = xor_decrypt_bytes(payload, chosen)
                    text = dec.decode("utf-8", errors="ignore")
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    self.real_messages.append(("IN", ts, chosen, text))
                    self._log_line("IN", ts, chosen, text)
                    self.show(f"🕵 Extracted text ({chosen}): {text}\n")
                except Exception as e:
                    messagebox.showerror("Decryption error", f"Could not decrypt with emotion '{chosen}': {e}")
        except Exception as e:
            messagebox.showerror("Stego error", f"Could not extract: {e}")

    def stego_hide_file(self):
        carrier = filedialog.askopenfilename(title="Choose carrier image (PNG recommended)", filetypes=[("Images",".png;.bmp")])
        if not carrier:
            return
        file_to_hide = filedialog.askopenfilename(title="Choose file to hide (any file)")
        if not file_to_hide:
            return
        emotion = analyze_emotion(Path(file_to_hide).name)
        chosen = simpledialog.askstring("Emotion for encryption", f"Detected '{emotion}'. Enter emotion to use (or press OK to use detected):")
        if chosen and chosen.strip():
            emotion = chosen.strip()
        with open(file_to_hide, "rb") as f:
            payload_bytes = f.read()
        enc_payload = xor_encrypt_bytes(payload_bytes, emotion)
        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")], title="Save stego image as")
        if not out_path:
            return
        try:
            embed_bytes_in_image(carrier, enc_payload, out_path)
            self.show(f"🔒 File hidden in image and saved to: {out_path} (emotion: {emotion})\n")
            # offer to send
            if self.connected and messagebox.askyesno("Send stego image?", "Send the created stego-image to connected peer?"):
                with open(out_path, "rb") as f:
                    data = f.read()
                self.send_bytes_as_file(os.path.basename(out_path), data)
        except Exception as e:
            messagebox.showerror("Stego error", f"Could not embed file: {e}")

    def stego_extract_file(self):
        stego = filedialog.askopenfilename(title="Choose stego image", filetypes=[("Images",".png;.bmp;.jpg;.jpeg")])
        if not stego:
            return
        try:
            payload = extract_bytes_from_image(stego)
            for e in ("happy","sad","angry","fear","surprise","neutral"):
                try:
                    dec = xor_decrypt_bytes(payload, e)
                    save_path = filedialog.asksaveasfilename(title=f"Save extracted file (assumed {e})")
                    if not save_path:
                        return
                    with open(save_path, "wb") as out_f:
                        out_f.write(dec)
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    self.real_messages.append(("IN", ts, e, f"<binary file saved to {save_path}>"))
                    self._log_line("IN", ts, e, f"<binary file saved to {save_path}>")
                    self.show(f"🕵 Extracted file saved to {save_path} (assumed emotion: {e})\n")
                    return
                except Exception:
                    pass
            chosen = simpledialog.askstring("Emotion", "Enter emotion used to encrypt (happy/sad/angry/fear/surprise/neutral):")
            if not chosen:
                return
            dec = xor_decrypt_bytes(payload, chosen)
            save_path = filedialog.asksaveasfilename(title="Save extracted file (decrypted)")
            if not save_path:
                return
            with open(save_path, "wb") as out_f:
                out_f.write(dec)
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.real_messages.append(("IN", ts, chosen, f"<binary file saved to {save_path}>"))
            self._log_line("IN", ts, chosen, f"<binary file saved to {save_path}>")
            self.show(f"🕵 Extracted file saved to {save_path} (used {chosen})\n")
        except Exception as e:
            messagebox.showerror("Stego error", f"Could not extract: {e}")

    def show_secure_log(self):
        """Decrypt and display the secure log file (prompts for password if needed)."""
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Secure Log", "No log file found.")
            return
        # If we have no fernet/xor_key (e.g., user started without password), ask for password now
        local_fernet = self.fernet
        local_xor = self.xor_key
        if not local_fernet and not local_xor:
            pwd = simpledialog.askstring("Log password", "Enter log password to decrypt saved chat log:", show="*")
            if not pwd:
                messagebox.showinfo("Secure Log", "No password provided. Cannot decrypt.")
                return
            if FERNET_AVAILABLE:
                try:
                    key = derive_fernet_key(pwd, self.log_salt)
                    local_fernet = Fernet(key)
                except Exception as e:
                    # fallback test - maybe wrong password; we'll still try XOR below
                    local_fernet = None
            if not local_fernet:
                local_xor = derive_xor_key_from_password(pwd, self.log_salt, length=64)

        lines = read_encrypted_log_lines()
        decrypted = decrypt_log_lines(lines, fernet_obj=local_fernet, xor_key=local_xor)
        # show in a simple dialog (large)
        text = "\n".join(decrypted)
        top = tk.Toplevel(self.root)
        top.title("Decrypted Secure Log")
        txt = tk.Text(top, wrap="word")
        txt.insert("1.0", text)
        txt.configure(state="disabled")
        txt.pack(expand=True, fill="both")
        top.geometry("700x500")

    def on_close(self):
        self.stop_threads = True
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        try:
            if self.server_socket:
                self.server_socket.close()
        except:
            pass
        self.root.destroy()

# Compatibility functions (kept)
def emotion_adaptive_encrypt(message, emotion):
    if emotion == "happy":
        return f"[H-ENC]{''.join(reversed(message))}"
    elif emotion == "sad":
        return f"[S-ENC]{''.join(chr(ord(c)+1) for c in message)}"
    else:
        return f"[N-ENC]{message}"

def emotion_adaptive_decrypt(enc_message):
    if enc_message.startswith("[H-ENC]"):
        return ''.join(reversed(enc_message[7:]))
    elif enc_message.startswith("[S-ENC]"):
        return ''.join(chr(ord(c)-1) for c in enc_message[7:])
    return enc_message.replace("[N-ENC]", "")

# Run
if __name__ == "__main__":
    root = ctk.CTk()
    SecureChatApp(root)
    root.mainloop()