#!/usr/bin/env python3
"""
trellix_ip_checker_ttl_append_gui.py (final, region’lu, blacklist logic)

- Non-malicious IP'leri append modunda saklar, geçmiş kayıtları korur
- TTL uygulanır (score'a göre dinamik):
    - Score 0-10   -> 3 gün
    - Score 10-20  -> 2 gün
    - Score 20-30  -> 1 gün
    - Score >=30   -> direkt blackliste eklenir
- GUI'de non-malicious IP'ler için Confidence Score ve TTL (gün olarak) gösterilir
- API anahtarları otomatik sırayla kullanılır
"""

#region Imports
import csv
import re
import time
import threading
from pathlib import Path
from typing import Set, Dict
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox
import requests
import os
from dotenv import load_dotenv
#endregion

#region Environment Setup
def setup_env_file():
    """Program başlangıcında .env dosyasını kontrol eder, yoksa oluşturur."""
    env_path = Path(".env")
    if not env_path.exists():
        # Ana GUI oluşturulmadan önce dialog göstermek için geçici bir root penceresi
        temp_root = tk.Tk()
        temp_root.withdraw()  # Ana pencereyi gizle

        keys_input = simpledialog.askstring(
            "API Anahtarı Kurulumu",
            "'.env' dosyası bulunamadı.\n\n"
            "Lütfen AbuseIPDB API anahtarlarınızı virgülle ayırarak girin:",
            parent=temp_root
        )

        if keys_input and keys_input.strip():
            with env_path.open("w", encoding="utf-8") as f:
                f.write(f'ABUSEIPDB_API_KEYS="{keys_input.strip()}"\n')
            messagebox.showinfo(
                "Başarılı", "API anahtarları '.env' dosyasına başarıyla kaydedildi.", parent=temp_root
            )
        else:
            messagebox.showwarning("Uyarı", "API anahtarları girilmedi. Program anahtarlar olmadan çalışamaz.", parent=temp_root)
        temp_root.destroy()
#endregion

#region Constants & Regex
IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
PRIVATE_AND_BOGON_RANGES = [
    re.compile(r"^10\."), re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^192\.168\."), re.compile(r"^169\.254\."),
    re.compile(r"^127\."), re.compile(r"^0\."), re.compile(r"^255\.255\.255\.255")
]
DEFAULT_GITHUB_URL = "https://raw.githubusercontent.com/Infinitum-IT/IOAs/master/ips.txt"
NON_MALICIOUS_FILE = Path("non_malicious.txt")
#endregion

#region AbuseIPDB API Keys & Globals
setup_env_file()
load_dotenv()

api_keys_str = os.getenv("ABUSEIPDB_API_KEYS")
if not api_keys_str:
    ABUSEIPDB_KEYS = []
else:
    ABUSEIPDB_KEYS = [key.strip() for key in api_keys_str.split(',')]

api_remaining_quota = None
current_key_index = 0
#endregion

#region TTL Logic & Blacklist Check
def get_ttl_seconds(score: int) -> int:
    """Score değerine göre TTL belirle (non-malicious IP'ler için)"""
    if 0 <= score <= 10:
        return 259200  # 3 gün
    elif 10 < score <= 20:
        return 172800  # 2 gün
    elif 20 < score < 30:
        return 86400   # 1 gün
    else:
        return 0       # 30 ve üzeri score blackliste, TTL yok
#endregion

#region API Key Management
def get_current_api_key():
    global current_key_index
    return ABUSEIPDB_KEYS[current_key_index]

def switch_api_key():
    global current_key_index
    if current_key_index < len(ABUSEIPDB_KEYS) - 1:
        current_key_index += 1
        return True
    return False
#endregion

#region IP Helpers
def is_invalid_or_private_ip(ip: str) -> bool:
    return any(regex.match(ip) for regex in PRIVATE_AND_BOGON_RANGES)

def load_ips_from_file(path: Path) -> Set[str]:
    ips: Set[str] = set()
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("Source IP", "").strip()
            if IP_REGEX.match(ip):
                ips.add(ip)
    return ips

def extract_ips_from_text(text: str) -> Set[str]:
    return set(IP_REGEX.findall(text))

def load_ips_from_github(url: str) -> Set[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return extract_ips_from_text(resp.text)
#endregion

#region AbuseIPDB Query
def query_abuseipdb(ip: str, max_age: int = 90, log_output=None) -> Dict:
    global api_remaining_quota
    while True:
        api_key = get_current_api_key()
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age}
        try:
            r = requests.get(endpoint, headers=headers, params=params, timeout=15)
            if r.status_code == 429:
                if switch_api_key():
                    if log_output:
                        log_output.insert(tk.END, "[!] API anahtarı limiti aşıldı. Sonraki anahtara geçiliyor...\n")
                        log_output.see(tk.END)
                    continue
                else:
                    raise Exception("Tüm API anahtarlarının limiti aşıldı.")
            r.raise_for_status()
        except requests.RequestException as e:
            if switch_api_key():
                if log_output:
                    log_output.insert(tk.END, f"[!] API hatası ({e}). Sonraki anahtara geçiliyor...\n")
                    log_output.see(tk.END)
                continue
            else:
                raise
        api_remaining_quota = r.headers.get("X-RateLimit-Remaining")
        return r.json()['data']
#endregion

#region Cache Management
def load_non_malicious():
    ips = {}
    if NON_MALICIOUS_FILE.exists():
        with NON_MALICIOUS_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    ip, ts, score = line.strip().split(",")
                    ts, score = float(ts), int(score)
                    ttl = get_ttl_seconds(score)
                    if ttl > 0 and time.time() - ts < ttl:
                        ips[ip] = ts
                except ValueError:
                    continue
    return ips

def append_non_malicious(ip: str, score: int):
    with NON_MALICIOUS_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{ip},{time.time()},{score}\n")
#endregion

#region GUI
def run_gui():
    global root, stop_flag
    stop_flag = False

    #region GUI Helpers
    def select_file():
        file_path = filedialog.askopenfilename(filetypes=[["CSV files", "*.csv"]])
        if file_path:
            entry_input.delete(0, tk.END)
            entry_input.insert(0, file_path)

    def stop_check():
        global stop_flag
        stop_flag = True

    def update_api_status():
        """Updates the API key status label in the GUI."""
        if ABUSEIPDB_KEYS:
            status_text = f"Mevcut API Anahtarı: {current_key_index + 1}/{len(ABUSEIPDB_KEYS)}"
            if api_remaining_quota is not None:
                status_text += f"   |   Kalan Sorgu Hakkı: {api_remaining_quota}"
            api_status_var.set(status_text)
        else:
            api_status_var.set("API Anahtarı Bulunamadı. Lütfen .env dosyasını kontrol edin.")
    #endregion

    #region Main Threaded Check
    def threaded_check():
        if not ABUSEIPDB_KEYS:
            text_output.insert(tk.END, "[!] HATA: API anahtarları bulunamadı. Lütfen .env dosyasını kontrol edin.\n")
            text_output.insert(tk.END, "    .env dosyası 'ABUSEIPDB_API_KEYS=\"key1,key2,...\"' şeklinde olmalıdır.\n")
            text_output.see(tk.END)
            return

        input_file = entry_input.get()
        if not input_file:
            text_output.insert(tk.END, "[!] Lütfen bir giriş dosyası seçin.\n")
            return

        input_path = Path(input_file)
        if not input_path.exists():
            text_output.insert(tk.END, f"[!] Dosya bulunamadı: {input_file}\n")
            return

        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, "[*] Trellix çıktısından IP'ler yükleniyor...\n")
        trellix_ips = load_ips_from_file(input_path)
        text_output.insert(tk.END, f"    {len(trellix_ips)} benzersiz IP bulundu.\n")

        text_output.insert(tk.END, "[*] GitHub üzerinden referans IP'ler yükleniyor...\n")
        github_ips = load_ips_from_github(DEFAULT_GITHUB_URL)
        text_output.insert(tk.END, f"    {len(github_ips)} referans IP yüklendi.\n")

        non_malicious = load_non_malicious()
        ips_to_check = sorted(
            ip for ip in (trellix_ips - github_ips)
            if not is_invalid_or_private_ip(ip) and ip not in non_malicious
        )
        text_output.insert(tk.END, f"[*] Kontrol edilecek {len(ips_to_check)} geçerli public IP bulundu.\n\n")

        malicious = []
        for i, ip in enumerate(ips_to_check, 1):
            if stop_flag:
                text_output.insert(tk.END, "[*] Kontrol kullanıcı tarafından durduruldu.\n")
                break
            try:
                result = query_abuseipdb(ip, log_output=text_output)
                score = result.get("abuseConfidenceScore", 0)

                update_api_status()  # Update status after each query

                if score >= 30:  # 30 ve üzeri -> direkt blackliste
                    malicious.append(ip)
                    text_output.insert(tk.END, f"[{i}/{len(ips_to_check)}] Blacklist (Zararlı) IP: {ip} | Confidence Score: {score}\n")
                else:  # TTL mantığı ile non-malicious
                    append_non_malicious(ip, score)
                    ttl_days = get_ttl_seconds(score) // 86400
                    text_output.insert(tk.END, f"[{i}/{len(ips_to_check)}] Kontrol edildi: {ip}\n")
                    text_output.insert(tk.END, f"    Non-Malicious | Confidence Score: {score} → TTL: {ttl_days} gün\n")

                text_output.see(tk.END)
                root.update_idletasks()
                time.sleep(0.1)

            except Exception as e:
                update_api_status()  # Also update on error
                text_output.insert(tk.END, f"[!] Hata ({ip}): {str(e)}\n")
                text_output.see(tk.END)
                root.update_idletasks()

        if malicious:
            text_output.insert(tk.END, f"[*] Blacklist IP adresleri: {';'.join(malicious)}\n")
        else:
            text_output.insert(tk.END, "[*] Zararlı IP bulunamadı.\n")
        update_api_status()  # Final update
        text_output.see(tk.END)
    #endregion

    #region GUI Run
    def run_check():
        global stop_flag
        stop_flag = False
        threading.Thread(target=threaded_check, daemon=True).start()

    root = tk.Tk()
    root.title("Trellix IP Kontrol Aracı (TTL + Append)")
    root.configure(bg="#2e2e2e")

    frame = tk.Frame(root, bg="#2e2e2e")
    frame.pack(padx=10, pady=10, fill="x")

    tk.Label(frame, text="Giriş CSV Dosyası:", bg="#2e2e2e", fg="#ffffff").grid(row=0, column=0, sticky="w")
    entry_input = tk.Entry(frame, width=60, bg="#3c3c3c", fg="#ffffff", insertbackground="#ffffff")
    entry_input.grid(row=0, column=1, padx=5, sticky="ew")
    tk.Button(frame, text="Gözat", command=select_file, bg="#444444", fg="#ffffff").grid(row=0, column=2)
    frame.grid_columnconfigure(1, weight=1)

    tk.Button(frame, text="Kontrolü Başlat", command=run_check, bg="#5c5c5c", fg="#ffffff").grid(row=1, column=1, pady=10)
    tk.Button(frame, text="Durdur", command=stop_check, bg="#aa4444", fg="#ffffff").grid(row=1, column=2, padx=5)

    # API Status Label
    api_status_var = tk.StringVar()
    api_status_label = tk.Label(frame, textvariable=api_status_var, bg="#2e2e2e", fg="#a0a0a0", justify=tk.LEFT)
    api_status_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

    text_output = scrolledtext.ScrolledText(root, width=100, height=30, bg="#1e1e1e", fg="#dcdcdc", insertbackground="#ffffff")
    text_output.pack(padx=10, pady=5, fill="both", expand=True)

    update_api_status()  # Set initial status
    root.mainloop()
    #endregion
#endregion

if __name__ == "__main__":
    run_gui()
