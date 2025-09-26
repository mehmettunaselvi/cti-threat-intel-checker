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
from collections import Counter
import json
from pathlib import Path
from typing import Set, Dict
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox
import requests

# Yerel modülleri import et
from vt_lookup import vt_lookup, VTLookupError
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
        
        env_content = ""
        
        abuse_keys_input = simpledialog.askstring(
            "AbuseIPDB API Anahtarı Kurulumu",
            "Lütfen AbuseIPDB API anahtarlarınızı virgülle ayırarak girin (isteğe bağlı):",
            parent=temp_root
        )
        if abuse_keys_input and abuse_keys_input.strip():
            env_content += f'ABUSEIPDB_API_KEYS="{abuse_keys_input.strip()}"\n'

        vt_key_input = simpledialog.askstring(
            "VirusTotal API Anahtarı Kurulumu",
            "Lütfen VirusTotal API anahtarınızı girin (isteğe bağlı):",
            parent=temp_root
        )
        if vt_key_input and vt_key_input.strip():
            env_content += f'VT_API_KEY="{vt_key_input.strip()}"\n'

        if env_content:
            with env_path.open("w", encoding="utf-8") as f:
                f.write(env_content)
            messagebox.showinfo("Başarılı", "API anahtarları '.env' dosyasına kaydedildi.", parent=temp_root)
        else:
            messagebox.showwarning("Uyarı", "Hiçbir API anahtarı girilmedi. Program sınırlı işlevsellikle çalışabilir.", parent=temp_root)
        
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
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}
#endregion

#region API Keys & Globals
setup_env_file()
load_dotenv()

api_keys_str = os.getenv("ABUSEIPDB_API_KEYS")
if not api_keys_str:
    ABUSEIPDB_KEYS = []
else:
    ABUSEIPDB_KEYS = [key.strip() for key in api_keys_str.split(',')]

VT_API_KEY = os.getenv("VT_API_KEY")

api_remaining_quota = None
current_key_index = 0
scan_results = [] # Taramadan elde edilen sonuçları saklamak için global liste
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
def query_abuseipdb(ip: str, max_age_in_days: int, log_output=None) -> Dict:
    global api_remaining_quota
    while True:
        api_key = get_current_api_key()
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_in_days, "verbose": True}
        try:
            r = requests.get(endpoint, headers=headers, params=params, timeout=15)
            if r.status_code == 429:
                if switch_api_key():
                    if log_output:
                        log_output.insert(tk.END, "[!] AbuseIPDB API limiti aşıldı. Sonraki anahtara geçiliyor...\n")
                        log_output.see(tk.END)
                    continue
                else:
                    raise Exception("Tüm AbuseIPDB API anahtarlarının limiti aşıldı.")
            r.raise_for_status()
        except requests.RequestException as e:
            if switch_api_key():
                if log_output:
                    log_output.insert(tk.END, f"[!] AbuseIPDB API hatası ({e}). Sonraki anahtara geçiliyor...\n")
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

    def update_api_status(service):
        """Updates the API key status label in the GUI."""
        if service == "AbuseIPDB":
            if ABUSEIPDB_KEYS:
                status_text = f"Mevcut AbuseIPDB Anahtarı: {current_key_index + 1}/{len(ABUSEIPDB_KEYS)}"
                if api_remaining_quota is not None:
                    status_text += f"   |   Kalan Sorgu Hakkı: {api_remaining_quota}"
                api_status_var.set(status_text)
            else:
                api_status_var.set("AbuseIPDB API Anahtarı Bulunamadı.")
        elif service == "VirusTotal":
            if VT_API_KEY:
                api_status_var.set("VirusTotal API Anahtarı Yüklendi.")
            else:
                api_status_var.set("VirusTotal API Anahtarı Bulunamadı.")

    def save_results():
        """Taramadan elde edilen sonuçları bir JSON dosyasına kaydeder."""
        if not scan_results:
            messagebox.showinfo("Bilgi", "Kaydedilecek sonuç bulunmuyor. Lütfen önce bir tarama yapın.", parent=root)
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Sonuçları Kaydet"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, ensure_ascii=False, indent=4)
            messagebox.showinfo("Başarılı", f"Sonuçlar başarıyla '{file_path}' dosyasına kaydedildi.", parent=root)
    #endregion

    #region Main Threaded Check
    def threaded_check():
        selected_service = service_var.get()
        
        if selected_service == "AbuseIPDB" and not ABUSEIPDB_KEYS:
            text_output.insert(tk.END, "[!] HATA: AbuseIPDB API anahtarları bulunamadı. Lütfen .env dosyasını kontrol edin.\n")
            return
        if selected_service == "VirusTotal" and not VT_API_KEY:
            text_output.insert(tk.END, "[!] HATA: VirusTotal API anahtarı (VT_API_KEY) bulunamadı. Lütfen .env dosyasını kontrol edin.\n")
            return

        input_file = entry_input.get()
        if not input_file:
            text_output.insert(tk.END, "[!] Lütfen bir giriş dosyası seçin.\n")
            return

        try:
            malicious_threshold = int(threshold_entry.get())
        except ValueError:
            text_output.insert(tk.END, "[!] HATA: Zararlılık eşiği geçerli bir sayı olmalıdır.\n")
            return

        try:
            max_age = int(max_age_entry.get())
        except ValueError:
            text_output.insert(tk.END, "[!] HATA: Rapor yaşı geçerli bir sayı olmalıdır.\n")
            return

        input_path = Path(input_file)
        if not input_path.exists():
            text_output.insert(tk.END, f"[!] Dosya bulunamadı: {input_file}\n")
            return

        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, f"[*] Servis seçildi: {selected_service}\n")
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

        global scan_results
        scan_results.clear() # Her yeni taramada sonuçları temizle

        malicious = []
        for i, ip in enumerate(ips_to_check, 1):
            if stop_flag:
                text_output.insert(tk.END, "[*] Kontrol kullanıcı tarafından durduruldu.\n")
                break
            try:
                score = 0
                score_label = ""
                ip_result_data = { "ip": ip, "service": selected_service }
                
                if selected_service == "AbuseIPDB":
                    result = query_abuseipdb(ip, max_age_in_days=max_age, log_output=text_output)
                    ip_result_data["details"] = {
                        "countryCode": result.get('countryCode', 'N/A'),
                        "isWhitelisted": result.get('isWhitelisted', 'N/A'),
                        "isp": result.get('isp', 'N/A'),
                        "domain": result.get('domain', 'N/A'),
                        "usageType": result.get('usageType', 'N/A'),
                        "totalReports": result.get('totalReports', 0),
                        "numDistinctUsers": result.get('numDistinctUsers', 0)
                    }
                    # text_output.insert(tk.END, f"    [AbuseIPDB Full Response]:\n{json.dumps(result, indent=4, ensure_ascii=False)}\n")
                    score = result.get("abuseConfidenceScore", 0)
                    # Add a summary line with key fields
                    summary_line = (
                        f"    Özet: Ülke: {result.get('countryCode', 'N/A')}, "
                        f"Whitelisted: {result.get('isWhitelisted', 'N/A')}, "
                        f"ISP: {result.get('isp', 'N/A')}, Domain: {result.get('domain', 'N/A')}, "
                        f"Kullanım Tipi: {result.get('usageType', 'N/A')}\n"
                    )
                    text_output.insert(tk.END, summary_line)

                    # Add report counts
                    report_counts_line = (
                        f"    Raporlar: Toplam {result.get('totalReports', 0)} rapor, {result.get('numDistinctUsers', 0)} farklı kullanıcı tarafından.\n"
                    )
                    text_output.insert(tk.END, report_counts_line)

                    # Extract and display report categories
                    reports = result.get("reports", [])
                    if reports:
                        category_counts = Counter(cat for report in reports for cat in report.get("categories", []))
                        top_categories = category_counts.most_common(10)
                        report_categories = { ABUSEIPDB_CATEGORIES.get(cat_id, 'Bilinmeyen'): count for cat_id, count in top_categories }
                        ip_result_data["details"]["report_categories"] = report_categories

                        category_str = "\n        ".join([f"- {category_name}: {count} rapor" for category_name, count in report_categories.items()])
                        category_line = f"    Rapor Kategorileri:\n        {category_str}\n"
                        text_output.insert(tk.END, category_line)

                    score_label = f"Confidence Score: {score}"
                    update_api_status(selected_service)
                
                elif selected_service == "VirusTotal":
                    result = vt_lookup(ip, "ip")
                    ip_result_data["details"] = result.get("vt_summary", {})
                    # Display the raw response from the API
                    # text_output.insert(tk.END, f"    [VirusTotal Full Response]:\n{json.dumps(result.get('raw', {}), indent=4, ensure_ascii=False)}\n")

                    if result.get("status") == "not_found":
                        score = 0
                        score_label = "VT'de bulunamadı"
                    else:
                        score = result["vt_summary"].get("malicious_votes", 0)
                        score_label = f"Malicious Votes: {score}"
                    update_api_status(selected_service)

                ip_result_data["score"] = score
                ip_result_data["is_malicious"] = score >= malicious_threshold

                if score >= malicious_threshold:
                    malicious.append(ip)
                    text_output.insert(tk.END, f"[{i}/{len(ips_to_check)}] Blacklist (Zararlı) IP: {ip} | {score_label}\n", "error")
                else:
                    # Sadece skoru 0 olanları non-malicious olarak önbelleğe al.
                    if score == 0:
                        append_non_malicious(ip, score)
                    ttl_days = get_ttl_seconds(score) // 86400
                    text_output.insert(tk.END, f"[{i}/{len(ips_to_check)}] Kontrol edildi: {ip}\n")
                    text_output.insert(tk.END, f"    Non-Malicious | {score_label} → TTL: {ttl_days} gün\n")
                scan_results.append(ip_result_data)
                text_output.see(tk.END)
                root.update_idletasks()
                time.sleep(0.1) # Genel bir bekleme

            except (Exception, VTLookupError) as e:
                update_api_status(selected_service)
                text_output.insert(tk.END, f"[!] Hata ({ip}): {str(e)}\n")
                text_output.see(tk.END)
                root.update_idletasks()

        if malicious:
            text_output.insert(tk.END, f"\n[*] Toplam {len(malicious)} zararlı IP adresi bulundu: {';'.join(malicious)}\n")
        else:
            text_output.insert(tk.END, "\n[*] Zararlı IP bulunamadı.\n")
        update_api_status(selected_service)
        text_output.see(tk.END)
    #endregion

    #region GUI Run
    def run_check():
        global stop_flag
        stop_flag = False
        threading.Thread(target=threaded_check, daemon=True).start()

    root = tk.Tk()
    root.title("CTI IP Kontrol Aracı")
    root.configure(bg="#2e2e2e")

    # --- Input Frame ---
    input_frame = tk.Frame(root, bg="#2e2e2e")
    input_frame.pack(padx=10, pady=10, fill="x")

    tk.Label(input_frame, text="Giriş CSV Dosyası:", bg="#2e2e2e", fg="#ffffff").grid(row=0, column=0, sticky="w", pady=2)
    entry_input = tk.Entry(input_frame, width=60, bg="#3c3c3c", fg="#ffffff", insertbackground="#ffffff")
    entry_input.grid(row=0, column=1, padx=5, sticky="ew")
    tk.Button(input_frame, text="Gözat", command=select_file, bg="#444444", fg="#ffffff").grid(row=0, column=2)
    input_frame.grid_columnconfigure(1, weight=1)

    # --- Options Frame ---
    options_frame = tk.Frame(root, bg="#2e2e2e")
    options_frame.pack(padx=10, pady=(0, 10), fill="x")

    # Service Selection
    service_frame = tk.LabelFrame(options_frame, text="Sorgu Servisi", bg="#2e2e2e", fg="#ffffff", padx=5, pady=5)
    service_frame.pack(side="left", fill="x", expand=True)
    service_var = tk.StringVar(value="AbuseIPDB")
    tk.Radiobutton(service_frame, text="AbuseIPDB", variable=service_var, value="AbuseIPDB", bg="#2e2e2e", fg="#ffffff", selectcolor="#3c3c3c", command=lambda: update_api_status("AbuseIPDB")).pack(side="left")
    tk.Radiobutton(service_frame, text="VirusTotal", variable=service_var, value="VirusTotal", bg="#2e2e2e", fg="#ffffff", selectcolor="#3c3c3c", command=lambda: update_api_status("VirusTotal")).pack(side="left", padx=10)

    # Threshold Setting
    threshold_frame = tk.LabelFrame(options_frame, text="Zararlılık Eşiği", bg="#2e2e2e", fg="#ffffff", padx=5, pady=5)
    threshold_frame.pack(side="left", fill="x", expand=True, padx=10)
    tk.Label(threshold_frame, text="Skor >=", bg="#2e2e2e", fg="#ffffff").pack(side="left")
    threshold_entry = tk.Entry(threshold_frame, width=5, bg="#3c3c3c", fg="#ffffff", insertbackground="#ffffff")
    threshold_entry.insert(0, "30")
    threshold_entry.pack(side="left", padx=5)

    # Max Age Setting
    max_age_frame = tk.LabelFrame(options_frame, text="Rapor Yaşı (gün)", bg="#2e2e2e", fg="#ffffff", padx=5, pady=5)
    max_age_frame.pack(side="left", fill="x", expand=True)
    tk.Label(max_age_frame, text="En fazla:", bg="#2e2e2e", fg="#ffffff").pack(side="left")
    max_age_entry = tk.Entry(max_age_frame, width=5, bg="#3c3c3c", fg="#ffffff", insertbackground="#ffffff")
    max_age_entry.insert(0, "90")
    max_age_entry.pack(side="left", padx=5)

    # --- Control Frame ---
    control_frame = tk.Frame(root, bg="#2e2e2e")
    control_frame.pack(padx=10, pady=5, fill="x")
    tk.Button(control_frame, text="Kontrolü Başlat", command=run_check, bg="#5c5c5c", fg="#ffffff", height=2).pack(side="left", fill="x", expand=True)
    tk.Button(control_frame, text="Durdur", command=stop_check, bg="#aa4444", fg="#ffffff", height=2).pack(side="left", fill="x", expand=True, padx=5)
    tk.Button(control_frame, text="Sonuçları Kaydet", command=save_results, bg="#4a7a4a", fg="#ffffff", height=2).pack(side="left", fill="x", expand=True)

    # --- Status and Output ---
    api_status_var = tk.StringVar()
    api_status_label = tk.Label(root, textvariable=api_status_var, bg="#2e2e2e", fg="#a0a0a0", justify=tk.LEFT)
    api_status_label.pack(padx=10, pady=(5, 0), fill="x")

    text_output = scrolledtext.ScrolledText(root, width=100, height=25, bg="#1e1e1e", fg="#dcdcdc", insertbackground="#ffffff")
    text_output.tag_config("error", foreground="#ff6b6b")
    text_output.pack(padx=10, pady=5, fill="both", expand=True)

    update_api_status(service_var.get())  # Set initial status
    root.mainloop()
    #endregion
#endregion

if __name__ == "__main__":
    run_gui()
