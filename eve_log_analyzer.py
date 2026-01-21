import json
import pandas as pd
import os
import argparse
import matplotlib.pyplot as plt
import numpy as np

# ==========================================
# KONFIGURASI MAPPING (DATABASE SIGNATURE)
# ==========================================
# (Tidak diubah, sesuai script awal)
ATTACK_SCENARIOS = {
    "1. Port Scanning (Nmap)": ["Nmap", "SCAN", "nmap"],
    "2. SSH Brute Force (Hydra)": ["SSH", "Brute Force", "hydra"],
    "3. DoS Attack (Hping3)": ["ICMP", "Flood", "DoS", "Hping", "Large ICMP"],
    "4. SQL Injection (Curl)": ["SQL", "Union", "Syntax", "UNION SELECT"],
    "5. XSS (Curl)": ["XSS", "Script", "Cross Site", "alert("],
    "6. Path Traversal (Curl)": ["Traversal", "Directory", "etc/passwd", "../"],
    "7. RCE (Metasploit)": ["Metasploit", "Exploit", "Meterpreter", "reverse_tcp", "handler"]
}

QUIET_ACTIVITIES = {
    "1. Download Binary": ["POLICY PE EXE", "DLL Windows", "file download"],
    "2. System Update": ["GNU/Linux APT", "User-Agent", "Debian APT"],
    "3. SSH Login Agresif": ["SSH Brute Force"], 
    "4. Net Diagnostic": ["INFO PING", "Large ICMP Packet"],
    "5. FTP Login": ["FTP Login", "FTP USER"],
    "6. Non-Standard Port": ["HTTP on non-standard port", ":8180", ":8080"],
    "7. The Lost User": ["HTTP 404", "WEB_SERVER 404"]
}

def load_filtered_data(file_path):
    """
    Membaca file JSON dan mengambil field penting.
    (Diperbarui sedikit untuk mengambil data lampiran detail)
    """
    if not os.path.exists(file_path): return None
    data = []
    try:
        print(f"Sedang membaca file: {file_path} ...")
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get('event_type') == 'alert':
                        # Flat entry untuk analisis & lampiran
                        flat_entry = {
                            'timestamp': entry.get('timestamp'),
                            'src_ip': entry.get('src_ip'),
                            'dest_ip': entry.get('dest_ip'),
                            'flow_id': entry.get('flow_id', entry.get('timestamp')), 
                            'alert.signature': entry.get('alert', {}).get('signature', 'Unknown')
                        }
                        data.append(flat_entry)
                except json.JSONDecodeError: continue
        return pd.DataFrame(data)
    except Exception: return None

def analyze_events_detailed(df, mapping_dict, filter_ip=None, exclude_ip=None):
    """
    Fungsi Analisis Event-Based (Modifikasi dari script awal).
    Sekarang mengembalikan 2 hal: 
    1. Counts (untuk statistik/grafik)
    2. Details (untuk lampiran Excel)
    """
    if df is None or df.empty:
        return {k: 0 for k in mapping_dict.keys()}, pd.DataFrame()

    # Filter IP (Sesuai logika awal)
    if filter_ip: df = df[df['src_ip'] == filter_ip]
    if exclude_ip: df = df[df['src_ip'] != exclude_ip]

    unique_events_tracker = {k: set() for k in mapping_dict.keys()}
    detailed_records = [] # List baru untuk menampung data lampiran

    for index, row in df.iterrows():
        sig = str(row['alert.signature'])
        flow = row['flow_id']
        
        matched = False
        for category, keywords in mapping_dict.items():
            for kw in keywords:
                if kw.lower() in sig.lower():
                    # Cek Flow ID (Logika Event-Based)
                    if flow not in unique_events_tracker[category]:
                        unique_events_tracker[category].add(flow)
                        
                        # [FITUR TAMBAHAN] Simpan detail untuk Excel
                        detailed_records.append({
                            "Waktu": row['timestamp'],
                            "Skenario": category,
                            "Signature": row['alert.signature'],
                            "Source": row['src_ip'],
                            "Target": row['dest_ip'],
                            "Flow ID": str(flow)
                        })
                    matched = True
                    break 
            if matched: break 
            
    # Hitung total dari set unique
    counts = {k: len(v) for k, v in unique_events_tracker.items()}
    
    # Buat DataFrame detail
    df_details = pd.DataFrame(detailed_records)
    if not df_details.empty:
        df_details = df_details.sort_values(by=["Skenario", "Waktu"])

    return counts, df_details

def generate_chart(pre_counts, post_counts, output_filename="grafik_perbandingan.png"):
    """
    [FITUR TAMBAHAN] Membuat Grafik Batang Otomatis
    """
    print(f"\n[GRAFIK] Membuat grafik visualisasi: {output_filename} ...")
    
    labels = list(pre_counts.keys())
    short_labels = [l.split(". ")[1] if ". " in l else l for l in labels]
    
    pre_vals = list(pre_counts.values())
    post_vals = list(post_counts.values())

    x = np.arange(len(labels))
    width = 0.35

    plt.figure(figsize=(12, 6))
    plt.bar(x - width/2, pre_vals, width, label='Pre-Test', color='#ff9999', edgecolor='grey')
    plt.bar(x + width/2, post_vals, width, label='Post-Test', color='#99ff99', edgecolor='grey')

    plt.ylabel('Jumlah Event Unik')
    plt.title('Perbandingan Deteksi IDS (Event-Based Analysis)')
    plt.xticks(x, short_labels, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Label angka
    for i in range(len(x)):
        plt.text(x[i] - width/2, pre_vals[i], str(pre_vals[i]), ha='center', va='bottom', fontsize=9)
        plt.text(x[i] + width/2, post_vals[i], str(post_vals[i]), ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(output_filename, dpi=300)
    print(f"[SUKSES] Grafik tersimpan.")

def calculate_metrics_event_based(tp_events, fp_events, total_real_events):
    # (Logika perhitungan tetap sama seperti script awal)
    tp_events = min(tp_events, total_real_events)
    recall = (tp_events / total_real_events) * 100 if total_real_events > 0 else 0
    precision = (tp_events / (tp_events + fp_events)) * 100 if (tp_events + fp_events) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return round(recall, 2), round(precision, 2), round(f1, 2)

def main():
    # Header tetap dipertahankan
    print("="*70)
    print(" ANALYZER TA: EVENT-BASED METRICS (Complete Edition) ")
    print("="*70)

    # Argument Parser tetap sama
    parser = argparse.ArgumentParser()
    parser.add_argument("--pre", required=True, help="File Pre-Test (eve.json)")
    parser.add_argument("--post", required=True, help="File Post-Test (eve.json)")
    parser.add_argument("--attacker", required=True, help="IP Attacker")
    parser.add_argument("--events_total", type=int, default=210, help="Total Real Events (Default: 210)")
    parser.add_argument("--output", help="Nama file Excel output (Wajib untuk export)")
    args = parser.parse_args()

    df_pre = load_filtered_data(args.pre)
    df_post = load_filtered_data(args.post)

    if df_pre is None or df_post is None: return

    # --- PROSES ANALISIS ---
    print("\n[PROSES] Menganalisis Event Unik...")
    # Sekarang menangkap variable 'details' juga
    tp_pre_counts, tp_pre_details = analyze_events_detailed(df_pre, ATTACK_SCENARIOS, filter_ip=args.attacker)
    tp_post_counts, tp_post_details = analyze_events_detailed(df_post, ATTACK_SCENARIOS, filter_ip=args.attacker)
    
    fp_pre_counts, fp_pre_details = analyze_events_detailed(df_pre, QUIET_ACTIVITIES, exclude_ip=args.attacker)
    fp_post_counts, fp_post_details = analyze_events_detailed(df_post, QUIET_ACTIVITIES, exclude_ip=args.attacker)

    # [FITUR BARU] Generate Grafik
    generate_chart(tp_pre_counts, tp_post_counts)

    # --- OUTPUT TERMINAL (Sesuai format awal) ---
    df_rekap = pd.DataFrame({
        "Skenario": list(ATTACK_SCENARIOS.keys()),
        "Pre-Test (Events)": list(tp_pre_counts.values()),
        "Post-Test (Events)": list(tp_post_counts.values())
    })
    
    print(f"\n=== DETEKSI EVENT SERANGAN (Target: {args.events_total} Events) ===")
    print(df_rekap.to_string(index=False))

    # --- METRIK ---
    total_tp_pre = sum(tp_pre_counts.values())
    total_tp_post = sum(tp_post_counts.values())
    total_fp_pre = sum(fp_pre_counts.values())
    total_fp_post = sum(fp_post_counts.values())

    rec_pre, prec_pre, f1_pre = calculate_metrics_event_based(total_tp_pre, total_fp_pre, args.events_total)
    rec_post, prec_post, f1_post = calculate_metrics_event_based(total_tp_post, total_fp_post, args.events_total)

    df_metrics = pd.DataFrame({
        "Metrik": ["Recall (Akurasi)", "Precision", "F1-Score", "Total TP (Serangan)", "Total FP (Noise)"],
        "Pre-Test": [f"{rec_pre}%", f"{prec_pre}%", f1_pre, total_tp_pre, total_fp_pre],
        "Post-Test": [f"{rec_post}%", f"{prec_post}%", f1_post, total_tp_post, total_fp_post]
    })

    print("\n=== METRIK FINAL ===")
    print(df_metrics.to_string(index=False))

    # --- [FITUR TAMBAHAN] EKSPOR EXCEL LENGKAP ---
    if args.output:
        fname = args.output if args.output.endswith('.xlsx') else args.output + '.xlsx'
        print(f"\n[EKSPOR] Menyimpan Lampiran Lengkap ke: {fname} ...")
        
        try:
            with pd.ExcelWriter(fname, engine='openpyxl') as writer:
                # 1. Ringkasan
                df_metrics.to_excel(writer, sheet_name='Ringkasan Metrik', index=False)
                # 2. Rekap (Data Grafik)
                df_rekap.to_excel(writer, sheet_name='Rekap Deteksi', index=False)
                # 3. Lampiran Bukti Pre-Test
                if not tp_pre_details.empty:
                    tp_pre_details.to_excel(writer, sheet_name='Lampiran - PreTest', index=False)
                else:
                    pd.DataFrame(["Tidak ada deteksi"]).to_excel(writer, sheet_name='Lampiran - PreTest')
                # 4. Lampiran Bukti Post-Test
                if not tp_post_details.empty:
                    tp_post_details.to_excel(writer, sheet_name='Lampiran - PostTest', index=False)
                else:
                    pd.DataFrame(["Tidak ada deteksi"]).to_excel(writer, sheet_name='Lampiran - PostTest')

            print("[SUKSES] File Excel berhasil dibuat.")
        except Exception as e:
            print(f"[ERROR] Gagal menyimpan Excel: {e}")

if __name__ == "__main__":
    main()