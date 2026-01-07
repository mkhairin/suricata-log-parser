import json
import pandas as pd
import os
import argparse
import matplotlib.pyplot as plt

# ==========================================
# KONFIGURASI MAPPING (DATABASE SIGNATURE)
# ==========================================
# Sesuai PDF: Jadwal Daily Test IDS - Skenario Attack
ATTACK_SCENARIOS = {
    "1. Port Scanning (Nmap)": ["Nmap", "SCAN", "nmap"],
    "2. SSH Brute Force (Hydra)": ["SSH", "Brute Force", "hydra"],
    "3. DoS Attack (Hping3)": ["ICMP", "Flood", "DoS", "Hping", "Large ICMP"],
    "4. SQL Injection (Curl)": ["SQL", "Union", "Syntax", "UNION SELECT"],
    "5. XSS (Curl)": ["XSS", "Script", "Cross Site", "alert("],
    "6. Path Traversal (Curl)": ["Traversal", "Directory", "etc/passwd", "../"],
    "7. RCE (Metasploit)": ["Metasploit", "Exploit", "Meterpreter", "reverse_tcp", "handler"]
}

# Sesuai PDF: Jadwal Daily Test IDS - Aktivitas Fase Tenang
QUIET_ACTIVITIES = {
    "1. Download Binary (Wget/Browser)": ["POLICY PE EXE", "DLL Windows", "file download"],
    "2. System Update (Apt/Curl)": ["GNU/Linux APT", "User-Agent", "Suspicious User-Agent", "Debian APT"],
    "3. SSH Login Agresif (Admin)": ["SSH Brute Force"],
    "4. Net Diagnostic (Ping Jumbo)": ["INFO PING", "Large ICMP Packet"],
    "5. FTP Login (Cleartext)": ["FTP Login", "FTP USER"],
    "6. Non-Standard Port (Dev)": ["HTTP on non-standard port", ":8180", ":8080"],
    "7. The Lost User (404 Error)": ["HTTP 404", "WEB_SERVER 404"]
}


def load_filtered_data(file_path):
    """Membaca file JSON log Suricata"""
    if not os.path.exists(file_path):
        return None
    data = []
    try:
        print(f"Sedang membaca file: {file_path} ...")
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get('event_type') == 'alert':
                        flat_entry = {
                            'timestamp': entry.get('timestamp'),
                            'src_ip': entry.get('src_ip'),
                            'dest_ip': entry.get('dest_ip'),
                            'flow_id': entry.get('flow_id', 0),
                            'alert.signature': entry.get('alert', {}).get('signature', 'Unknown'),
                            'alert.category': entry.get('alert', {}).get('category', 'Unknown'),
                            'alert.severity': entry.get('alert', {}).get('severity', 3)
                        }
                        data.append(flat_entry)
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(data)
    except Exception as e:
        print(f"[ERROR] Gagal membaca file: {e}")
        return None


def map_alerts_to_scenarios(df, mapping_dict, filter_ip=None, exclude_ip=None):
    """Mengelompokkan alert ke skenario TP atau FP."""
    if df is None or df.empty:
        return {k: 0 for k in mapping_dict.keys()}

    results = {k: 0 for k in mapping_dict.keys()}

    if filter_ip:
        df = df[df['src_ip'] == filter_ip]
    if exclude_ip:
        df = df[df['src_ip'] != exclude_ip]

    for index, row in df.iterrows():
        sig = str(row['alert.signature'])
        matched = False
        for category, keywords in mapping_dict.items():
            for kw in keywords:
                if kw.lower() in sig.lower():
                    results[category] += 1
                    matched = True
                    break
            if matched:
                break

    return results


def calculate_metrics_v2(tp_count, fp_count, total_attacks_sent):
    """
    Menghitung metrik.
    Total Attacks Sent = 210 (7 Skenario x 10 Ronde x 3 Hari)
    """
    fn = max(0, total_attacks_sent - tp_count)

    recall = (tp_count / (tp_count + fn)) * 100 if (tp_count + fn) > 0 else 0
    precision = (tp_count / (tp_count + fp_count)) * \
        100 if (tp_count + fp_count) > 0 else 0
    f1 = 2 * (precision * recall) / (precision +
                                     recall) if (precision + recall) > 0 else 0

    return round(recall, 2), round(precision, 2), round(f1, 2)


def generate_comparative_chart(tp_pre, tp_post, fp_pre, fp_post, output_file):
    labels = ['True Positive (Deteksi)', 'False Positive (Noise)']
    pre_vals = [sum(tp_pre.values()), sum(fp_pre.values())]
    post_vals = [sum(tp_post.values()), sum(fp_post.values())]

    x = range(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar([p - width/2 for p in x], pre_vals, width,
                    label='PRE-TEST (Default)', color='#e74c3c')
    rects2 = ax.bar([p + width/2 for p in x], post_vals, width,
                    label='POST-TEST (Optimized)', color='#2ecc71')

    ax.set_ylabel('Jumlah Alert')
    ax.set_title('Efektivitas Tuning: Deteksi vs Noise (3 Hari Pengujian)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)

    plt.tight_layout()
    plt.savefig(output_file)
    print(f"\n[GRAFIK] Disimpan ke: {output_file}")


def main():
    print("="*70)
    print(" ANALYZER TA ULTIMATE: 3-DAY CYCLE ANALYSIS ")
    print("="*70)

    # Update Text Bantuan agar sesuai 210 serangan
    desc = "Analisis Log Suricata untuk Eksperimen 3 Hari (Total 210 Serangan per Fase)"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--pre", required=True,
                        help="File Log Pre-Test (eve.json)")
    parser.add_argument("--post", required=True,
                        help="File Log Post-Test (eve.json)")
    parser.add_argument("--attacker", required=True,
                        help="IP Attacker (Kali Linux)")

    # Default diganti ke 210 sesuai perhitungan: 7 skenario * 10 ronde * 3 hari
    parser.add_argument("--attacks_total", type=int, default=210,
                        help="Total serangan dikirim per fase. Default=210 (7x10x3)")

    parser.add_argument("--output", help="Simpan ke Excel")
    parser.add_argument("--plot", help="Simpan Grafik")
    args = parser.parse_args()

    # 1. Load Data
    df_pre = load_filtered_data(args.pre)
    df_post = load_filtered_data(args.post)

    if df_pre is None or df_post is None:
        return

    # 2. Mapping TP & FP
    print("\n[PROSES] Memetakan Log ke Skenario (TP & FP)...")
    tp_pre = map_alerts_to_scenarios(
        df_pre, ATTACK_SCENARIOS, filter_ip=args.attacker)
    tp_post = map_alerts_to_scenarios(
        df_post, ATTACK_SCENARIOS, filter_ip=args.attacker)
    fp_pre = map_alerts_to_scenarios(
        df_pre, QUIET_ACTIVITIES, exclude_ip=args.attacker)
    fp_post = map_alerts_to_scenarios(
        df_post, QUIET_ACTIVITIES, exclude_ip=args.attacker)

    # 3. Tabel TP (Serangan)
    df_tp = pd.DataFrame({
        "Skenario Serangan": list(ATTACK_SCENARIOS.keys()),
        "Pre-Test": list(tp_pre.values()),
        "Post-Test": list(tp_post.values())
    })
    df_tp['Trend'] = df_tp.apply(
        lambda x: "NAIK" if x['Post-Test'] > x['Pre-Test'] else "TURUN/TETAP", axis=1)

    print("\n=== HASIL DETEKSI SERANGAN (TP) - Target 210 Total ===")
    print(df_tp.to_string(index=False))

    # 4. Tabel FP (Noise)
    df_fp = pd.DataFrame({
        "Aktivitas Normal": list(QUIET_ACTIVITIES.keys()),
        "Pre-Test (Noise)": list(fp_pre.values()),
        "Post-Test (Noise)": list(fp_post.values())
    })
    df_fp['Status'] = df_fp.apply(
        lambda x: "OPTIMAL" if x['Post-Test (Noise)'] < x['Pre-Test (Noise)'] else "BELUM", axis=1)

    print("\n=== HASIL REDUKSI NOISE (FP) ===")
    print(df_fp.to_string(index=False))

    # 5. Metrik Akhir (Menggunakan pembagi 210)
    recall_pre, prec_pre, f1_pre = calculate_metrics_v2(
        sum(tp_pre.values()), sum(fp_pre.values()), args.attacks_total)
    recall_post, prec_post, f1_post = calculate_metrics_v2(
        sum(tp_post.values()), sum(fp_post.values()), args.attacks_total)

    print("\n=== PERBANDINGAN METRIK (BAB IV) ===")
    print(f"       | Recall (Akurasi) | Precision (Anti-Noise) | F1-Score")
    print(
        f"PRE    | {recall_pre}%           | {prec_pre}%                 | {f1_pre}")
    print(
        f"POST   | {recall_post}%           | {prec_post}%                 | {f1_post}")

    # 6. Simpan Excel
    if args.output:
        try:
            with pd.ExcelWriter(args.output, engine='openpyxl') as writer:
                df_tp.to_excel(writer, sheet_name='Analisis TP', index=False)
                df_fp.to_excel(writer, sheet_name='Analisis FP', index=False)
                pd.DataFrame([{
                    "Fase": "Pre-Test", "Total Serangan": args.attacks_total, "Recall": recall_pre, "Precision": prec_pre
                }, {
                    "Fase": "Post-Test", "Total Serangan": args.attacks_total, "Recall": recall_post, "Precision": prec_post
                }]).to_excel(writer, sheet_name='Metrik', index=False)
            print(f"\n[EXCEL] Disimpan: {args.output}")
        except Exception as e:
            print(f"[ERROR] Gagal simpan Excel: {e}")

    if args.plot:
        generate_comparative_chart(tp_pre, tp_post, fp_pre, fp_post, args.plot)


if __name__ == "__main__":
    main()
