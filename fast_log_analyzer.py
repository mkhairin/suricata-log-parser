import pandas as pd
import os
import argparse
import re
import matplotlib.pyplot as plt
import numpy as np

# ==========================================
# KONFIGURASI MAPPING (DATABASE SIGNATURE)
# ==========================================
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


def parse_fast_log_line(line):
    """
    Regex khusus untuk membaca fast.log Suricata Legacy
    """
    pattern = r'(?P<timestamp>^[\d\/\-\:\.]+)\s+\[\*\*\]\s+\[(?P<sid>[\d\:]+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+(?:\[Classification:\s+(?P<classification>.*?)\]\s+)?(?:\[Priority:\s+(?P<priority>\d+)\]\s+)?\{(?P<protocol>\w+)\}\s+(?P<src_ip>\S+):(?P<src_port>\d+)\s+->\s+(?P<dest_ip>\S+):(?P<dest_port>\d+)'
    match = re.search(pattern, line)
    if match:
        return match.groupdict()
    return None


def load_data(file_path):
    """
    Membaca fast.log dan membuat 'Pseudo Flow ID' karena fast.log tidak punya flow_id asli.
    """
    if not os.path.exists(file_path):
        return pd.DataFrame()

    data = []
    print(f"Sedang membaca file: {file_path} ...")

    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_fast_log_line(line.strip())
            if parsed:
                # [PENTING] Membuat PSEUDO FLOW ID
                # Format: SRC_IP:PORT -> DST_IP:PORT
                # Ini menggantikan flow_id dari JSON agar logika Event-Based tetap jalan.
                pseudo_flow_id = f"{parsed['src_ip']}:{parsed['src_port']}->{parsed['dest_ip']}:{parsed['dest_port']}"

                data.append({
                    'timestamp': parsed['timestamp'],
                    'src_ip': parsed['src_ip'],
                    'dest_ip': parsed['dest_ip'],
                    # Di fast.log, message adalah signature
                    'alert.signature': parsed['message'],
                    'flow_id': pseudo_flow_id
                })

    return pd.DataFrame(data)


def map_events_unique(df, mapping_dict, filter_ip=None, exclude_ip=None):
    """
    Logika Event-Based Analysis (Sama seperti versi JSON)
    Mengembalikan: (Counts Dict, Details DataFrame)
    """
    counts = {k: 0 for k in mapping_dict.keys()}
    unique_tracker = {k: set() for k in mapping_dict.keys()}
    details_list = []

    if df.empty:
        return counts, pd.DataFrame()

    # Filter IP
    if filter_ip:
        df = df[df['src_ip'] == filter_ip]
    if exclude_ip:
        df = df[df['src_ip'] != exclude_ip]

    for index, row in df.iterrows():
        sig = str(row['alert.signature'])
        flow = row['flow_id']  # Ini sekarang menggunakan Pseudo Flow ID

        matched = False
        for category, keywords in mapping_dict.items():
            for kw in keywords:
                if kw.lower() in sig.lower():
                    # Cek Flow ID (Logika Event-Based)
                    if flow not in unique_tracker[category]:
                        unique_tracker[category].add(flow)

                        # Simpan detail untuk Excel Lampiran
                        details_list.append({
                            "Waktu": row['timestamp'],
                            "Skenario": category,
                            "Signature": row['alert.signature'],
                            "Source": row['src_ip'],
                            "Target": row['dest_ip'],
                            "Pseudo Flow ID": flow
                        })
                    matched = True
                    break
            if matched:
                break

    # Update counts
    for k, v in unique_tracker.items():
        counts[k] = len(v)

    df_details = pd.DataFrame(details_list)
    if not df_details.empty:
        df_details = df_details.sort_values(by=["Skenario", "Waktu"])

    return counts, df_details


def generate_chart(pre_counts, post_counts, output_filename="grafik_perbandingan.png"):
    """
    Membuat Grafik Batang Perbandingan Pre vs Post
    """
    print(f"\n[GRAFIK] Sedang membuat grafik visual: {output_filename} ...")

    labels = list(pre_counts.keys())
    # Memperpendek label agar tidak berantakan di grafik (opsional)
    short_labels = [l.split(". ")[1].split(" (")[0] for l in labels]

    pre_values = list(pre_counts.values())
    post_values = list(post_counts.values())

    x = np.arange(len(labels))
    width = 0.35

    plt.figure(figsize=(10, 6))
    plt.bar(x - width/2, pre_values, width, label='Pre-Test (Default)',
            color='#ff9999', edgecolor='black')
    plt.bar(x + width/2, post_values, width,
            label='Post-Test (Optimized)', color='#99ff99', edgecolor='black')

    plt.ylabel('Jumlah Event Unik Terdeteksi')
    plt.title('Perbandingan Efektivitas Deteksi IDS (Event-Based)')
    plt.xticks(x, short_labels, rotation=45, ha='right')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Menambahkan label angka di atas batang
    for i in range(len(x)):
        plt.text(x[i] - width/2, pre_values[i] + 0.1,
                 str(pre_values[i]), ha='center', va='bottom', fontsize=9)
        plt.text(x[i] + width/2, post_values[i] + 0.1,
                 str(post_values[i]), ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(output_filename, dpi=300)  # Simpan High Resolution
    print(f"[SUKSES] Grafik tersimpan sebagai '{output_filename}'")


def calculate_metrics_event_based(tp, fp, total_real):
    """Hitung Recall, Precision, F1"""
    tp = min(tp, total_real)
    recall = (tp / total_real) * 100 if total_real > 0 else 0
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
    f1 = 2 * (precision * recall) / (precision +
                                     recall) if (precision + recall) > 0 else 0
    return round(recall, 2), round(precision, 2), round(f1, 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Suricata FAST.LOG Analyzer (Event-Based)")
    parser.add_argument("--pre", required=True,
                        help="File Pre-Test (fast.log)")
    parser.add_argument("--post", required=True,
                        help="File Post-Test (fast.log)")
    parser.add_argument("--attacker", required=True, help="IP Attacker")
    parser.add_argument("--events_total", type=int,
                        default=210, help="Total Real Events")
    parser.add_argument(
        "--output", help="Nama file Excel untuk hasil analisis & lampiran")

    args = parser.parse_args()

    # 1. Load Data
    df_pre = load_data(args.pre)
    df_post = load_data(args.post)

    # 2. Analisis Event Unik
    print("\n[ANALISIS] Menghitung Event Unik (Pseudo Flow-Based)...")
    tp_pre, details_tp_pre = map_events_unique(
        df_pre, ATTACK_SCENARIOS, filter_ip=args.attacker)
    tp_post, details_tp_post = map_events_unique(
        df_post, ATTACK_SCENARIOS, filter_ip=args.attacker)

    fp_pre, details_fp_pre = map_events_unique(
        df_pre, QUIET_ACTIVITIES, exclude_ip=args.attacker)
    fp_post, details_fp_post = map_events_unique(
        df_post, QUIET_ACTIVITIES, exclude_ip=args.attacker)

    # 3. Generate Grafik (FITUR BARU)
    generate_chart(tp_pre, tp_post)

    # 4. Output Tabel Terminal
    df_rekap = pd.DataFrame({
        "Skenario": list(ATTACK_SCENARIOS.keys()),
        "Pre-Test (Events)": list(tp_pre.values()),
        "Post-Test (Events)": list(tp_post.values())
    })

    print(
        f"\n=== DETEKSI EVENT SERANGAN (Target: {args.events_total} Events) ===")
    print(df_rekap.to_string(index=False))

    # 5. Hitung Metrik
    total_tp_pre = sum(tp_pre.values())
    total_tp_post = sum(tp_post.values())
    total_fp_pre = sum(fp_pre.values())
    total_fp_post = sum(fp_post.values())

    rec_pre, prec_pre, f1_pre = calculate_metrics_event_based(
        total_tp_pre, total_fp_pre, args.events_total)
    rec_post, prec_post, f1_post = calculate_metrics_event_based(
        total_tp_post, total_fp_post, args.events_total)

    df_metrics = pd.DataFrame({
        "Metrik": ["Recall (Akurasi)", "Precision", "F1-Score", "Total Detected (TP)", "Total Noise (FP)"],
        "Pre-Test": [f"{rec_pre}%", f"{prec_pre}%", f1_pre, total_tp_pre, total_fp_pre],
        "Post-Test": [f"{rec_post}%", f"{prec_post}%", f1_post, total_tp_post, total_fp_post]
    })

    print("\n=== METRIK PERFORMA ===")
    print(df_metrics.to_string(index=False))

    # 6. Ekspor Excel
    if args.output:
        fname = args.output if args.output.endswith(
            '.xlsx') else args.output + '.xlsx'
        print(f"\n[EKSPOR] Menyimpan Lampiran ke Excel: {fname} ...")

        try:
            with pd.ExcelWriter(fname, engine='openpyxl') as writer:
                df_metrics.to_excel(
                    writer, sheet_name='Ringkasan Metrik', index=False)
                df_rekap.to_excel(
                    writer, sheet_name='Rekap Deteksi', index=False)

                if not details_tp_pre.empty:
                    details_tp_pre.to_excel(
                        writer, sheet_name='Lampiran - PreTest', index=False)
                else:
                    pd.DataFrame(["Tidak ada deteksi"]).to_excel(
                        writer, sheet_name='Lampiran - PreTest')

                if not details_tp_post.empty:
                    details_tp_post.to_excel(
                        writer, sheet_name='Lampiran - PostTest', index=False)
                else:
                    pd.DataFrame(["Tidak ada deteksi"]).to_excel(
                        writer, sheet_name='Lampiran - PostTest')

            print("[SUKSES] File Excel berhasil dibuat.")
        except Exception as e:
            print(f"[ERROR] Gagal menyimpan Excel: {e}")
