import json
import pandas as pd
import os
import argparse
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


def load_filtered_data(file_path):
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
                            'src_ip': entry.get('src_ip'),
                            # Flow ID sangat penting untuk menghitung "Event" unik
                            'flow_id': entry.get('flow_id', entry.get('timestamp')),
                            'alert.signature': entry.get('alert', {}).get('signature', 'Unknown')
                        }
                        data.append(flat_entry)
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(data)
    except Exception:
        return None


def map_events_unique(df, mapping_dict, filter_ip=None, exclude_ip=None):
    """
    LOGIKA BARU: Menghitung Unique Flow ID per Kategori.
    Agar 50 alert dari 1 serangan dihitung sebagai 1 Deteksi Event.
    """
    if df is None or df.empty:
        return {k: 0 for k in mapping_dict.keys()}

    # Gunakan SET untuk menyimpan Flow ID unik (agar tidak duplikat)
    unique_events = {k: set() for k in mapping_dict.keys()}

    if filter_ip:
        df = df[df['src_ip'] == filter_ip]
    if exclude_ip:
        df = df[df['src_ip'] != exclude_ip]

    for index, row in df.iterrows():
        sig = str(row['alert.signature'])
        flow = row['flow_id']  # ID unik sesi serangan

        matched = False
        for category, keywords in mapping_dict.items():
            for kw in keywords:
                if kw.lower() in sig.lower():
                    # Simpan Flow ID, bukan sekadar counter +1
                    unique_events[category].add(flow)
                    matched = True
                    break
            if matched:
                break

    # Kembalikan jumlah Flow ID unik (Jumlah Event Terdeteksi)
    return {k: len(v) for k, v in unique_events.items()}


def generate_comparison_chart(pre_data, post_data, output_img="grafik_perbandingan.png"):
    """
    Fungsi Baru: Membuat Grafik Batang Pre vs Post
    """
    print(f"\n[GRAFIK] Sedang membuat visualisasi data ke '{output_img}'...")

    labels = list(pre_data.keys())
    # Memperpendek label agar grafik rapi (mengambil teks setelah angka "1. ")
    short_labels = [label.split(
        ". ")[1] if ". " in label else label for label in labels]

    pre_vals = list(pre_data.values())
    post_vals = list(post_data.values())

    x = np.arange(len(labels))  # Lokasi label
    width = 0.35  # Lebar batang

    fig, ax = plt.subplots(figsize=(12, 6))
    rects1 = ax.bar(x - width/2, pre_vals, width,
                    label='Pre-Test (Default)', color='#ff9999', edgecolor='grey')
    rects2 = ax.bar(x + width/2, post_vals, width,
                    label='Post-Test (Optimized)', color='#99ff99', edgecolor='grey')

    # Tambahkan teks label, judul, dan kustomisasi sumbu
    ax.set_ylabel('Jumlah Event Unik Terdeteksi')
    ax.set_title('Perbandingan Efektivitas Deteksi IDS (Event-Based Analysis)')
    ax.set_xticks(x)
    ax.set_xticklabels(short_labels, rotation=45, ha='right')
    ax.legend()

    # Fungsi untuk menaruh angka di atas batang
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate('{}'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)

    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.savefig(output_img, dpi=300)  # Simpan resolusi tinggi
    print(f"[SUKSES] Grafik tersimpan: {output_img}")


def calculate_metrics_event_based(tp_events, fp_events, total_real_events):
    """
    Menghitung Recall berdasarkan Event (bukan raw log).
    TP Events = Jumlah serangan unik yang terdeteksi
    Total Real Events = 210
    """
    # Cap TP di angka total (jika ada fragmentasi flow berlebih)
    tp_events = min(tp_events, total_real_events)

    fn = total_real_events - tp_events

    recall = (tp_events / total_real_events) * \
        100 if total_real_events > 0 else 0

    # Untuk Precision, FP biasanya tetap dihitung volume (noise),
    # tapi agar apple-to-apple, kita pakai FP Events (Unique Noise Flows) juga.
    precision = (tp_events / (tp_events + fp_events)) * \
        100 if (tp_events + fp_events) > 0 else 0
    f1 = 2 * (precision * recall) / (precision +
                                     recall) if (precision + recall) > 0 else 0

    return round(recall, 2), round(precision, 2), round(f1, 2)


def main():
    print("="*70)
    print(" ANALYZER TA: EVENT-BASED METRICS (FLOW ID) ")
    print("="*70)

    parser = argparse.ArgumentParser()
    parser.add_argument("--pre", required=True, help="File Pre-Test")
    parser.add_argument("--post", required=True, help="File Post-Test")
    parser.add_argument("--attacker", required=True, help="IP Attacker")
    # Default 210 Events (Bukan Log!)
    parser.add_argument("--events_total", type=int, default=210,
                        help="Total Real Events (Default: 210)")
    parser.add_argument("--output", help="Simpan Excel")
    args = parser.parse_args()

    df_pre = load_filtered_data(args.pre)
    df_post = load_filtered_data(args.post)

    if df_pre is None or df_post is None:
        return

    # Mapping menggunakan LOGIKA UNIK (Flow ID)
    print("\n[PROSES] Menghitung Unique Events (Flow ID)...")
    tp_pre = map_events_unique(
        df_pre, ATTACK_SCENARIOS, filter_ip=args.attacker)
    tp_post = map_events_unique(
        df_post, ATTACK_SCENARIOS, filter_ip=args.attacker)
    fp_pre = map_events_unique(
        df_pre, QUIET_ACTIVITIES, exclude_ip=args.attacker)
    fp_post = map_events_unique(
        df_post, QUIET_ACTIVITIES, exclude_ip=args.attacker)

    # Tabel Output
    df_tp = pd.DataFrame({
        "Skenario": list(ATTACK_SCENARIOS.keys()),
        "Pre-Test (Events Detected)": list(tp_pre.values()),
        "Post-Test (Events Detected)": list(tp_post.values())
    })

    print(
        f"\n=== DETEKSI EVENT SERANGAN (Target: {args.events_total} Events) ===")
    print(df_tp.to_string(index=False))

    # 2. GENERATE GRAFIK (FITUR BARU)
    # Grafik akan otomatis dibuat dengan nama file ini
    generate_comparison_chart(
        tp_pre, tp_post, output_img="grafik_perbandingan_eve.png")

    # Metrik
    total_tp_pre = sum(tp_pre.values())
    total_tp_post = sum(tp_post.values())
    total_fp_pre = sum(fp_pre.values())
    total_fp_post = sum(fp_post.values())

    rec_pre, prec_pre, f1_pre = calculate_metrics_event_based(
        total_tp_pre, total_fp_pre, args.events_total)
    rec_post, prec_post, f1_post = calculate_metrics_event_based(
        total_tp_post, total_fp_post, args.events_total)

    print("\n=== METRIK FINAL (EVENT BASED) ===")
    print(f"       | Recall (Akurasi) | Precision | F1-Score")
    print(f"PRE    | {rec_pre}%           | {prec_pre}%      | {f1_pre}")
    print(f"POST   | {rec_post}%           | {prec_post}%      | {f1_post}")

    if args.output:
        df_tp.to_excel(args.output, index=False)
        print(f"\n[OK] Disimpan ke {args.output}")


if __name__ == "__main__":
    main()
