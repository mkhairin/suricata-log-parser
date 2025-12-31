import json
import pandas as pd
import os
import argparse
import matplotlib.pyplot as plt

def load_data(file_path):
    if not os.path.exists(file_path):
        return None
    logs = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        return pd.json_normalize(logs)
    except Exception:
        return None

def calculate_metrics(df, attacker_ip, total_attacks):
    if df is None or 'alert.signature' not in df.columns:
        return 0, 0, 0, 0, 0, 0

    # TP: Serangan dari IP Penyerang yang terdeteksi [cite: 210, 394]
    tp = len(df[(df['event_type'] == 'alert') & (df['src_ip'] == attacker_ip)])
    
    # FP: Alert yang muncul BUKAN dari IP Penyerang (Peringatan Palsu) [cite: 210, 396]
    fp = len(df[(df['event_type'] == 'alert') & (df['src_ip'] != attacker_ip)])
    
    # FN: Serangan yang dikirim tapi tidak ada di log [cite: 212, 395]
    fn = max(0, total_attacks - tp)

    # Rumus Metrik sesuai Bab 3.5 [cite: 383, 387, 393]
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return tp, fp, fn, round(recall, 2), round(precision, 2), round(f1, 2)

def generate_graph(m_pre, m_post, output_name):
    # Parameter metrik untuk grafik [cite: 252-265]
    labels = ['Recall (%)', 'Precision (%)', 'F1-Score']
    pre_values = [m_pre[3], m_pre[4], m_pre[5]]
    post_values = [m_post[3], m_post[4], m_post[5]]

    x = range(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Membuat batang Pre-Test (Merah) dan Post-Test (Hijau) [cite: 182, 186]
    bar1 = ax.bar([p - width/2 for p in x], pre_values, width, label='PRE-TEST (Default)', color='#e74c3c')
    bar2 = ax.bar([p + width/2 for p in x], post_values, width, label='POST-TEST (Optimized)', color='#2ecc71')

    # Atur Label dan Judul
    ax.set_ylabel('Persentase (%)')
    ax.set_title('Perbandingan Performa IDS Suricata: Pre-Test vs Post-Test')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 110)
    ax.legend()

    # Tambahkan angka di atas setiap batang
    ax.bar_label(bar1, padding=3)
    ax.bar_label(bar2, padding=3)

    fig.tight_layout()
    plt.savefig(output_name)
    print(f"\n[OK] Grafik berhasil disimpan: {output_name}")

def main():
    description_text = """
======================================================================
TOOL ANALISIS METRIK & VISUALISASI IDS SURICATA - MUHAMMAD KHAIRIN
======================================================================
    """
    
    usage_example = """
Contoh Penggunaan:
  python analyzer_ta_suricata.py --pre pre.json --post post.json --attacks 70 --ip 192.168.100.10 --plot hasil_grafik.png
    """

    parser = argparse.ArgumentParser(
        description=description_text,
        epilog=usage_example,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--pre", required=True, help="Path ke file eve.json PRE-TEST [cite: 182]")
    parser.add_argument("--post", required=True, help="Path ke file eve.json POST-TEST [cite: 186]")
    parser.add_argument("--attacks", type=int, required=True, help="Total paket serangan yang dikirim [cite: 79, 321]")
    parser.add_argument("--ip", required=True, help="IP Attacker/Kali Linux [cite: 274, 309]")
    parser.add_argument("--plot", help="Nama file untuk menyimpan grafik (contoh: grafik.png)")
    
    args = parser.parse_args()

    df_pre = load_data(args.pre)
    df_post = load_data(args.post)

    if df_pre is None or df_post is None:
        print("[Error] Salah satu file log tidak ditemukan atau rusak.")
        return

    m_pre = calculate_metrics(df_pre, args.ip, args.attacks)
    m_post = calculate_metrics(df_post, args.ip, args.attacks)

    data = {
        "Parameter/Metrik": ["TP", "FP", "FN", "Recall (%)", "Precision (%)", "F1-Score"],
        "PRE-TEST": m_pre,
        "POST-TEST": m_post
    }
    
    print("\n" + "="*65)
    print("TABEL HASIL ANALISIS DATA KOMPARATIF")
    print("="*65)
    print(pd.DataFrame(data).to_string(index=False))
    
    # Tampilkan Kesimpulan Singkat
    print("\n" + "-"*30)
    print(f"KESIMPULAN TUNING:")
    print(f"Peningkatan Recall   : {round(m_post[3] - m_pre[3], 2)}%")
    print(f"Penurunan False Pos  : {m_pre[1] - m_post[1]} alert")
    print("-"*30)

    # Menjalankan Fitur No. 3 (Grafik) jika argumen --plot diberikan
    if args.plot:
        generate_graph(m_pre, m_post, args.plot)

if __name__ == "__main__":
    main()