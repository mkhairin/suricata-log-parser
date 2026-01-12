import json
import pandas as pd
import os
import argparse

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

def main():
    # Kustomisasi teks bantuan (Help) [cite: 101, 217]
    description_text = """
======================================================================
TOOL ANALISIS METRIK IDS SURICATA - TUGAS AKHIR MUHAMMAD KHAIRIN
======================================================================
Skrip ini digunakan untuk membandingkan hasil deteksi Suricata antara 
tahap Pre-Test (Default Rules) dan Post-Test (Custom Rules). 
Berdasarkan metodologi penelitian eksperimental Pre-Post Design.
    """
    
    usage_example = """
Contoh Penggunaan:
  # Jika total serangan 70 kali dan IP Kali Linux adalah 192.168.100.10:
  python analyzer_ta_suricata.py --pre eve_default.json --post eve_tuned.json --attacks 70 --ip 192.168.100.10
    """

    parser = argparse.ArgumentParser(
        description=description_text,
        epilog=usage_example,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--pre", required=True, help="Path ke file eve.json hasil fase PRE-TEST [cite: 182]")
    parser.add_argument("--post", required=True, help="Path ke file eve.json hasil fase POST-TEST [cite: 186]")
    parser.add_argument("--attacks", type=int, required=True, help="Total paket serangan yang dikirim (misal: 7 skenario x 10 ulangan = 70) [cite: 79, 321]")
    parser.add_argument("--ip", required=True, help="Alamat IP Attacker/Kali Linux untuk identifikasi True Positive [cite: 274, 309]")
    
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
    
    print("\n" + "-"*30)
    print(f"KESIMPULAN TUNING:")
    print(f"Peningkatan Recall   : {round(m_post[3] - m_pre[3], 2)}%")
    print(f"Penurunan False Pos  : {m_pre[1] - m_post[1]} alert")
    print("-"*30)

if __name__ == "__main__":
    main()