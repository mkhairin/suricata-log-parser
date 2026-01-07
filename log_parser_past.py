import json
import pandas as pd
import os
import argparse

def process_suricata(file_path, output_excel, show_table, show_stats):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        # Membaca data primer sesuai Bab 3.5 [cite: 349]
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        
        df = pd.json_normalize(logs)

        # 1. FITUR EKSPOR EXCEL (Seluruh Data)
        if output_excel:
            cols = ['timestamp', 'event_type', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'alert.signature', 'alert.category']
            available_cols = [c for c in cols if c in df.columns]
            df[available_cols].to_excel(output_excel, index=False, engine='openpyxl')
            print(f"[OK] Seluruh data berhasil diekspor ke: {output_excel}")

        # 2. TAMPILKAN TABEL LOG (Mode Independen)
        if show_table:
            cols = ['timestamp', 'event_type', 'src_ip', 'dest_ip', 'proto', 'alert.signature']
            available_cols = [c for c in cols if c in df.columns]
            
            pd.set_option('display.max_rows', None)
            pd.set_option('display.width', 1000)
            
            print("\n" + "="*60)
            print("TABEL LOG SURICATA (SELURUH TRAFIK)")
            print("="*60)
            print(df[available_cols].to_string(index=False))

        # 3. TAMPILKAN STATISTIK GLOBAL (Tanpa Filter IP)
        if show_stats:
            print("\n" + "="*60)
            print("RINGKASAN STATISTIK GLOBAL (SEMUA IP)")
            print("="*60)
            
            # Menghitung total log keseluruhan [cite: 282]
            print(f"Total Seluruh Baris Log : {len(df)}")
            
            # Statistik per jenis event (Aktivitas Jaringan) 
            if 'event_type' in df.columns:
                print("\n[Total Per Jenis Event]")
                print(df['event_type'].value_counts().to_string())
            
            # Statistik per Signature (Penting untuk deteksi FP/TP) [cite: 81]
            if 'alert.signature' in df.columns:
                print("\n[Total Per Signature Alert - Semua Sumber]")
                print(df['alert.signature'].value_counts().to_string())
            
        if not show_table and not show_stats:
            print("\n[Selesai] Gunakan argumen -t untuk tabel atau -s untuk statistik.")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Global Suricata Analyzer - TA Khairin")
    parser.add_argument("-f", "--file", required=True, help="Input file eve.json")
    parser.add_argument("-o", "--output", help="Simpan ke Excel")
    parser.add_argument("-t", "--table", action="store_true", help="Tampilkan tabel log saja")
    parser.add_argument("-s", "--stats", action="store_true", help="Tampilkan statistik global saja")
    
    args = parser.parse_args()
    process_suricata(args.file, args.output, args.table, args.stats)