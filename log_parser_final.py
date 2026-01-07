import json
import pandas as pd
import os
import argparse

def process_suricata(file_path, output_excel, show_table, show_stats, show_web):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        # Membaca data log Suricata (eve.json)
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        
        # Meratakan JSON agar kolom bersarang (seperti alert dan http) bisa dibaca
        df = pd.json_normalize(logs)

        # 1. FITUR EKSPOR EXCEL
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

        # 3. TAMPILKAN STATISTIK GLOBAL
        if show_stats:
            print("\n" + "="*60)
            print("RINGKASAN STATISTIK GLOBAL (SEMUA IP)")
            print("="*60)
            print(f"Total Seluruh Baris Log : {len(df)}")
            
            if 'event_type' in df.columns:
                print("\n[Total Per Jenis Event]")
                print(df['event_type'].value_counts().to_string())
            
            if 'alert.signature' in df.columns:
                print("\n[Total Per Signature Alert - Semua Sumber]")
                print(df['alert.signature'].value_counts().to_string())

        # 4. FITUR NO. 4: ANALISIS DETAIL PAYLOAD WEB (HTTP)
        if show_web:
            print("\n" + "="*60)
            print("DETAIL PAYLOAD SERANGAN WEB (HTTP)")
            print("="*60)
            
            # Kolom spesifik metadata HTTP sesuai Bab 2.2.2 proposal
            web_cols = [
                'timestamp', 'src_ip', 'dest_ip', 
                'http.hostname', 'http.url', 'http.http_method', 'http.http_user_agent'
            ]
            
            available_web = [c for c in web_cols if c in df.columns]
            
            # Memfilter hanya event tipe alert yang memiliki data HTTP
            df_web = df[df['event_type'] == 'alert'].dropna(subset=['http.url']) if 'http.url' in df.columns else pd.DataFrame()

            if not df_web.empty:
                print(df_web[available_web].to_string(index=False))
            else:
                print("[INFO] Tidak ditemukan detail payload HTTP (SQLi/XSS/Traversal) dalam log ini.")
            
        if not any([show_table, show_stats, show_web]):
            print("\n[Selesai] Gunakan argumen -t (tabel), -s (stats), atau -w (web).")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Global Suricata Analyzer - TA Khairin")
    parser.add_argument("-f", "--file", required=True, help="Input file eve.json")
    parser.add_argument("-o", "--output", help="Simpan ke Excel (.xlsx)")
    parser.add_argument("-t", "--table", action="store_true", help="Tampilkan tabel log saja")
    parser.add_argument("-s", "--stats", action="store_true", help="Tampilkan statistik global")
    parser.add_argument("-w", "--web", action="store_true", help="Tampilkan detail payload web (Fitur No. 4)")
    
    args = parser.parse_args()
    process_suricata(args.file, args.output, args.table, args.stats, args.web)