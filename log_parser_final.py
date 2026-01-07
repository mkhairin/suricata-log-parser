import json
import pandas as pd
import os
import argparse

def process_suricata(file_path, output_excel, full_excel, show_table, show_stats, show_web):
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

        # 1. FITUR EKSPOR EXCEL (LOG PENTING SAJA)
        # Argumen: -o atau --output
        if output_excel:
            cols = ['timestamp', 'event_type', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'alert.signature', 'alert.category']
            # Hanya ambil kolom yang ada di dataframe
            available_cols = [c for c in cols if c in df.columns]
            
            df[available_cols].to_excel(output_excel, index=False, engine='openpyxl')
            print(f"[OK] Log PENTING berhasil diekspor ke: {output_excel}")

        # 2. FITUR EKSPOR EXCEL (SEMUA DATA/FULL DUMP) [BARU]
        # Argumen: -d atau --dump
        if full_excel:
            # Mengekspor SELURUH dataframe tanpa filter kolom
            # Kami mengonversi kolom yang berisi list/dict menjadi string agar Excel tidak error
            df_all = df.applymap(lambda x: str(x) if isinstance(x, (list, dict)) else x)
            
            df_all.to_excel(full_excel, index=False, engine='openpyxl')
            print(f"[OK] SELURUH Log (Full Dump) berhasil diekspor ke: {full_excel}")

        # 3. TAMPILKAN TABEL LOG (Mode Independen)
        if show_table:
            cols = ['timestamp', 'event_type', 'src_ip', 'dest_ip', 'proto', 'alert.signature']
            available_cols = [c for c in cols if c in df.columns]
            
            pd.set_option('display.max_rows', None)
            pd.set_option('display.width', 1000)
            
            print("\n" + "="*60)
            print("TABEL LOG SURICATA (SELURUH TRAFIK)")
            print("="*60)
            print(df[available_cols].to_string(index=False))

        # 4. TAMPILKAN STATISTIK GLOBAL
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

        # 5. FITUR ANALISIS DETAIL PAYLOAD WEB (HTTP)
        if show_web:
            print("\n" + "="*60)
            print("DETAIL PAYLOAD SERANGAN WEB (HTTP)")
            print("="*60)
            
            web_cols = [
                'timestamp', 'src_ip', 'dest_ip', 
                'http.hostname', 'http.url', 'http.http_method', 'http.http_user_agent'
            ]
            
            available_web = [c for c in web_cols if c in df.columns]
            
            df_web = df[df['event_type'] == 'alert'].dropna(subset=['http.url']) if 'http.url' in df.columns else pd.DataFrame()

            if not df_web.empty:
                print(df_web[available_web].to_string(index=False))
            else:
                print("[INFO] Tidak ditemukan detail payload HTTP (SQLi/XSS/Traversal) dalam log ini.")
            
        if not any([output_excel, full_excel, show_table, show_stats, show_web]):
            print("\n[Selesai] Gunakan argumen -t, -s, -w, -o (penting), atau -d (semua).")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Global Suricata Analyzer - TA Khairin")
    parser.add_argument("-f", "--file", required=True, help="Input file eve.json")
    
    # Argumen Excel 1: Log Penting
    parser.add_argument("-o", "--output", help="Simpan log PENTING saja ke Excel (.xlsx)")
    
    # Argumen Excel 2: Semua Log (Baru)
    parser.add_argument("-d", "--dump", help="Simpan SEMUA elemen log ke Excel (.xlsx)")
    
    parser.add_argument("-t", "--table", action="store_true", help="Tampilkan tabel log saja")
    parser.add_argument("-s", "--stats", action="store_true", help="Tampilkan statistik global")
    parser.add_argument("-w", "--web", action="store_true", help="Tampilkan detail payload web")
    
    args = parser.parse_args()
    process_suricata(args.file, args.output, args.dump, args.table, args.stats, args.web)