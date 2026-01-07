import json
import pandas as pd
import os
import argparse

def ensure_xlsx_extension(filename):
    """Fungsi bantu untuk memastikan file berakhiran .xlsx"""
    if not filename.endswith('.xlsx'):
        print(f"[INFO] Mengoreksi ekstensi file '{filename}' menjadi '{filename}.xlsx'")
        return filename + '.xlsx'
    return filename

def process_suricata(file_path, output_excel, full_excel, show_table, show_stats, show_web):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        print(f"Sedang membaca file: {file_path}...")
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        
        df = pd.json_normalize(logs)

        # 1. EKSPOR LOG PENTING
        if output_excel:
            output_excel = ensure_xlsx_extension(output_excel)
            cols = ['timestamp', 'event_type', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'alert.signature', 'alert.category']
            available_cols = [c for c in cols if c in df.columns]
            
            df[available_cols].to_excel(output_excel, index=False, engine='openpyxl')
            print(f"[OK] Log PENTING berhasil diekspor ke: {output_excel}")

        # 2. EKSPOR SEMUA LOG (FULL DUMP)
        if full_excel:
            full_excel = ensure_xlsx_extension(full_excel)
            
            # PERBAIKAN: Menggunakan .map() bukan .applymap() untuk Pandas terbaru
            # Mengubah list/dict menjadi string agar bisa masuk sel Excel
            df_all = df.map(lambda x: str(x) if isinstance(x, (list, dict)) else x)
            
            df_all.to_excel(full_excel, index=False, engine='openpyxl')
            print(f"[OK] SELURUH Log (Full Dump) berhasil diekspor ke: {full_excel}")

        # 3. TAMPILKAN TABEL
        if show_table:
            cols = ['timestamp', 'event_type', 'src_ip', 'dest_ip', 'proto', 'alert.signature']
            available_cols = [c for c in cols if c in df.columns]
            pd.set_option('display.max_rows', None)
            pd.set_option('display.width', 1000)
            print("\n" + "="*60)
            print("TABEL LOG SURICATA")
            print("="*60)
            print(df[available_cols].to_string(index=False))

        # 4. STATISTIK GLOBAL
        if show_stats:
            print("\n" + "="*60)
            print("RINGKASAN STATISTIK")
            print("="*60)
            print(f"Total Baris Log : {len(df)}")
            if 'event_type' in df.columns:
                print("\n[Total Per Jenis Event]")
                print(df['event_type'].value_counts().to_string())
            if 'alert.signature' in df.columns:
                print("\n[Total Per Signature Alert]")
                print(df['alert.signature'].value_counts().to_string())

        # 5. PAYLOAD WEB
        if show_web:
            print("\n" + "="*60)
            print("DETAIL PAYLOAD WEB (HTTP)")
            print("="*60)
            web_cols = ['timestamp', 'src_ip', 'dest_ip', 'http.hostname', 'http.url', 'http.http_method']
            available_web = [c for c in web_cols if c in df.columns]
            
            if 'http.url' in df.columns:
                df_web = df[df['event_type'] == 'alert'].dropna(subset=['http.url'])
                if not df_web.empty:
                    print(df_web[available_web].to_string(index=False))
                else:
                    print("[INFO] Tidak ditemukan data HTTP pada alert.")
            else:
                print("[INFO] Kolom http.url tidak ditemukan dalam log.")

        if not any([output_excel, full_excel, show_table, show_stats, show_web]):
            print("\n[Selesai] Gunakan argumen -o, -d, -t, -s, atau -w.")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool Parser Log Suricata")
    parser.add_argument("-f", "--file", required=True, help="Input file eve.json")
    parser.add_argument("-o", "--output", help="Simpan log PENTING ke Excel")
    parser.add_argument("-d", "--dump", help="Simpan SEMUA log ke Excel")
    parser.add_argument("-t", "--table", action="store_true", help="Tampilkan tabel")
    parser.add_argument("-s", "--stats", action="store_true", help="Tampilkan statistik")
    parser.add_argument("-w", "--web", action="store_true", help="Tampilkan payload web")
    
    args = parser.parse_args()
    process_suricata(args.file, args.output, args.dump, args.table, args.stats, args.web)