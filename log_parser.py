import json
import pandas as pd
import os
import argparse

def extract_suricata_logs(file_path):
    # Memastikan file ada sebelum diproses [cite: 242, 283]
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        print(f"Sedang memproses file: {file_path}...")
        
        # Membaca file baris demi baris (EVE JSON format) [cite: 349]
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        
        # Mengonversi list JSON menjadi DataFrame Pandas [cite: 349, 377]
        df = pd.json_normalize(logs)

        # Daftar kolom utama untuk analisis sesuai Bab 3.5 Proposal [cite: 350, 356]
        columns_to_show = [
            'timestamp', 
            'event_type', 
            'src_ip', 
            'src_port', 
            'dest_ip', 
            'dest_port', 
            'proto', 
            'alert.signature', 
            'alert.category'
        ]

        # Filter hanya kolom yang benar-benar ada di dalam file log
        available_columns = [col for col in columns_to_show if col in df.columns]
        
        # Pengaturan tampilan tabel agar rapi dan tidak terpotong
        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', 1000)
        pd.set_option('display.colheader_justify', 'left')

        # Menampilkan hasil ekstraksi
        print("\n" + "="*50)
        print("HASIL EKSTRAKSI LOG SURICATA")
        print("="*50)
        print(df[available_columns].to_string(index=False))

    except Exception as e:
        print(f"Terjadi kesalahan saat memproses log: {e}")

if __name__ == "__main__":
    # Inisialisasi parser argumen [cite: 399]
    parser = argparse.ArgumentParser(description="Tool Ekstraksi Log Suricata untuk Penelitian TA")
    
    # Menambahkan argumen -f atau --file
    parser.add_argument("-f", "--file", required=True, help="Path menuju file log (contoh: eve.json)")
    
    args = parser.parse_args()
    
    # Menjalankan fungsi dengan path file dari command line
    extract_suricata_logs(args.file)