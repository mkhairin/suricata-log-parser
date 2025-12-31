import json
import pandas as pd
import os

def extract_suricata_logs(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        # Membaca file eve.json per baris
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))
        
        # Meratakan (flatten) JSON yang bersarang (seperti bagian 'alert') menjadi kolom tabel
        df = pd.json_normalize(logs)

        # Daftar kolom yang ingin ditampilkan sesuai permintaanmu
        # Kita menggunakan .get() atau pengecekan kolom agar skrip tidak error jika kolom tertentu tidak ada
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

        # Memastikan hanya kolom yang tersedia di log yang akan ditampilkan
        available_columns = [col for col in columns_to_show if col in df.columns]
        
        # Menampilkan tabel dengan semua baris (all information)
        # pd.set_option digunakan agar tampilan di terminal tidak terpotong
        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', 1000)
        pd.set_option('display.colheader_justify', 'left')

        print(df[available_columns].to_string(index=False))

    except Exception as e:
        print(f"Terjadi kesalahan saat memproses log: {e}")

# Nama file log sesuai draf proposal (Bab 3.5)
log_file = "eve.json" 
extract_suricata_logs(log_file)