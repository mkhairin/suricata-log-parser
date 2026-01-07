import json
import pandas as pd
import os
import argparse


def ensure_xlsx_extension(filename):
    """
    Fitur Safety: Memastikan nama file berakhiran .xlsx
    Jika user salah ketik .xlxs atau lupa ekstensi, otomatis diperbaiki.
    """
    if not filename:
        return None
    if not filename.endswith('.xlsx'):
        # Jika user mengetik ekstensi yang salah (typo)
        if filename.endswith('.xlxs'):
            corrected = filename.replace('.xlxs', '.xlsx')
            print(
                f"[AUTO-FIX] Memperbaiki ekstensi '{filename}' menjadi '{corrected}'")
            return corrected
        # Jika user lupa mengetik ekstensi
        print(f"[AUTO-FIX] Menambahkan ekstensi .xlsx pada '{filename}'")
        return filename + '.xlsx'
    return filename


def process_suricata(file_path, output_excel, full_excel, show_table, show_stats, show_web):
    if not os.path.exists(file_path):
        print(f"[ERROR] File {file_path} tidak ditemukan.")
        return

    logs = []
    try:
        print(f"Sedang membaca file log: {file_path}...")
        with open(file_path, 'r') as f:
            for line in f:
                logs.append(json.loads(line))

        # Normalisasi JSON ke DataFrame Pandas
        df = pd.json_normalize(logs)
        print(f"[INFO] Berhasil memuat {len(df)} baris log.")

        # ---------------------------------------------------------
        # 1. FITUR EKSPOR EXCEL (LOG PENTING / RINGKAS)
        # ---------------------------------------------------------
        if output_excel:
            output_excel = ensure_xlsx_extension(output_excel)

            # [REVISI PENTING] Menambahkan 'flow_id' untuk korelasi event
            cols = [
                'timestamp', 'flow_id', 'event_type',
                'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto',
                'alert.signature', 'alert.category', 'alert.action', 'alert.severity'
            ]

            # Hanya ambil kolom yang benar-benar ada di data
            available_cols = [c for c in cols if c in df.columns]

            print(f"Sedang mengekspor data ringkas ke {output_excel}...")
            df[available_cols].to_excel(
                output_excel, index=False, engine='openpyxl')
            print(f"[SUKSES] File Excel Ringkas tersimpan: {output_excel}")

        # ---------------------------------------------------------
        # 2. FITUR EKSPOR EXCEL (FULL DUMP / SEMUA DATA)
        # ---------------------------------------------------------
        if full_excel:
            full_excel = ensure_xlsx_extension(full_excel)

            print(
                f"Sedang mengekspor SEMUA data ke {full_excel} (ini mungkin memakan waktu)...")

            # [REVISI] Menggunakan .map() menggantikan .applymap() untuk menghindari FutureWarning
            # Mengubah list/dict menjadi string agar Excel tidak error
            df_all = df.map(lambda x: str(
                x) if isinstance(x, (list, dict)) else x)

            df_all.to_excel(full_excel, index=False, engine='openpyxl')
            print(f"[SUKSES] File Excel Full Dump tersimpan: {full_excel}")

        # ---------------------------------------------------------
        # 3. TAMPILKAN TABEL (TERMINAL)
        # ---------------------------------------------------------
        if show_table:
            # Menampilkan flow_id juga di terminal
            cols = ['timestamp', 'flow_id', 'event_type',
                    'src_ip', 'dest_ip', 'alert.signature']
            available_cols = [c for c in cols if c in df.columns]

            pd.set_option('display.max_rows', None)
            pd.set_option('display.width', 1000)

            print("\n" + "="*50)
            print("PREVIEW TABEL LOG SURICATA")
            print("="*50)
            print(df[available_cols].to_string(index=False))

        # ---------------------------------------------------------
        # 4. STATISTIK GLOBAL
        # ---------------------------------------------------------
        if show_stats:
            print("\n" + "="*50)
            print("RINGKASAN STATISTIK GLOBAL")
            print("="*50)
            print(f"Total Log Terproses : {len(df)}")

            if 'event_type' in df.columns:
                print("\n[Jumlah per Event Type]")
                print(df['event_type'].value_counts().to_string())

            if 'alert.signature' in df.columns:
                print("\n[Top Alert Signature]")
                print(df['alert.signature'].value_counts().head(10).to_string())

        # ---------------------------------------------------------
        # 5. DETAIL PAYLOAD WEB
        # ---------------------------------------------------------
        if show_web:
            print("\n" + "="*80)
            print("DETAIL PAYLOAD HTTP (Web Attack Analysis)")
            print("="*80)

            # Menambahkan variasi nama kolom User-Agent untuk kompatibilitas
            web_cols = [
                'timestamp', 'src_ip', 'dest_ip',
                'http.hostname', 'http.url', 'http.http_method',
                'http.user_agent', 'http.http_user_agent'
            ]

            available_web = [c for c in web_cols if c in df.columns]

            # Filter hanya alert yang punya URL
            if 'http.url' in df.columns:
                df_web = df[df['event_type'] == 'alert'].dropna(
                    subset=['http.url'])
                if not df_web.empty:
                    print(df_web[available_web].to_string(index=False))
                else:
                    print("[INFO] Tidak ditemukan alert dengan detail URL HTTP.")
            else:
                print("[INFO] Kolom http.url tidak ditemukan dalam log ini.")

        # Pesan bantuan jika tidak ada argumen aksi
        if not any([output_excel, full_excel, show_table, show_stats, show_web]):
            print("\n[INFO] Tidak ada aksi yang dipilih.")
            print("Gunakan argumen berikut:")
            print("  -o nama.xlsx : Simpan log PENTING (Ringkas)")
            print("  -d nama.xlsx : Simpan SEMUA log (Full Dump)")
            print("  -s           : Tampilkan statistik")
            print("  -w           : Tampilkan payload web")
            print("  -t           : Tampilkan tabel preview")

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Terjadi kesalahan sistem: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Suricata Log Parser & Analyzer - TA Edition")
    parser.add_argument("-f", "--file", required=True,
                        help="Path ke file eve.json")

    # Argumen Excel
    parser.add_argument(
        "-o", "--output", help="Simpan log PENTING/RINGKAS ke Excel")
    parser.add_argument(
        "-d", "--dump", help="Simpan SEMUA log (Full Dump) ke Excel")

    # Argumen Tampilan Terminal
    parser.add_argument("-t", "--table", action="store_true",
                        help="Lihat tabel di terminal")
    parser.add_argument("-s", "--stats", action="store_true",
                        help="Lihat statistik global")
    parser.add_argument("-w", "--web", action="store_true",
                        help="Lihat analisis HTTP/Web")

    args = parser.parse_args()

    process_suricata(args.file, args.output, args.dump,
                     args.table, args.stats, args.web)
