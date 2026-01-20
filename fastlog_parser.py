import pandas as pd
import os
import argparse
import re
from colorama import Fore, Style, init

# Inisialisasi Colorama untuk output berwarna di terminal
init(autoreset=True)


def ensure_xlsx_extension(filename):
    """
    Meniru logika dari log_parser.py Anda:
    Memastikan nama file output berakhiran .xlsx
    """
    if not filename:
        return None
    if not filename.endswith('.xlsx'):
        if filename.endswith('.xlxs'):
            corrected = filename.replace('.xlxs', '.xlsx')
            print(
                f"{Fore.YELLOW}[AUTO-FIX] Typo diperbaiki: '{filename}' -> '{corrected}'")
            return corrected
        print(
            f"{Fore.YELLOW}[AUTO-FIX] Menambahkan ekstensi .xlsx pada '{filename}'")
        return filename + '.xlsx'
    return filename


def parse_line(line):
    """
    Memecah satu baris fast.log menjadi dictionary menggunakan Regex.
    Cocok untuk format sampel: 
    01/14/2026-22:34:37... [**] [1:2210058:2] ...
    """
    # Regex Pattern yang disesuaikan dengan sampel Anda
    # Group 1: Timestamp (01/14/2026-22:34:37.805537)
    # Group 2: SID (1:2210058:2)
    # Group 3: Message (Alert text)
    # Group 4: Classification (Optional)
    # Group 5: Priority (Optional)
    # Group 6: Protocol (TCP/UDP/ICMP)
    # Group 7-10: Src IP, Src Port, Dst IP, Dst Port
    pattern = r'(?P<timestamp>^[\d\/\-\:\.]+)\s+\[\*\*\]\s+\[(?P<sid>[\d\:]+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+(?:\[Classification:\s+(?P<classification>.*?)\]\s+)?(?:\[Priority:\s+(?P<priority>\d+)\]\s+)?\{(?P<protocol>\w+)\}\s+(?P<src_ip>\S+):(?P<src_port>\d+)\s+->\s+(?P<dest_ip>\S+):(?P<dest_port>\d+)'

    match = re.search(pattern, line)
    if match:
        return match.groupdict()
    return None


def process_fast_log(file_path, output_excel, show_table, show_stats):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[ERROR]File '{file_path}' tidak ditemukan.")
        return

    parsed_data = []
    error_count = 0

    print(f"{Fore.CYAN}Sedang membaca file: {file_path}...")

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip baris kosong

                data = parse_line(line)
                if data:
                    parsed_data.append(data)
                else:
                    # Debugging: tampilkan baris yang gagal diparsing (opsional)
                    # if error_count < 3: print(f"[DEBUG GAGAL] {line}")
                    error_count += 1

        if not parsed_data:
            print(
                f"{Fore.RED}[ERROR]Tidak ada data valid. Pastikan format file sesuai fast.log Suricata.")
            return

        # Konversi ke DataFrame
        df = pd.DataFrame(parsed_data)

        # Konversi Priority ke angka agar bisa diurutkan
        if 'priority' in df.columns:
            df['priority'] = pd.to_numeric(df['priority'], errors='coerce')

        print(f"{Fore.GREEN}[SUCCESS]Berhasil memuat {len(df)} baris log.")
        if error_count > 0:
            print(
                f"{Fore.YELLOW}[INFO]{error_count} baris dilewati (format tidak cocok/rusak).")

        # ---------------------------------------------------------
        # 1. EKSPOR KE EXCEL
        # ---------------------------------------------------------
        if output_excel:
            output_excel = ensure_xlsx_extension(output_excel)
            print(f"{Fore.CYAN}Sedang menyimpan ke Excel: {output_excel}...")

            # Urutan kolom yang rapi untuk laporan
            cols_order = ['timestamp', 'message', 'classification', 'priority',
                          'protocol', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'sid']

            # Filter kolom yang ada saja (mencegah error jika field kosong)
            final_cols = [c for c in cols_order if c in df.columns]

            df[final_cols].to_excel(
                output_excel, index=False, engine='openpyxl')
            print(f"{Fore.GREEN}[SUCCESS]File Excel tersimpan.")

        # ---------------------------------------------------------
        # 2. STATISTIK (Mirip fitur -s di script lama)
        # ---------------------------------------------------------
        if show_stats:
            print("="*60)
            print("STATISTIK SERANGAN (FAST LOG)")
            print("="*60 + Style.RESET_ALL)

            print(f"Total Alert: {len(df)}")

            if 'message' in df.columns:
                print(f"\n{Fore.CYAN}[INFO][Klasifikasi Jenis Serangan]")
                print(df[['message', 'classification', 'sid', 'priority']
                         ].value_counts().to_string())

            if 'src_ip' in df.columns:
                print(f"\n{Fore.CYAN}[INFO][Daftar IP Penyerang]")
                print(df['src_ip'].value_counts().to_string())

            if 'dest_ip' in df.columns:
                print(f"\n{Fore.CYAN}[INFO][Daftar IP Target]")
                print(df['dest_ip'].value_counts().to_string())

            if 'protocol' in df.columns:
                print(f"\n{Fore.CYAN}[INFO][Daftar Protocol]")
                print(df['protocol'].value_counts().to_string())

        # ---------------------------------------------------------
        # 3. TABEL PREVIEW (Mirip fitur -t)
        # ---------------------------------------------------------
        if show_table:
            preview_cols = ['timestamp', 'message', 'classification', 'src_ip', 'dest_ip']
            available_preview = [c for c in preview_cols if c in df.columns]

            pd.set_option('display.max_rows', None)
            pd.set_option('display.width', 1000)
            # Agar pesan panjang tidak terpotong jelek
            pd.set_option('display.max_colwidth', 50)

            print("="*60)
            print("PREVIEW DATA FAST LOG")
            print("="*60 + Style.RESET_ALL)
            print(df[available_preview].to_string(index=False))

        # Pesan jika tidak ada argumen
        if not any([output_excel, show_table, show_stats]):
            print(f"\n{Fore.YELLOW}[INFO] Tidak ada aksi dipilih.")
            print("Gunakan argumen:")
            print("  -f file.log  : Input file")
            print("  -o nama.xlsx : Simpan Excel")
            print("  -s           : Lihat Statistik")
            print("  -t           : Lihat Tabel")

    except Exception as e:
        print(f"{Fore.RED}[CRITICAL ERROR] {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Suricata Fast.log Parser (Regex Edition)")
    parser.add_argument("-f", "--file", required=True,
                        help="Path ke file fast.log")
    parser.add_argument("-o", "--output", help="Simpan hasil ke Excel")
    parser.add_argument("-t", "--table", action="store_true",
                        help="Lihat tabel di terminal")
    parser.add_argument("-s", "--stats", action="store_true",
                        help="Lihat statistik")

    args = parser.parse_args()
    process_fast_log(args.file, args.output, args.table, args.stats)
