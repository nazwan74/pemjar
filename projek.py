from scapy.all import rdpcap
import geoip2.database

def packet_sniffing(pcap_file):
    """Fitur 1: Packet Sniffing - Membaca file PCAP"""
    print("Membaca file PCAP:", pcap_file)
    packets = rdpcap(pcap_file)
    print(f"Total paket ditemukan: {len(packets)}")
    return packets

def packet_parsing(packets):
    """Fitur 2: Packet Parsing - Menganalisis paket dan menampilkan IP"""
    print("-" * 50)
    print(f"{'Source IP':<15} {'Destination IP':<15} {'Protocol':<10}")
    print("-" * 50)
    for packet in packets:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            proto = packet["IP"].proto

            # Menentukan nama protokol
            if proto == 6:
                protocol = "TCP"
            elif proto == 17:
                protocol = "UDP"
            elif proto == 1:
                protocol = "ICMP"
            else:
                protocol = str(proto)
            
            print(f"{src_ip:<15} {dst_ip:<15} {protocol:<10}")
    print("-" * 50)

def geoip_location(packets, geoip_db_path):
    """Fitur 3: GeoIP Location - Mendapatkan lokasi geografis berdasarkan IP"""
    geo_reader = geoip2.database.Reader(geoip_db_path)
    print("-" * 50)
    print(f"{'Source IP':<15} {'Latitude':<10} {'Longitude':<10}")
    print("-" * 50)

    for packet in packets:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            try:
                location = geo_reader.city(src_ip)
                lat = location.location.latitude
                lon = location.location.longitude
            except:
                lat, lon = "N/A", "N/A"
            print(f"{src_ip:<15} {lat:<10} {lon:<10}")
    
    geo_reader.close()
    print("-" * 50)

def protocol_identification(packets):
    """Fitur 4: Identifikasi Protokol"""
    print("-" * 50)
    print(f"{'Source IP':<15} {'Protocol':<10}")
    print("-" * 50)
    for packet in packets:
        if packet.haslayer("IP"):
            proto = packet["IP"].proto
            if proto == 6:
                protocol = "TCP"
            elif proto == 17:
                protocol = "UDP"
            elif proto == 1:
                protocol = "ICMP"
            else:
                protocol = str(proto)
            print(f"{packet['IP'].src:<15} {protocol:<10}")
    print("-" * 50)

def packet_ports(packets):
    """Fitur 5: Pengecekan Port (TCP/UDP)"""
    print("-" * 50)
    print(f"{'Source IP':<15} {'Dest IP':<15} {'Src Port':<10} {'Dst Port':<10}")
    print("-" * 50)
    for packet in packets:
        if packet.haslayer("TCP"):
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport
            print(f"{packet['IP'].src:<15} {packet['IP'].dst:<15} {src_port:<10} {dst_port:<10}")
        elif packet.haslayer("UDP"):
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport
            print(f"{packet['IP'].src:<15} {packet['IP'].dst:<15} {src_port:<10} {dst_port:<10}")
    print("-" * 50)

def main():
    """Menu utama untuk memilih fitur yang akan dijalankan"""
    pcap_file = "traffic.pcap"  # Ganti dengan file PCAP Anda
    geoip_database = "GeoLite2-City.mmdb"  # Path ke GeoLite2 database
    
    while True:
        print("==== Menu Pilihan Fitur NetGuard ====")
        print("1. Packet Sniffing (Baca File PCAP)")
        print("2. Packet Parsing (Analisis Paket IP)")
        print("3. GeoIP Location (Lokasi Geografis Berdasarkan IP)")
        print("4. Protocol Identification (Identifikasi Protokol)")
        print("5. Packet Ports (Pengecekan Port TCP/UDP)")
        print("6. Keluar")
        
        try:
            choice = int(input("Pilih fitur yang ingin dijalankan (1-6): "))
            if choice == 1:
                packets = packet_sniffing(pcap_file)
            elif choice == 2:
                packet_parsing(packets)
            elif choice == 3:
                geoip_location(packets, geoip_database)
            elif choice == 4:
                protocol_identification(packets)
            elif choice == 5:
                packet_ports(packets)
            elif choice == 6:
                print("Terima kasih telah menggunakan NetGuard!")
                break
            else:
                print("Pilihan tidak valid, coba lagi.")
        except ValueError:
            print("Input tidak valid. Harap masukkan angka antara 1-6.")
        
if __name__ == "__main__":
    main()
