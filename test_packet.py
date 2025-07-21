from scapy.all import IP, TCP, send

# ปรับตามค่าใน rule ที่พบ
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
src_port = 12345
dst_port = 80
payload = b"GET /"

# สร้าง packet
packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA') / payload

# ส่งผ่าน interface ที่ต้องการ (เช่น enp2s0)
send(packet, iface="enp2s0")
