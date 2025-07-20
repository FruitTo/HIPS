#!/usr/bin/env bash
set -euxo pipefail

# ตรวจสอบว่าเรียกด้วย root
if [ "$EUID" -ne 0 ]; then
  echo "กรุณาใช้ root หรือ sudo"
  exit 1
fi

NS2="ns2"
VETH0="veth0"
VETH1="veth1"
IP0="10.0.0.1/24"
IP1="10.0.0.2/24"

# ตรวจ namespace ถ้ายังไม่มีค่อยสร้าง
if ! ip netns list | grep -qw "$NS2"; then
  ip netns add "$NS2"
  echo "สร้าง namespace $NS2"
else
  echo "namespace $NS2 มีอยู่แล้ว — ข้ามขั้นตอนสร้าง"
fi

# ตรวจ veth0 ก่อนสร้าง
if ip link show "$VETH0" &>/dev/null; then
  echo "interface $VETH0 มีอยู่ — ข้ามสร้าง"
else
  ip link add "$VETH0" type veth peer name "$VETH1"
  ip link set "$VETH1" netns "$NS2"
  echo "สร้าง veth pair: $VETH0 ↔ $VETH1"
fi

# กำหนด IP และ bring up ฝั่ง root
ip addr flush dev "$VETH0" || true
ip addr add "$IP0" dev "$VETH0"
ip link set dev "$VETH0" up

# bring up ฝั่งใน namespace
ip netns exec "$NS2" bash -euxc "
  ip link set lo up
  ip addr flush dev \"$VETH1\" || true
  ip addr add \"$IP1\" dev \"$VETH1\"
  ip link set dev \"$VETH1\" up
"

# ทดสอบ ping
ip netns exec "$NS2" ping -c2 -I "$VETH1" "${IP0%/*}" || {
  echo "ping ล้มเหลว — ตรวจสอบการตั้งค่า"
  exit 1
}

echo "✅ สร้าง veth pair และ namespace สำเร็จ (หรือเคยมีอยู่แล้ว)"
