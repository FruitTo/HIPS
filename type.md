# 📚 สรุป `_t` Data Types ใน C / POSIX

`_t` คือรูปแบบการตั้งชื่อชนิดข้อมูล (type) ที่ใช้ในภาษา C และ POSIX เพื่อระบุว่าเป็น **typedef หรือชนิดข้อมูลพิเศษ**  
โดยมากจะใช้ในระบบปฏิบัติการ Linux/Unix และใน library ที่เกี่ยวข้องกับ system call

---

## ✅ ความหมายโดยรวม

- `_t` = **type** (ย่อมาจาก “type”)
- ใช้สำหรับ `typedef` ที่ระบบหรือ library กำหนดมาให้
- ออกแบบมาเพื่อให้ **ปลอดภัย**, **ยืดหยุ่น**, และ **เหมาะกับแต่ละระบบปฏิบัติการ**

---

## 🧩 ตัวอย่างชนิดข้อมูล `_t` ที่ใช้บ่อย

| ชนิดข้อมูล (`_t`) | ใช้ทำอะไร | มักแทนด้วย |
|--------------------|------------|-------------|
| `size_t`           | ขนาดของ object, memory, array | `unsigned int` / `unsigned long` |
| `ssize_t`          | signed version ของ `size_t` (ใช้กับ `read()`/`write()`) | `signed long` |
| `pid_t`            | เก็บ Process ID | `int` |
| `uid_t`            | เก็บ User ID | `unsigned int` |
| `gid_t`            | เก็บ Group ID | `unsigned int` |
| `mode_t`           | สิทธิ์ไฟล์ เช่น 0777 | `unsigned short` |
| `off_t`            | ตำแหน่ง offset ในไฟล์ | `long` |
| `time_t`           | เวลาตาม UNIX timestamp (วินาทีจาก 1970) | `long` |
| `clock_t`          | หน่วยเวลา CPU (ticks) | `long` |
| `dev_t`            | device ID | `unsigned long` |
| `ino_t`            | inode number ของไฟล์ | `unsigned long` |
| `socklen_t`        | ขนาดของโครงสร้าง socket | `int` |
| `pthread_t`        | Thread ID สำหรับ pthread | struct / pointer |
| `intptr_t`         | ตัวเลขที่เก็บ pointer ได้ | `long` |
| `uintptr_t`        | unsigned version ของ `intptr_t` | `unsigned long` |
| `sigset_t`         | ใช้เก็บ signal mask | struct |
| `fd_set`           | ชุดของ file descriptors สำหรับ `select()` | struct |
| `int8_t`, `int32_t`, `uint64_t` | ตัวเลขที่ขนาดคงที่ | typedef จาก `<stdint.h>` |

---

## 🧠 ทำไมถึงไม่ใช้ `int` ตรง ๆ?

| เหตุผล | อธิบาย |
|--------|--------|
| ✅ Platform Independence | เช่น `size_t` จะเป็น 32 บิตบนระบบ 32-bit และ 64 บิตบนระบบ 64-bit |
| ✅ ปลอดภัย | เช่น `size_t` ไม่มีค่าติดลบ ทำให้ไม่มี bug แบบ signed/unsigned mismatch |
| ✅ อ่านง่าย | เห็น `pid_t` แล้วรู้ทันทีว่าคือ Process ID |
| ✅ ตรงกับ system call | ฟังก์ชันอย่าง `fork()`, `malloc()`, `read()` ใช้ชนิดพวกนี้โดยตรง |

---

## 📚 แหล่งที่พบ `_t`

- `<stddef.h>` — `size_t`, `ptrdiff_t`
- `<sys/types.h>` — `pid_t`, `uid_t`, `mode_t`, ฯลฯ
- `<stdint.h>` — `int8_t`, `uint32_t`, `intptr_t`
- `<time.h>` — `time_t`, `clock_t`
- `<pthread.h>` — `pthread_t`
- `<signal.h>` — `sigset_t`
- `<sys/socket.h>` — `socklen_t`

---

## ✅ สรุปสุดท้าย

- `_t` ไม่ใช่ตัวแปรพิเศษ แต่เป็นชนิดข้อมูลที่กำหนดโดยระบบ
- ใช้สำหรับทำให้โค้ดปลอดภัย, portable และ readable
- ควรใช้ชนิดพวกนี้เมื่อเขียนโปรแกรมระบบ, network, memory หรือ multi-threading

> 💡 ถ้าคุณกำลังเขียนโปรแกรมระดับล่าง หรือใช้ system call เช่น `fork()`, `read()`, `malloc()` — คุณจะต้องใช้ `_t` พวกนี้แน่นอน!
