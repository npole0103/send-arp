# send-arp
send-arp HW

---

ARP Attack Wireshark 화면
![image](https://user-images.githubusercontent.com/37138188/127363884-4b070d2f-3126-4d88-8f53-7fb0d17ba6d8.png)

ARP Victim ARP Table 화면
![image](https://user-images.githubusercontent.com/37138188/127364058-142d68c5-5e1a-4d2c-8bc6-34df1b811842.png)

## 1.254인 GateWay의 MAC 어드레스가 공격자의 주소로 바뀐 것을 확인할 수 있었음.

---

## pcap-test 코드리뷰

패킷 받을 때 OFFSET으로 하지말고, 구조체를 sizeof하여 더해줘야한다.

왜냐하면 헤더 크기나 TCP 헤더 크기는 옵션에 따라서 크기가 가변적이기 때문이다.

`totlen` – `ip_len` – `tcp len` 하면 데이터의 길이. ※totlen은 IP 뒤에 오는 데이터의 총 길이.

**ip_hl에 4를 곱하는 이유?**
sizeof(struct up)는 IP 헤더 길이를 8비트 바이트 단위로 산출함.
여기서 ip_hl에 4를 곱해야 32비트 워드로 제공이 된다.

`char* inet_ntoa(uint32_t ip);` : 스태틱 변수로 값을 리턴하기 때문에, 값을 저장하는 상황에서는 절대 사용하면 안된다.

변수를 저장할 때는 `inet_ntop();`를 사용해야한다. 이는 인자로 담아둘 변수 포인터 값도 전달해줘야 하는 함수다.

---

## ARP란?

ARP 프로토콜(Address Resolution Protocol) : 네트워크 상에서 IP주소를 물리적 네트워크 주소로 대응(Bind)시키기 위해 사용되는 프로토콜이다.

이를테면, IP 호스트 A가 IP 호스트 B에게 IP 패킷을 전송하려고 할 때 IP 호스트 B의 물리적 네트워크 주소를 모른다면, ARP 프로토콜을 사용하여 목적지 IP 주소 B와 브로드캐스팅 물리적 네트워크 주소 FFFFFFFFFFFF를 가지는 ARP 패킷을 네트워크 상에 전송한다.

호스트 B는 자신의 IP 주소가 목적지에 있는 ARP 패킷을 수신하면 자신의 물리적 네트워크 주소를 A에게 응답한다.

이와 같은 방식으로 수집된 IP 주소와 이에 해당하는 물리적 네트워크 주소 정보는 각 IP 호스트의 ARP 캐시라 불리는 메모리에 테이블 형태로 저장된 다음, 패킷을 전송할 때에 다시 사용된다.

---

## 실습

`ifconfig` : 나의 아이피와 맥 어드레스 찾기

`ping` : 상대 아이피와 맥 어드레스 찾기

`arp -an` : ARP 캐쉬테이블에 저장되어 있는 호스트정보 출력

[ARP 사용법](http://board.theko.co.kr/bbs/board.php?bo_table=B11&wr_id=307)

`route -n` : 라우트 테이블 정보 출력 - 게이트웨이 주소

### Ping Packet 실습
Wireshark를 실행하여 'ping 8.8.8.8' 명령어에 의한 ICMP packet(icmp.pcap으로 저장)을 잡아 ppt 파일의 ICMP 란에 ETH 헤더와 IP 헤더에 mac과 ip 정보를 입력한다.

### ARP Packet 실습
'sudo arp -d <gateway>'라는 명령어로 자신의 ARP cache table을 삭제하게 되면 외부와의 통신을 위해서 자신의 호스트와 gatway 사이에 ARP packet(ARP request, ARP reply)가 발생한다. 이 상태에서 잡힌 ARP packet(arp.pcap으로 저장)을 보면서 PPT 파일의 ARP 란에 mac과 ip 정보를 입력한다.

상대방, 나, 게이트웨이 모두 Arp Table을 가지고 있다.
  
**우리의 목표는 마치 내가 Gateway인 것처럼 거짓된 ARP Reply를 날리는 것**
- 그렇게 해서 Victim은 Gateway에 보내야할 정보를 Attacker에게 보내게 된다.
 
FF:FF:FF:FF:FF:FF 같은 네트워크 대역 모두에게 전달되는 브로드케스트임. Target IP를 갖고 있는 놈만 응답함.
Target MAC은 모르기 때문에, 00:00:00:00:00:00으로 실어서 Request 날림.
  
**ARP Request/Reply 발생 시 ARP_SRC_MAC / ARP_SRC_IP로 ARP 테이블 업데이트**

### 프로그램을 이용하여 상대방 컴퓨터의 ARP cache table 감염(infection)

main.cpp 코드 내부에 있는 값들을 적당히 수정하여 상대방 컴퓨터(victim)에서 gateway에 대한 ARP cache table을 감염시켜 본다.

이 경우(attack이 성공한 경우) 상대방 컴퓨터에서 ARP cache table이 변경되고, 외부 ping을 때렸을 때 그 ping packet이 자신(attacker)에게 오게 되며, 상대방 컴퓨터에서는 정상적인 IP 통신을 할 수 없게 된다(인터넷이 막히는 것처럼 된다).
  
### Src MAC 어드레스는 Attack의 MAC

### Src IP 어드레스는 Gateway의 IP

---

## 개념

MAC은 로컬 통신을 위해서 사용

IP는 원격 통신을 위해서 사용

ARP Request : 상대방에 대한 MAC을 묻기 위한 것이다.

ARP Reply : MAC 어드레스를 물어본 상대방에게 답을 보내는 것이다.

**ARP REQUEST는 브로드캐스트**

**ARP REPLAY는 유니캐스트**

**유니캐스트란?** : 유니캐스트는 정보를 전송하기 위한 프레임에 자신의 MAC 주소와 목적지의 MAC 주소를 첨부하여 전송하는 방식을 말한다. 어떤 시스템이 유니캐스트 방식으로 데이터를 전송하게 되면 같은 네트워크에 있는 모든 시스템들은 그 MAC 주소를 받아서 자신의 MAC 주소와 비교 후에 자신의 MAC 주소와 같지 않다면 프레임을 버리고 같다면 프레임을 받아서 처리하게 된다.

**브로드캐스트란?** : 브로드캐스트 방식은 로컬 네트워크에 연결되어 있는 모든 시스템에게 프레임을 보내는 방식을 말한다. 브로드캐스트 방식은 통신하고자 하는 시스템의 MAC 주소를 알지 못하는 경우, 네트워크에 있는 모든 시스템에게 알리는 경우, 라우터끼리 정보를 교환하거나 새로운 라우터를 찾는 경우 등에 이용이 된다.

[브로드캐스트/유니스캐스트/멀티캐스트](https://m.blog.naver.com/wnrjsxo/221250742423)
