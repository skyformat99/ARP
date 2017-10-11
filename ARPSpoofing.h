#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H


#define ETHER_ADDR_LEN		6		//��̫��MAC��ַ����
#define IP_ADDR_LEN			4		//IP��ַ����

#define ETH_IP				0x0800	//IP����
#define ETH_ARP				0x0806	//ARP����
#define ARP_REQUEST			0x0001	//ARP����
#define ARP_REPLY			0x0002	//ARP��Ӧ
#define ARP_HARDWARE		0x0001	//ARPӲ������

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;

typedef struct _ethdr		//��̫��֡ͷ�ṹ
{
	u_char	eh_dst[ETHER_ADDR_LEN];	//Ŀ��MAC��ַ	
	u_char eh_src[ETHER_ADDR_LEN];	//ԴMAC��ַ
	u_short eh_type;				//֡����
}ETHDR,*PETHDR;

typedef struct _arphdr		//APRͷ�ṹ
{
	u_short arp_htype;		//Hardware type Ӳ������
	u_short arp_ptype;		//Protocol type Э������
	u_char	arp_hlen;		//Hardware address length  Ӳ����ַ����
	u_char  arp_plen;		//Protocol address length  Э���ַ����
	u_short	arp_op;			//Operation ������1Ϊ����2Ϊ�ش�
	u_char  arp_sha[ETHER_ADDR_LEN];		//sha = Sender hardware address ���ͷ�Ӳ����ַ
	u_long  arp_spa;		//spa = Sender protocol address ���ͷ�Э���ַ
	u_char  arp_tha[ETHER_ADDR_LEN];		//tha = Target hardware address Ŀ��Ӳ����ַ
	u_long  arp_tpa;		//tpa = Target protocol address Ŀ��Э���ַ
}ARPHDR,*PARPHDR;

typedef struct _packet		//����װ�����ݰ��ṹ
{
	ETHDR ethdr;			//��̫ͷ
	ARPHDR arphdr;			//ARPͷ
}PACKET;

#endif