#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H


#define ETHER_ADDR_LEN		6		//以太网MAC地址长度
#define IP_ADDR_LEN			4		//IP地址长度

#define ETH_IP				0x0800	//IP类型
#define ETH_ARP				0x0806	//ARP类型
#define ARP_REQUEST			0x0001	//ARP请求
#define ARP_REPLY			0x0002	//ARP响应
#define ARP_HARDWARE		0x0001	//ARP硬件类型

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;

typedef struct _ethdr		//以太网帧头结构
{
	u_char	eh_dst[ETHER_ADDR_LEN];	//目的MAC地址	
	u_char eh_src[ETHER_ADDR_LEN];	//源MAC地址
	u_short eh_type;				//帧类型
}ETHDR,*PETHDR;

typedef struct _arphdr		//APR头结构
{
	u_short arp_htype;		//Hardware type 硬件类型
	u_short arp_ptype;		//Protocol type 协议类型
	u_char	arp_hlen;		//Hardware address length  硬件地址长度
	u_char  arp_plen;		//Protocol address length  协议地址长度
	u_short	arp_op;			//Operation 操作，1为请求，2为回答
	u_char  arp_sha[ETHER_ADDR_LEN];		//sha = Sender hardware address 发送方硬件地址
	u_long  arp_spa;		//spa = Sender protocol address 发送方协议地址
	u_char  arp_tha[ETHER_ADDR_LEN];		//tha = Target hardware address 目标硬件地址
	u_long  arp_tpa;		//tpa = Target protocol address 目标协议地址
}ARPHDR,*PARPHDR;

typedef struct _packet		//最后封装的数据包结构
{
	ETHDR ethdr;			//以太头
	ARPHDR arphdr;			//ARP头
}PACKET;

#endif