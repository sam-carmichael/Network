/*************************************************
版本：EMR 0.0.1
作者：李德新
日期：2013-5-3
描述：此头文件用于定义，在抓包时用提取的各个层上的头文件，
      如数据链路层、网络层、传输层
**************************************************/
#define WIN32
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define ETHER_ADDR_LEN 6

#define TCP_PROTOCAL 6
#define POP3_PROTOCAL 110

#define TCP_HEAD_FIN 0x01
#define TCP_HEAD_SYN 0x02
#define TCP_HEAD_ACK 0x10

#define PCAP_FILE_EOF -2

/* 定义数据链接层头结构 */
typedef struct Ethernet_Header{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}Ethernet_Header;

/* 4字节的IP地址*/
typedef struct IP_Address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IP_Address;

/* 定义网络层的IP数据报头结构 */
typedef struct IP_Header{
	u_char ver_ihl;				/* 版本(4 bits) + 首部(4 bits) */
	u_char tos;					/* 服务类型(Type of service) */
	u_short tlen;				/* 总长度(Total length) */
	u_short identification;		/* 标识(Identification) */
	u_short flags_fo;			/* 标志位(Flags)(3 bits) + 片偏移量(Fragment offset)(13 bits) */
	u_char ttl;					/* 存活时间(Time to live) */
	u_char proto;				/* 协议(Protocol) */
	u_short crc;				/* 首部校验和(Header checksum) */
	IP_Address saddr;			/* 源地址(Source address) */
	IP_Address daddr;			/* 目的地址(Destination address) */
	u_int op_pad;				/* 选项与填充 */
}IP_Header;

/* 定义传输层的TCP数据报头结构 */
typedef u_int tcp_seq;

typedef struct TCP_Head {
	u_short th_sport;			/* 源端口号 */
	u_short th_dport;			/* 目的端口号 */
	tcp_seq th_seq;				/* 序列号 */
	tcp_seq th_ack;				/* 确认号 */
	u_char th_offx2;			/* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40				/* 这个TH_ECE还不懂 */ 
#define TH_CWR 0x80				/* 这个TH_CWR还不懂 */
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				/* 窗口 */
	u_short th_sum;				/* 检验和 */
	u_short th_urp;				/* 紧急指针 */
}TCP_Head;

/* TCP的伪首部，用于checksum时使用
   -------------
   成员1:32位源IP字段
   成员2:32位目的IP字段
   成员3:TCP协议编号
   成员4:TCP长度
   -------------
*/
typedef struct Pseudo_TCP_Head{
	IP_Address saddr;
	IP_Address daddr;
	u_short protocal_value;
	u_short tcp_len;
}Pseudo_TCP_Head;


/* TCP的数据段，用于TCP数据重组时使用，每个成员都是必要的，不可减少
   -------------
   成员1:32位TCP头部中的序号
   成员2:当前TCP数据报的下一个TCP数据报的起始字节位
   成员3:TCP数据部中的数据的实际长度
   成员4:存TCP报文中数据段的实际内容
   成员5:指向前一个结构的指针
   成员6:指向后一个结构的指针
   -------------
*/
typedef struct TCP_DATA_FREGMENT{
	u_int tcp_seq;
	u_int tcp_seq_next;
	u_int tcp_data_frag_len;	/* 当被声明为头结点时，此字段表明当前链表中有多少个结点 */
	u_char tcp_data_frag[1500];
	struct TCP_DATA_FREGMENT* tcp_data_prev;
	struct TCP_DATA_FREGMENT* tcp_data_next;
}TCP_DATA_FREGMENT;


/* 标识每个TCP链接
   -------------
   成员1:TCP链接的标识，形如：IPsrc_PORTsrc_IPdst_PORTdst.txt，要不要它也做输入的文件名，再考虑下
   成员2:表明当前此TCP链接是否已收到TCP首部序号等于1的数据段
   成员3:表明当前此TCP链接是否已收到TCP四次挥手中的第一次数据
   成员4:记录当前TCP链接已收到TCP四次挥手中的第一次数据时的序列员
   成员5:指向前一个TCP_STREAM链接的指针
   成员6:指向后一个TCP_STREAM链接的指针
   成员7:指向tcp_data_frag链接的指针
   成员8:表明当前所指的tcp_data_frag链接中有多少个结点
   -------------
*/
typedef struct TCP_STREAM{

	u_char filename[51];

	bool finish_state;
	u_int finish_state_seq;

	struct TCP_STREAM* tcp_stream_prev;		/* 注意，当被声明为tcp_stream_head时，此指针指向链表中的第一个结点 */
	struct TCP_STREAM* tcp_stream_next;		/* 注意，当被声明为tcp_stream_head时，此指针指向链表中的最后一个结点 */
	struct TCP_DATA_FREGMENT* tcp_data_frag_head;

}TCP_STREAM;