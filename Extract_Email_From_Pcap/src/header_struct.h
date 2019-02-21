/*************************************************
�汾��EMR 0.0.1
���ߣ������
���ڣ�2013-5-3
��������ͷ�ļ����ڶ��壬��ץ��ʱ����ȡ�ĸ������ϵ�ͷ�ļ���
      ��������·�㡢����㡢�����
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

/* �����������Ӳ�ͷ�ṹ */
typedef struct Ethernet_Header{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}Ethernet_Header;

/* 4�ֽڵ�IP��ַ*/
typedef struct IP_Address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IP_Address;

/* ����������IP���ݱ�ͷ�ṹ */
typedef struct IP_Header{
	u_char ver_ihl;				/* �汾(4 bits) + �ײ�(4 bits) */
	u_char tos;					/* ��������(Type of service) */
	u_short tlen;				/* �ܳ���(Total length) */
	u_short identification;		/* ��ʶ(Identification) */
	u_short flags_fo;			/* ��־λ(Flags)(3 bits) + Ƭƫ����(Fragment offset)(13 bits) */
	u_char ttl;					/* ���ʱ��(Time to live) */
	u_char proto;				/* Э��(Protocol) */
	u_short crc;				/* �ײ�У���(Header checksum) */
	IP_Address saddr;			/* Դ��ַ(Source address) */
	IP_Address daddr;			/* Ŀ�ĵ�ַ(Destination address) */
	u_int op_pad;				/* ѡ������� */
}IP_Header;

/* ���崫����TCP���ݱ�ͷ�ṹ */
typedef u_int tcp_seq;

typedef struct TCP_Head {
	u_short th_sport;			/* Դ�˿ں� */
	u_short th_dport;			/* Ŀ�Ķ˿ں� */
	tcp_seq th_seq;				/* ���к� */
	tcp_seq th_ack;				/* ȷ�Ϻ� */
	u_char th_offx2;			/* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40				/* ���TH_ECE������ */ 
#define TH_CWR 0x80				/* ���TH_CWR������ */
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				/* ���� */
	u_short th_sum;				/* ����� */
	u_short th_urp;				/* ����ָ�� */
}TCP_Head;

/* TCP��α�ײ�������checksumʱʹ��
   -------------
   ��Ա1:32λԴIP�ֶ�
   ��Ա2:32λĿ��IP�ֶ�
   ��Ա3:TCPЭ����
   ��Ա4:TCP����
   -------------
*/
typedef struct Pseudo_TCP_Head{
	IP_Address saddr;
	IP_Address daddr;
	u_short protocal_value;
	u_short tcp_len;
}Pseudo_TCP_Head;


/* TCP�����ݶΣ�����TCP��������ʱʹ�ã�ÿ����Ա���Ǳ�Ҫ�ģ����ɼ���
   -------------
   ��Ա1:32λTCPͷ���е����
   ��Ա2:��ǰTCP���ݱ�����һ��TCP���ݱ�����ʼ�ֽ�λ
   ��Ա3:TCP���ݲ��е����ݵ�ʵ�ʳ���
   ��Ա4:��TCP���������ݶε�ʵ������
   ��Ա5:ָ��ǰһ���ṹ��ָ��
   ��Ա6:ָ���һ���ṹ��ָ��
   -------------
*/
typedef struct TCP_DATA_FREGMENT{
	u_int tcp_seq;
	u_int tcp_seq_next;
	u_int tcp_data_frag_len;	/* ��������Ϊͷ���ʱ�����ֶα�����ǰ�������ж��ٸ���� */
	u_char tcp_data_frag[1500];
	struct TCP_DATA_FREGMENT* tcp_data_prev;
	struct TCP_DATA_FREGMENT* tcp_data_next;
}TCP_DATA_FREGMENT;


/* ��ʶÿ��TCP����
   -------------
   ��Ա1:TCP���ӵı�ʶ�����磺IPsrc_PORTsrc_IPdst_PORTdst.txt��Ҫ��Ҫ��Ҳ��������ļ������ٿ�����
   ��Ա2:������ǰ��TCP�����Ƿ����յ�TCP�ײ���ŵ���1�����ݶ�
   ��Ա3:������ǰ��TCP�����Ƿ����յ�TCP�Ĵλ����еĵ�һ������
   ��Ա4:��¼��ǰTCP�������յ�TCP�Ĵλ����еĵ�һ������ʱ������Ա
   ��Ա5:ָ��ǰһ��TCP_STREAM���ӵ�ָ��
   ��Ա6:ָ���һ��TCP_STREAM���ӵ�ָ��
   ��Ա7:ָ��tcp_data_frag���ӵ�ָ��
   ��Ա8:������ǰ��ָ��tcp_data_frag�������ж��ٸ����
   -------------
*/
typedef struct TCP_STREAM{

	u_char filename[51];

	bool finish_state;
	u_int finish_state_seq;

	struct TCP_STREAM* tcp_stream_prev;		/* ע�⣬��������Ϊtcp_stream_headʱ����ָ��ָ�������еĵ�һ����� */
	struct TCP_STREAM* tcp_stream_next;		/* ע�⣬��������Ϊtcp_stream_headʱ����ָ��ָ�������е����һ����� */
	struct TCP_DATA_FREGMENT* tcp_data_frag_head;

}TCP_STREAM;