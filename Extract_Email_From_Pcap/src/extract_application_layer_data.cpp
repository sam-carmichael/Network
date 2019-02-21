/*************************************************
�汾��EMR 0.0.1
���ߣ������
���ڣ�2013-5-3
�������˳��������Ϊ��ʽ.pcap���ļ������ļ��а�������pop3Э��
      �����Ӧ�ò��е��������ݳ�ȡ��������������һ���ļ��С�
**************************************************/
#include "header_struct.h"

#define LINE_LEN 16
#define LINE_BETWEEN 8

char Filename[51]="";	/* ����product_name�����У��ļ�������ʽΪ��Ŀ��IP_Ŀ��port_ԴIP_ԴPort.txt */

/* product_name����������
   ��������Ψһ��ʶ���ļ�����
   �ļ������磺Ŀ��IP_Ŀ��port_ԴIP_ԴPort.txt
*/
char* product_name(struct IP_Header* ip_head, u_short th_sport, u_short th_dport){

	char str[6];					//���ڶԶ˿ڵ�����ת�ַ������ת��
	u_int position = 0;
	int pos;
	int temp;						//��ת�������ļ�����Ҫ�õ�

	memset(Filename, '\0', sizeof(Filename));
	temp = (u_int)(ip_head->saddr.byte1);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	position = 0;
	pos = position;
	for(int i = 0; position < pos + strlen(str);position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->saddr.byte2);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->saddr.byte3);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->saddr.byte4);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (int)th_sport;
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->daddr.byte1);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->daddr.byte2);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->daddr.byte3);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (u_int)(ip_head->daddr.byte4);
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];
	Filename[position++] = '_';

	temp = (int)th_dport;
	memset(str, '\0', sizeof(str));
	itoa(temp, str, 10);
	pos = position;
	for(int i = 0; position < pos + strlen(str); position++, i++)
		Filename[position] = str[i];

	Filename[position++] = '.';
	Filename[position++] = 't';
	Filename[position++] = 'x';
	Filename[position++] = 't';
	Filename[position] = '\0';
	return Filename;
}

/* ��������αTCP�ײ�*/
Pseudo_TCP_Head* build_pseudo_TCP_Head(IP_Header* ip_head){

	//���ʹ��Pseudo_TCP_Head temp, ���ڷ���ջ�еĵ�ַ�ᱻ���ǣ�����Ҫ��ָ�롣���ǵ�Ҫ�ͷš�
	Pseudo_TCP_Head* temp = (Pseudo_TCP_Head*)malloc(sizeof(struct Pseudo_TCP_Head));

	temp->daddr = ip_head->daddr;
	temp->saddr = ip_head->saddr;
	temp->protocal_value = htons((u_short)(ip_head->proto));

	//��Ϊtcp_len��Ҫ���ڼ�����ϣ����Դ˴��Ƿ�Ӧ�������������ַ���ת���أ��������������˵
	temp->tcp_len =(u_short)(htons((ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4)));
	
	return temp;	
}


/* ���ڼ���TCP��checksumֵ�����������
   ��һ�������������Ļ�����
   �ڶ�������������TCP�εĳ��ȣ����ȵ�λ���ֽ�
   �㷨�������Ʒ����������   
*/
u_short tcp_check_sum(u_short* buffer, int size){
	
	unsigned long cksum = 0;
	while(size>1){
		cksum += ntohs(*buffer);
		buffer++;
		size -= sizeof(u_short);
	}

	if(size)
		cksum += ntohs(*buffer);	
	
	while(cksum >> 16)
		cksum = (cksum>>16) + (cksum&0xffff);

	return (u_short)(~cksum);
}

/* �����filenameΪ���Ľ���Ƿ������stream_node�����У���������򷵻������ָ�룬�򲻴����򷵻ؿ�ֵNULL */
struct TCP_STREAM* exist_stream_node(struct TCP_STREAM* stream_head, char* filename){

	struct TCP_STREAM* temp = stream_head->tcp_stream_prev;	/* ��stream_node�����еĵ�һ�����ĵ�ַ��temp */
	
	while(temp != NULL){

		//printf("temp->filename = %s\n",temp->filename);
		//printf("filename = %s\n",filename);
		if(strcmp((char*)(temp->filename), filename) == 0)
			return temp;
		else
			temp = temp->tcp_stream_next;
	}

	return NULL;
}

/* ɾ��stream_node��� */
void delete_stream_node(struct TCP_STREAM* stream_head, struct TCP_STREAM* current_stream_node){
	if((current_stream_node->tcp_stream_prev == stream_head) && 
	   (current_stream_node->tcp_stream_next == NULL))
	{
    	/* ���1:��ǰstream_node������ֻ��һ��stream_node��㣬stream_headָ���е�tcp_stream_head
	       ��tcp_stream_tail��ָ����һ��sream_node��� */
		stream_head->tcp_stream_prev = NULL;	//ͷ������ָ��ָ���
		stream_head->tcp_stream_next = NULL;	//ͷ����βָ��ָ���
		free(current_stream_node);//����ط�û������Դ�����һ�����ϣ�һ��Ҫ����
	}
	else if((current_stream_node->tcp_stream_prev != stream_head) &&
	        (current_stream_node->tcp_stream_next == NULL))
	{
		/* ���2:��ǰstream_node�������д��ڵ���2�����ϵ�stream_node���㣬
	         ��Ҫɾ����stream_node��������һ����� */
		current_stream_node->tcp_stream_prev->tcp_stream_next = NULL;
		stream_head->tcp_stream_next = current_stream_node->tcp_stream_prev;
		free(current_stream_node);//����ط�û������Դ�����һ�����ϣ�һ��Ҫ����
	}
	else if((current_stream_node->tcp_stream_prev == stream_head) &&
	        (current_stream_node->tcp_stream_next != NULL))
	{
		/* ���3:��ǰstream_node�������д��ڵ���2�����ϵ�stream_node����
	         ��Ҫɾ����stream_node����������еĵ�һ��stream_node��� */
		current_stream_node->tcp_stream_next->tcp_stream_prev = stream_head; 
		stream_head->tcp_stream_prev = current_stream_node->tcp_stream_next;
		free(current_stream_node);//����ط�û������Դ�����һ�����ϣ�һ��Ҫ����
	}
	else if((current_stream_node->tcp_stream_prev != stream_head) &&
	        (current_stream_node->tcp_stream_next != NULL))
	{
		/* ���4:��ǰstream_node�������д��ڵ���2�����ϵ�stream_node����
	         ��Ҫɾ����stream_node��㲻�ǵ�һ��Ҳ�������һ��stream_node��� */
		current_stream_node->tcp_stream_prev->tcp_stream_next = current_stream_node->tcp_stream_next;
		current_stream_node->tcp_stream_next->tcp_stream_prev = current_stream_node->tcp_stream_prev;
		free(current_stream_node);//����ط�û������Դ�����һ�����ϣ�һ��Ҫ����
	}
}

/* ��steam_node�����в���һ��stream_node, ���뷽����˳����� */
void insert_stream_node(struct TCP_STREAM* stream_head, struct TCP_STREAM* current_stream_node){
	/* ���stream_node�ǿյ�(�����������ǿյ�)�����뵽��һ��λ�ã�����Ͳ������һ��λ�� */
	if(stream_head->tcp_stream_prev == NULL)
	{	
		//printf("@_@\n");
		stream_head->tcp_stream_prev = current_stream_node;
		stream_head->tcp_stream_next = current_stream_node;
		current_stream_node->tcp_stream_prev = stream_head;	/* �˴�����û�� */
		current_stream_node->tcp_stream_next = NULL;
	}
	else	//�˴�����û�л������Ե�
	{
		struct TCP_STREAM* temp = stream_head->tcp_stream_next;
		current_stream_node->tcp_stream_next = temp;
		current_stream_node->tcp_stream_prev = stream_head;
		temp->tcp_stream_prev = current_stream_node;
		stream_head->tcp_stream_next = current_stream_node;
		/*����5�еĴ�����2013-8-22ע�͵ã��޸İ����
		struct TCP_STREAM* temp = stream_head->tcp_stream_next;
		temp->tcp_stream_next = current_stream_node;
		current_stream_node->tcp_stream_prev = temp;
		current_stream_node->tcp_stream_next = NULL;		
		stream_head->tcp_stream_next = current_stream_node;*/
	}
}

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int res;						//����pcap_next_ex()�����ķ���ֵ
	u_int ether_capture_num = 0;	//ͳ���ļ������Ӳ���ĸ���
	u_int tcp_data_section_len = 0;		//ͳ��ÿ��TCP���Ķ����ݲ��ֵĳ��ȣ��������Ӧ�ò�Э������㣬���û��Ӧ�ò�Э����Ϊ��
	struct Ethernet_Header* eth_head;
	struct IP_Header* ip_head;
	struct TCP_Head* tcp_head;
	struct Pseudo_TCP_Head* pseudo_tcp_head;
	FILE *store_pop_mail;
	u_char ReceiveBuffer[1600];		//����tcp_checksumʱʹ��
	char* filename;

	/* ע��tcp_stream_head��㣬��һ���ս�㣬���������еĵ�һ�����ָ��
	   �����һ��ָ�룬tcp_stream_prevָ��ͷ��㣬tcp_stream_nextָ��β��� */
	struct TCP_STREAM* tcp_stream_head = 
		(struct TCP_STREAM*)malloc(sizeof(struct TCP_STREAM));
	tcp_stream_head->tcp_stream_prev = NULL;
	tcp_stream_head->tcp_stream_next = NULL;

	struct TCP_STREAM* tcp_stream_node;
	struct TCP_DATA_FREGMENT* tcp_data_frag_head;
	struct TCP_DATA_FREGMENT* tcp_data_frag_node;

	if(argc != 2)
	{
		printf("usage: %s Filename", argv[0]);
		return -1;
	}

	/* ������WinPcap�﷨����һ��Դ�ַ��� */
	if ( pcap_createsrcstr( source,         // Դ�ַ���
		PCAP_SRC_FILE,						// ����Ҫ�򿪵��ļ�Ϊ�����ļ�
		NULL,								// Զ������
		NULL,								// Զ�������˿�
		argv[1],							// ����Ҫ�򿪵��ļ���
		errbuf								// ���󻺳���
		) != 0)
	{
		fprintf(stderr,"\nError creating a source string\n");
		return -1;
	}

	/* �򿪲����ļ� */
	if ( (fp= pcap_open(source,				 // �豸��
		65536,								 // Ҫ��׽�����ݰ��Ĳ���
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,			 // ����ģʽ
		1000,								// ��ȡ��ʱʱ��
		NULL,								// Զ�̻�����֤
		errbuf								// ���󻺳��
		) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", source);
		return -1;
	}
	
	/* �����·������ */
	printf("pcap_datalink = %s_%s\n",pcap_datalink_val_to_description(pcap_datalink(fp)), pcap_datalink_val_to_name(pcap_datalink(fp)));  
	printf("��ʼ��ȡ�ʼ�����,��ȴ�......\n");

	/* �������̫��������д��� */
	if(pcap_datalink_val_to_name(pcap_datalink(fp) == 1))
	{
		/* ���ļ���ȡ���ݰ�,whileѭ����ʾֻ���ļ�ȫ����ȡ��������ֹͣѭ�� */
		while((res = pcap_next_ex(fp, &header, &pkt_data)) !=  PCAP_FILE_EOF)
		{
			//bool finish_state = false;

			/* �ڴ˴�Ҫ��һ���жϣ�len == caplen, �����������¼���ĸ���ûץ�ã��ж��ٸ������İ� */

			/* ͳ���ļ����ж��ٸ�֡*/
			ether_capture_num++;
			
			/* ��λ������·����ײ���ַ */
			eth_head = (struct Ethernet_Header*)pkt_data;

			/* ��λ�������IP���ݱ����ײ���ַ */
			ip_head = (struct IP_Header*)((char*)eth_head + sizeof(struct Ethernet_Header));

			/* ��λ�������TCP���ݱ����ײ���ַ, ��ΪIPͷ�ײ��ĳ����ǿɱ�ģ����Ժû���������İ취�� */
			tcp_head = (struct TCP_Head*)((char*)ip_head + (ip_head->ver_ihl & 0x0f) * 4);

			/* �������㲻��TCPЭ��,����������ݰ��������˴�ѭ��*/
			if(ip_head->proto != TCP_PROTOCAL)
				continue;
			
			/* ��ǰ���TCP�����ײ�Դ��Ŀ�Ķ˿ںţ���Ϊ���ж�Ӧ�ò��Ƿ�ΪPOPЭ��*/
			u_short th_sport = ntohs(tcp_head->th_sport);
			u_short th_dport = ntohs(tcp_head->th_dport);

			/* ���TCP�����ײ���Դ�˿ں�Ϊ110���������ǰ���ݰ��Ǵ��ʼ������������ͻ��� */
			if(th_sport != POP3_PROTOCAL)
				continue;

			/* ���´�����free(pseudo_tcp_head)�����ж�TCP���ĵ�α�ײ��Ƿ���ȷ��
			   �������ȷ������˱��İ� */
			pseudo_tcp_head = build_pseudo_TCP_Head(ip_head);
			memset(ReceiveBuffer, 0, sizeof(ReceiveBuffer));
			memcpy(ReceiveBuffer, pseudo_tcp_head, sizeof(struct Pseudo_TCP_Head)); 
			memcpy(ReceiveBuffer + sizeof(struct Pseudo_TCP_Head), tcp_head, ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4);
			u_short tcp_checksum = tcp_check_sum((u_short*)ReceiveBuffer, sizeof(struct Pseudo_TCP_Head) + ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4);
			if(tcp_checksum != 0)
			{	
				/* ����3��Ϊע��ʱʹ��
				printf("tcp checksum is wrong.\n");
				printf("ether_capture_num = %d\n", ether_capture_num);
				printf("checksum = %x\n",tcp_checksum);*/
				free(pseudo_tcp_head);
				continue;
			}
			free(pseudo_tcp_head);

			/* filename�����ݸ�ʽΪĿ��IP_Ŀ��port_ԴIP_ԴPort���Ժ����Ǻ���������ɸ�Ϊ��ϣ����Ϊ��ϣ����*/
			filename = product_name(ip_head, th_sport, th_dport);

			/* printf����Ϊ����ʱʹ�� */
			//printf("ether_capture_num = %d\n", ether_capture_num); 
		
			if((tcp_head->th_flags & TCP_HEAD_SYN) &&
				(tcp_head->th_flags & TCP_HEAD_ACK))
			{
				tcp_stream_node = (struct TCP_STREAM*)malloc(sizeof(struct TCP_STREAM));
				tcp_data_frag_head = (struct TCP_DATA_FREGMENT*)malloc(sizeof(struct TCP_DATA_FREGMENT));

				/*��tcp_data_frag_head����ֵ*/
				tcp_data_frag_head->tcp_seq = ntohl(tcp_head->th_seq);
				tcp_data_frag_head->tcp_seq_next = ntohl(tcp_head->th_seq) + 1;
				tcp_data_frag_head->tcp_data_frag_len = 0;
				tcp_data_frag_head->tcp_data_next = NULL;

				/* ��tcp_stream_node�ĵ�1��2��3��6����Ա����ֵ */
				memset(tcp_stream_node->filename, 0, sizeof(tcp_stream_node->filename));
				memcpy(tcp_stream_node->filename, filename, sizeof(tcp_stream_node->filename));	//�˴����ܻ������⣬Ӧ�øĳ�Filename
				tcp_stream_node->finish_state = false;
				tcp_stream_node->finish_state_seq = 0;
				tcp_stream_node->tcp_data_frag_head = tcp_data_frag_head;

				/* tcp_stream_node����stream_node���� */
				insert_stream_node(tcp_stream_head ,tcp_stream_node);

				continue;
			} /* end if(tcp_head->th_flags & TCP_HEAD_SYN_ACK ) */

			/* ���TCP�����Ƿ��������У�
			   ������ڣ�exist_stream_node����NULL
			   ����ڣ�exist_stream_node���ش����ӵ�stream_node�ĵ�ַָ��
			*/
			struct TCP_STREAM* current_stream_node;
			current_stream_node = exist_stream_node(tcp_stream_head, filename);

			/* ����һ�ּ�����������ڰ�װʱ����ĳ̨�������ڽ����ʼ���״̬��
			   ����stream_node������û�д˽�㣬��������״̬�ı��Ĳ�Ҫ
			*/
			if(current_stream_node == NULL)
			{
				//printf("3@_@\n");
				continue;
			}
			
			
			/* ��¼tcp����4�λ��ֵĵ�1�λ��� */
			if( tcp_head->th_flags & TCP_HEAD_FIN )
			{
				//printf("test1\n");
				current_stream_node->finish_state = true;
				current_stream_node->finish_state_seq = ntohl(tcp_head->th_seq);
				continue;
			}/* end if(tcp_head->th_flags & TCP_HEAD_FIN) */

			/* �Ƿ���4�λ��ֵ����һ�����֣���������tcp_data_frag�����е�
			   ���н���е����ݴ����ļ��У����ͷ������е����н�㣬����tcp_data_frag_head
			   ����Ӧ��stream_node��㡣
			   ����������ǻ��ҵ�current_stream_node���ģ�
			   ��������˹���һ�������ڵĺ���������µĴ��뱻����
			*/
			if( current_stream_node->finish_state == true && 
				current_stream_node->finish_state_seq + 1 == ntohl(tcp_head->th_seq))
			{
				tcp_data_frag_head = current_stream_node->tcp_data_frag_head;
					
				/* tcp_data_fregment��������ȻΪ�� */
				if(tcp_data_frag_head->tcp_data_next == NULL)
				{
					//printf("1@_@\n");
					free(tcp_data_frag_head);
					delete_stream_node(tcp_stream_head,current_stream_node);
				}

				/* tcp_data_fregment�����в�Ϊ�գ���������Ҫд���ļ��� */
				if(tcp_data_frag_head->tcp_data_next != NULL)
				{
					struct TCP_DATA_FREGMENT* temp = tcp_data_frag_head->tcp_data_next;
					struct TCP_DATA_FREGMENT* delete_node;

					//printf("2@_@\n");
					if((store_pop_mail = fopen((char*)(current_stream_node->filename), "a+")) == NULL)
					{
						printf("cannot open the file writed.\n");
						exit(0);//�˴�������exit(0)����Ϊ�������ⲻӦ��Ӱ���������ݶεĴ�������֪��θģ���һ��Ҫ
					}

					/* �ѽ���е����ݴ����ļ������ͷŽ��ռ� */
					while(temp != NULL)
					{
						fwrite(&temp->tcp_data_frag[0], 1, temp->tcp_data_frag_len, store_pop_mail);
						delete_node = temp;
						temp = temp->tcp_data_next;
						free(delete_node);
					}
					fclose(store_pop_mail);

					free(tcp_data_frag_head);
					delete_stream_node(tcp_stream_head,current_stream_node);
				}/* end if(tcp_data_frag_head->tcp_data_next != NULL) */

				continue;
			}/* end if(current_stream_node->finish_state == true & current_stream_node->finish_state_seq + 1 == ntohl(tcp_head->th_seq))) */

			/* ���TCP���Ķ����ݲ��ֳ��ȣ��㷨��IP���ݱ������ݲ��ֳ��� - TCP�ײ����� */
			tcp_data_section_len = ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4 - TH_OFF(tcp_head) * 4;

			if(tcp_data_section_len != 0)
			{
				/* ������ش��İ����������
				   ��δ����Ƿǳ����õģ�tcp_data_frag_head->tcp_seq���������д���ļ����Ƕδ����йصģ��������档
				   �˴��жϵ��ش���ָ�������жϵ�������ݰ����Ѳ�����Ӳ���ļ���*/
				if(ntohl(tcp_head->th_seq) <= current_stream_node->tcp_data_frag_head->tcp_seq)
					continue;

				tcp_data_frag_node = (struct TCP_DATA_FREGMENT*)malloc(sizeof(struct TCP_DATA_FREGMENT));
				tcp_data_frag_node->tcp_seq = ntohl(tcp_head->th_seq);
				tcp_data_frag_node->tcp_data_frag_len = tcp_data_section_len;
				memset(tcp_data_frag_node->tcp_data_frag, 0, sizeof(tcp_data_frag_node->tcp_data_frag));
				u_int position = header->caplen - tcp_data_section_len;
				memcpy(tcp_data_frag_node->tcp_data_frag, &pkt_data[position], tcp_data_section_len); 

				/* ���д��������? 2013-8-22�ӵ�����ע��*/
				tcp_data_frag_head = current_stream_node->tcp_data_frag_head;

				/* ���tcp_data_fregment_node����Ϊ�գ���ֱ�Ӳ嵽tcp_data_frag_head����
				   ����ѭ�����ң����뵽���ʵ�λ�� */
				if(tcp_data_frag_head->tcp_data_next == NULL)
				{
					tcp_data_frag_head->tcp_data_next = tcp_data_frag_node;
					tcp_data_frag_node->tcp_data_prev = tcp_data_frag_node;
					tcp_data_frag_node->tcp_data_next = NULL;
					tcp_data_frag_head->tcp_data_frag_len++;
				}
				else
				{
					struct TCP_DATA_FREGMENT* current_data_frag_node = tcp_data_frag_head->tcp_data_next;
					while(current_data_frag_node != NULL)
					{
						/* ���������ָ��current_data_frag_node��ָ���������tcp���кţ�
						   ����tcp_data_fregment_node�е�tcp���кţ�����tcp_data_fregment_node�е�tcp����
						   Ϊ�ط������ݰ���ֱ�ӷ������ͷſռ� */
						if(current_data_frag_node->tcp_seq == tcp_data_frag_node->tcp_seq)
						{
							free(tcp_data_frag_node);
							break;
						}

						/* ����½������к�С�ڵ�ǰָ����ָ�������кţ�
						   ����½����뵽��ǰָ����ָ���֮ǰ */
						if(current_data_frag_node->tcp_seq > tcp_data_frag_node->tcp_seq)
						{
							current_data_frag_node->tcp_data_prev->tcp_data_next = tcp_data_frag_node;
							tcp_data_frag_node->tcp_data_prev = current_data_frag_node->tcp_data_prev;
							tcp_data_frag_node->tcp_data_next = current_data_frag_node;
							current_data_frag_node->tcp_data_prev = tcp_data_frag_node;
							tcp_data_frag_head->tcp_data_frag_len++;
							break;
						}

						/* �����ǰ�������к�С���½�����ţ����ҵ�ǰ������������е����һ�����ʱ��
						   ����½����뵽�������� */
						if(current_data_frag_node->tcp_seq < tcp_data_frag_node->tcp_seq &&
						   current_data_frag_node->tcp_data_next == NULL)
						{
							current_data_frag_node->tcp_data_next = tcp_data_frag_node;
							tcp_data_frag_node->tcp_data_prev = current_data_frag_node;
							tcp_data_frag_node->tcp_data_next = NULL;
							tcp_data_frag_head->tcp_data_frag_len++;
							break;
						}

						/* ������ɽ������кţ����ڵ�ǰ�������к���С�ڵ�ǰ������һ���������к�
						   ��Ͳ��뵽��ǰ����뵱ǰ������һ�������м�*/
						if(current_data_frag_node->tcp_seq < tcp_data_frag_node->tcp_seq &&
						   current_data_frag_node->tcp_data_next->tcp_seq > tcp_data_frag_node->tcp_seq)
						{
							tcp_data_frag_node->tcp_data_prev = current_data_frag_node;
							tcp_data_frag_node->tcp_data_next = current_data_frag_node->tcp_data_next;
							current_data_frag_node->tcp_data_next->tcp_data_prev = tcp_data_frag_node;
							current_data_frag_node->tcp_data_next = tcp_data_frag_node;
							tcp_data_frag_head->tcp_data_frag_len++;
							break;
						}

						current_data_frag_node = current_data_frag_node->tcp_data_next;

					}/* end while(current_data_frag_node != NULL) */
				}/* end else */
			}/* end if(tcp_data_section_len != 0) */

			/* �ж������еĽ���Ƿ�Ҫ�����ļ�,�˴�������Щ���ӣ�д�ɺ�����
			   ע��1�������5ֻ��һ����ֵ��Ҳ���Ը�Ϊ7��11�ȣ��Ҿ���������5���ʣ�ֻ��ֱ��
			*/
			if(current_stream_node->tcp_data_frag_head->tcp_data_next != NULL &&
			   current_stream_node->tcp_data_frag_head->tcp_data_frag_len >= 5)
			{
				tcp_data_frag_head = current_stream_node->tcp_data_frag_head;
				struct TCP_DATA_FREGMENT* temp = tcp_data_frag_head->tcp_data_next;
				struct TCP_DATA_FREGMENT* delete_node;

				if((store_pop_mail = fopen((char*)(current_stream_node->filename), "a+")) == NULL)
				{
					printf("cannot open the store file.\n");
					exit(0);//�˴�������exit(0)����Ϊ�������ⲻӦ��Ӱ���������ݶεĴ�������֪��θģ���һ��Ҫ
				}

				while(tcp_data_frag_head->tcp_data_frag_len != 0)
				{
					if(tcp_data_frag_head->tcp_seq_next == temp->tcp_seq)
					{
						fwrite(&temp->tcp_data_frag[0], 1, temp->tcp_data_frag_len, store_pop_mail);
						tcp_data_frag_head->tcp_seq = temp->tcp_seq;
						tcp_data_frag_head->tcp_seq_next = temp->tcp_seq_next;
						tcp_data_frag_head->tcp_data_next = temp->tcp_data_next;
						delete_node = temp;
						temp = temp->tcp_data_next;
						free(delete_node);
						tcp_data_frag_head->tcp_data_frag_len--;
					}
					else
					{
						break;
					}
				}/* end while(tcp_data_frag_head->tcp_data_frag_len != 0) */

				fclose(store_pop_mail);
			} /* end xxx != NULL & yyy >= 5 & zzz == true) */

		if (res == -1)
		{
			printf("Error reading the packets: %s\n", pcap_geterr(fp));
		}


		}//������while(res)��
	} /* end if(pcap_datalink_val_to_name(pcap_datalink(fp) == 1)) */
	else
	{
		printf("this is not the Ethernet V2 standard.\n");
	}
	
	printf("��ȡ�ʼ����ݽ���\n");
	
	/*
	int xox;
	scanf("%d",&xox);
	����ʱʹ��
	*/
	return 0;
}
