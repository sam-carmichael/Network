/*************************************************
版本：EMR 0.0.1
作者：李德新
日期：2013-5-3
描述：此程序处理对象为格式.pcap的文件，把文件中包含的以pop3协议
      传输的应用层中的所有数据抽取出来，并存入另一个文件中。
**************************************************/
#include "header_struct.h"

#define LINE_LEN 16
#define LINE_BETWEEN 8

char Filename[51]="";	/* 用在product_name函数中，文件名的形式为：目的IP_目的port_源IP_源Port.txt */

/* product_name函数的作用
   用于生成唯一标识的文件名，
   文件名形如：目的IP_目的port_源IP_源Port.txt
*/
char* product_name(struct IP_Header* ip_head, u_short th_sport, u_short th_dport){

	char str[6];					//用于对端口的数字转字符串类的转换
	u_int position = 0;
	int pos;
	int temp;						//在转换完整文件名中要用到

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

/* 用于生成伪TCP首部*/
Pseudo_TCP_Head* build_pseudo_TCP_Head(IP_Header* ip_head){

	//如果使用Pseudo_TCP_Head temp, 则在返回栈中的地址会被覆盖，所以要用指针。但记得要释放。
	Pseudo_TCP_Head* temp = (Pseudo_TCP_Head*)malloc(sizeof(struct Pseudo_TCP_Head));

	temp->daddr = ip_head->daddr;
	temp->saddr = ip_head->saddr;
	temp->protocal_value = htons((u_short)(ip_head->proto));

	//因为tcp_len是要用在检验和上，所以此处是否应该网络与主机字符序转换呢？先用这个试试再说
	temp->tcp_len =(u_short)(htons((ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4)));
	
	return temp;	
}


/* 用于检验TCP的checksum值，传入参数：
   第一个参数：待检测的缓冲区
   第二个参数：整个TCP段的长度，长度单位是字节
   算法：二进制反码运算求和   
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

/* 检查以filename为名的结点是否存在于stream_node链表中，如果存在则返回其结点的指针，或不存在则返回空值NULL */
struct TCP_STREAM* exist_stream_node(struct TCP_STREAM* stream_head, char* filename){

	struct TCP_STREAM* temp = stream_head->tcp_stream_prev;	/* 把stream_node链表中的第一个结点的地址给temp */
	
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

/* 删除stream_node结点 */
void delete_stream_node(struct TCP_STREAM* stream_head, struct TCP_STREAM* current_stream_node){
	if((current_stream_node->tcp_stream_prev == stream_head) && 
	   (current_stream_node->tcp_stream_next == NULL))
	{
    	/* 情况1:当前stream_node链表中只有一个stream_node结点，stream_head指针中的tcp_stream_head
	       与tcp_stream_tail都指向这一个sream_node结点 */
		stream_head->tcp_stream_prev = NULL;	//头结点的首指针指向空
		stream_head->tcp_stream_next = NULL;	//头结点的尾指针指向空
		free(current_stream_node);//这个地方没设防御性处理，查一下资料，一定要加上
	}
	else if((current_stream_node->tcp_stream_prev != stream_head) &&
	        (current_stream_node->tcp_stream_next == NULL))
	{
		/* 情况2:当前stream_node链表中有大于等于2个以上的stream_node链点，
	         且要删除的stream_node结点是最后一个结点 */
		current_stream_node->tcp_stream_prev->tcp_stream_next = NULL;
		stream_head->tcp_stream_next = current_stream_node->tcp_stream_prev;
		free(current_stream_node);//这个地方没设防御性处理，查一下资料，一定要加上
	}
	else if((current_stream_node->tcp_stream_prev == stream_head) &&
	        (current_stream_node->tcp_stream_next != NULL))
	{
		/* 情况3:当前stream_node链表中有大于等于2个以上的stream_node链表，
	         且要删除的stream_node结点是链表中的第一个stream_node结点 */
		current_stream_node->tcp_stream_next->tcp_stream_prev = stream_head; 
		stream_head->tcp_stream_prev = current_stream_node->tcp_stream_next;
		free(current_stream_node);//这个地方没设防御性处理，查一下资料，一定要加上
	}
	else if((current_stream_node->tcp_stream_prev != stream_head) &&
	        (current_stream_node->tcp_stream_next != NULL))
	{
		/* 情况4:当前stream_node链表中有大于等于2个以上的stream_node链表，
	         且要删除的stream_node结点不是第一个也不是最后一个stream_node结点 */
		current_stream_node->tcp_stream_prev->tcp_stream_next = current_stream_node->tcp_stream_next;
		current_stream_node->tcp_stream_next->tcp_stream_prev = current_stream_node->tcp_stream_prev;
		free(current_stream_node);//这个地方没设防御性处理，查一下资料，一定要加上
	}
}

/* 在steam_node链表中插入一个stream_node, 插入方法：顺序插入 */
void insert_stream_node(struct TCP_STREAM* stream_head, struct TCP_STREAM* current_stream_node){
	/* 如果stream_node是空的(则整个链表都是空的)，插入到第一个位置，否则就插入最后一个位置 */
	if(stream_head->tcp_stream_prev == NULL)
	{	
		//printf("@_@\n");
		stream_head->tcp_stream_prev = current_stream_node;
		stream_head->tcp_stream_next = current_stream_node;
		current_stream_node->tcp_stream_prev = stream_head;	/* 此处代码没有 */
		current_stream_node->tcp_stream_next = NULL;
	}
	else	//此处代码没有还被测试到
	{
		struct TCP_STREAM* temp = stream_head->tcp_stream_next;
		current_stream_node->tcp_stream_next = temp;
		current_stream_node->tcp_stream_prev = stream_head;
		temp->tcp_stream_prev = current_stream_node;
		stream_head->tcp_stream_next = current_stream_node;
		/*以下5行的代码于2013-8-22注释得，修改版见上
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
	u_int res;						//接收pcap_next_ex()函数的返回值
	u_int ether_capture_num = 0;	//统计文件中链接层包的个数
	u_int tcp_data_section_len = 0;		//统计每个TCP报文段数据部分的长度，即如果有应该层协议则非零，如果没有应用层协议则为零
	struct Ethernet_Header* eth_head;
	struct IP_Header* ip_head;
	struct TCP_Head* tcp_head;
	struct Pseudo_TCP_Head* pseudo_tcp_head;
	FILE *store_pop_mail;
	u_char ReceiveBuffer[1600];		//用于tcp_checksum时使用
	char* filename;

	/* 注意tcp_stream_head结点，是一个空结点，它存链表中的第一个结点指针
	   与最后一个指针，tcp_stream_prev指向头结点，tcp_stream_next指向尾结点 */
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

	/* 根据新WinPcap语法创建一个源字符串 */
	if ( pcap_createsrcstr( source,         // 源字符串
		PCAP_SRC_FILE,						// 我们要打开的文件为本地文件
		NULL,								// 远程主机
		NULL,								// 远程主机端口
		argv[1],							// 我们要打开的文件名
		errbuf								// 错误缓冲区
		) != 0)
	{
		fprintf(stderr,"\nError creating a source string\n");
		return -1;
	}

	/* 打开捕获文件 */
	if ( (fp= pcap_open(source,				 // 设备名
		65536,								 // 要捕捉的数据包的部分
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,			 // 混杂模式
		1000,								// 读取超时时间
		NULL,								// 远程机器验证
		errbuf								// 错误缓冲池
		) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", source);
		return -1;
	}
	
	/* 输出链路层类型 */
	printf("pcap_datalink = %s_%s\n",pcap_datalink_val_to_description(pcap_datalink(fp)), pcap_datalink_val_to_name(pcap_datalink(fp)));  
	printf("开始提取邮件数据,请等待......\n");

	/* 如果是以太网，则进行处理 */
	if(pcap_datalink_val_to_name(pcap_datalink(fp) == 1))
	{
		/* 从文件获取数据包,while循环表示只到文件全部读取结束，才停止循环 */
		while((res = pcap_next_ex(fp, &header, &pkt_data)) !=  PCAP_FILE_EOF)
		{
			//bool finish_state = false;

			/* 在此处要加一个判断，len == caplen, 如果不相等则记录是哪个包没抓好，有多少个这样的包 */

			/* 统计文件中有多少个帧*/
			ether_capture_num++;
			
			/* 定位数据链路层的首部地址 */
			eth_head = (struct Ethernet_Header*)pkt_data;

			/* 定位网络层中IP数据报的首部地址 */
			ip_head = (struct IP_Header*)((char*)eth_head + sizeof(struct Ethernet_Header));

			/* 定位传输层中TCP数据报的首部地址, 因为IP头首部的长度是可变的，所以好还是有下面的办法求 */
			tcp_head = (struct TCP_Head*)((char*)ip_head + (ip_head->ver_ihl & 0x0f) * 4);

			/* 如果传输层不是TCP协议,则放弃其数据包，结束此次循环*/
			if(ip_head->proto != TCP_PROTOCAL)
				continue;
			
			/* 提前求出TCP报文首部源与目的端口号，是为了判断应用层是否为POP协议*/
			u_short th_sport = ntohs(tcp_head->th_sport);
			u_short th_dport = ntohs(tcp_head->th_dport);

			/* 如果TCP报文首部的源端口号为110，则表明当前数据包是从邮件服务器发到客户端 */
			if(th_sport != POP3_PROTOCAL)
				continue;

			/* 以下代码至free(pseudo_tcp_head)都是判断TCP报文的伪首部是否正确，
			   如果不正确则放弃此报文包 */
			pseudo_tcp_head = build_pseudo_TCP_Head(ip_head);
			memset(ReceiveBuffer, 0, sizeof(ReceiveBuffer));
			memcpy(ReceiveBuffer, pseudo_tcp_head, sizeof(struct Pseudo_TCP_Head)); 
			memcpy(ReceiveBuffer + sizeof(struct Pseudo_TCP_Head), tcp_head, ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4);
			u_short tcp_checksum = tcp_check_sum((u_short*)ReceiveBuffer, sizeof(struct Pseudo_TCP_Head) + ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4);
			if(tcp_checksum != 0)
			{	
				/* 以下3行为注释时使用
				printf("tcp checksum is wrong.\n");
				printf("ether_capture_num = %d\n", ether_capture_num);
				printf("checksum = %x\n",tcp_checksum);*/
				free(pseudo_tcp_head);
				continue;
			}
			free(pseudo_tcp_head);

			/* filename的内容格式为目的IP_目的port_源IP_源Port，以后若是海量数据则可改为哈希，因为哈希够快*/
			filename = product_name(ip_head, th_sport, th_dport);

			/* printf代码为调试时使用 */
			//printf("ether_capture_num = %d\n", ether_capture_num); 
		
			if((tcp_head->th_flags & TCP_HEAD_SYN) &&
				(tcp_head->th_flags & TCP_HEAD_ACK))
			{
				tcp_stream_node = (struct TCP_STREAM*)malloc(sizeof(struct TCP_STREAM));
				tcp_data_frag_head = (struct TCP_DATA_FREGMENT*)malloc(sizeof(struct TCP_DATA_FREGMENT));

				/*给tcp_data_frag_head赋初值*/
				tcp_data_frag_head->tcp_seq = ntohl(tcp_head->th_seq);
				tcp_data_frag_head->tcp_seq_next = ntohl(tcp_head->th_seq) + 1;
				tcp_data_frag_head->tcp_data_frag_len = 0;
				tcp_data_frag_head->tcp_data_next = NULL;

				/* 给tcp_stream_node的第1、2、3、6个成员赋初值 */
				memset(tcp_stream_node->filename, 0, sizeof(tcp_stream_node->filename));
				memcpy(tcp_stream_node->filename, filename, sizeof(tcp_stream_node->filename));	//此处可能会有问题，应该改成Filename
				tcp_stream_node->finish_state = false;
				tcp_stream_node->finish_state_seq = 0;
				tcp_stream_node->tcp_data_frag_head = tcp_data_frag_head;

				/* tcp_stream_node插入stream_node链表 */
				insert_stream_node(tcp_stream_head ,tcp_stream_node);

				continue;
			} /* end if(tcp_head->th_flags & TCP_HEAD_SYN_ACK ) */

			/* 求此TCP链接是否在链表中，
			   如果不在，exist_stream_node返回NULL
			   如果在，exist_stream_node返回此链接的stream_node的地址指针
			*/
			struct TCP_STREAM* current_stream_node;
			current_stream_node = exist_stream_node(tcp_stream_head, filename);

			/* 这是一种极端情况，即在安装时已有某台机器处于接收邮件的状态，
			   而在stream_node链表中没有此结点，所以这种状态的报文不要
			*/
			if(current_stream_node == NULL)
			{
				//printf("3@_@\n");
				continue;
			}
			
			
			/* 记录tcp链接4次挥手的第1次挥手 */
			if( tcp_head->th_flags & TCP_HEAD_FIN )
			{
				//printf("test1\n");
				current_stream_node->finish_state = true;
				current_stream_node->finish_state_seq = ntohl(tcp_head->th_seq);
				continue;
			}/* end if(tcp_head->th_flags & TCP_HEAD_FIN) */

			/* 是否是4次挥手的最后一个挥手，如果是则把tcp_data_frag链表中的
			   所有结点中的数据存入文件中，并释放链表中的所有结点，还有tcp_data_frag_head
			   与相应的stream_node结点。
			   正常情况下是会找到current_stream_node结点的，
			   但如果有人构造一个不存在的合理包，以下的代码被攻击
			*/
			if( current_stream_node->finish_state == true && 
				current_stream_node->finish_state_seq + 1 == ntohl(tcp_head->th_seq))
			{
				tcp_data_frag_head = current_stream_node->tcp_data_frag_head;
					
				/* tcp_data_fregment链表中已然为空 */
				if(tcp_data_frag_head->tcp_data_next == NULL)
				{
					//printf("1@_@\n");
					free(tcp_data_frag_head);
					delete_stream_node(tcp_stream_head,current_stream_node);
				}

				/* tcp_data_fregment链表中不为空，即有数据要写入文件中 */
				if(tcp_data_frag_head->tcp_data_next != NULL)
				{
					struct TCP_DATA_FREGMENT* temp = tcp_data_frag_head->tcp_data_next;
					struct TCP_DATA_FREGMENT* delete_node;

					//printf("2@_@\n");
					if((store_pop_mail = fopen((char*)(current_stream_node->filename), "a+")) == NULL)
					{
						printf("cannot open the file writed.\n");
						exit(0);//此处不能用exit(0)，因为这类问题不应该影响其他数据段的处理，但不知如何改，但一定要
					}

					/* 把结点中的数据存入文件，并释放结点空间 */
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

			/* 求出TCP报文段数据部分长度，算法：IP数据报的数据部分长度 - TCP首部长度 */
			tcp_data_section_len = ntohs(ip_head->tlen) - (ip_head->ver_ihl & 0x0f) * 4 - TH_OFF(tcp_head) * 4;

			if(tcp_data_section_len != 0)
			{
				/* 如果是重传的包，则放弃。
				   这段代码是非常有用的，tcp_data_frag_head->tcp_seq是与把数据写入文件的那段代码有关的，在最下面。
				   此处判断的重传是指，现在判断的这个数据包，已插入了硬盘文件中*/
				if(ntohl(tcp_head->th_seq) <= current_stream_node->tcp_data_frag_head->tcp_seq)
					continue;

				tcp_data_frag_node = (struct TCP_DATA_FREGMENT*)malloc(sizeof(struct TCP_DATA_FREGMENT));
				tcp_data_frag_node->tcp_seq = ntohl(tcp_head->th_seq);
				tcp_data_frag_node->tcp_data_frag_len = tcp_data_section_len;
				memset(tcp_data_frag_node->tcp_data_frag, 0, sizeof(tcp_data_frag_node->tcp_data_frag));
				u_int position = header->caplen - tcp_data_section_len;
				memcpy(tcp_data_frag_node->tcp_data_frag, &pkt_data[position], tcp_data_section_len); 

				/* 下行代码的作用? 2013-8-22加的这行注释*/
				tcp_data_frag_head = current_stream_node->tcp_data_frag_head;

				/* 如果tcp_data_fregment_node链表为空，则直接插到tcp_data_frag_head后面
				   否则循环查找，插入到合适的位置 */
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
						/* 如果链表中指针current_data_frag_node所指的这个结点的tcp序列号，
						   等于tcp_data_fregment_node中的tcp序列号，则表达tcp_data_fregment_node中的tcp报文
						   为重发的数据包，直接放弃，释放空间 */
						if(current_data_frag_node->tcp_seq == tcp_data_frag_node->tcp_seq)
						{
							free(tcp_data_frag_node);
							break;
						}

						/* 如果新结点的序列号小于当前指针所指结点的序列号，
						   则把新结点插入到当前指针所指结点之前 */
						if(current_data_frag_node->tcp_seq > tcp_data_frag_node->tcp_seq)
						{
							current_data_frag_node->tcp_data_prev->tcp_data_next = tcp_data_frag_node;
							tcp_data_frag_node->tcp_data_prev = current_data_frag_node->tcp_data_prev;
							tcp_data_frag_node->tcp_data_next = current_data_frag_node;
							current_data_frag_node->tcp_data_prev = tcp_data_frag_node;
							tcp_data_frag_head->tcp_data_frag_len++;
							break;
						}

						/* 如果当前结点的序列号小于新结点的序号，并且当前结点已是链表中的最后一个结点时，
						   则把新结点插入到链表的最后 */
						if(current_data_frag_node->tcp_seq < tcp_data_frag_node->tcp_seq &&
						   current_data_frag_node->tcp_data_next == NULL)
						{
							current_data_frag_node->tcp_data_next = tcp_data_frag_node;
							tcp_data_frag_node->tcp_data_prev = current_data_frag_node;
							tcp_data_frag_node->tcp_data_next = NULL;
							tcp_data_frag_head->tcp_data_frag_len++;
							break;
						}

						/* 如果生成结点的序列号，大于当前结点的序列号且小于当前结点的下一个结点的序列号
						   则就插入到当前结点与当前结点的下一个结点的中间*/
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

			/* 判断链表中的结点是否要存入文件,此处处理有些复杂，写成函数吧
			   注意1：这里的5只是一个阀值，也可以改为7，11等，我觉得是质数5合适，只是直觉
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
					exit(0);//此处不能用exit(0)，因为这类问题不应该影响其他数据段的处理，但不知如何改，但一定要
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


		}//可能是while(res)的
	} /* end if(pcap_datalink_val_to_name(pcap_datalink(fp) == 1)) */
	else
	{
		printf("this is not the Ethernet V2 standard.\n");
	}
	
	printf("提取邮件数据结束\n");
	
	/*
	int xox;
	scanf("%d",&xox);
	测试时使用
	*/
	return 0;
}
