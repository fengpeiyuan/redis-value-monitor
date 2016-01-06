#include "monitor.h"

/*
 * banner
 */
void show_banner(void){
	fprintf(stdout,"%s - %s\n", APP_NAME, APP_DESC);
	fprintf(stdout,"\n");
	return;
}

/*
 * help
 */
void show_usage(void){
	printf("Usage: %s", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("-i  listen on <interface> for packets.\n");
	printf("-p  listen on redis port.\n");
	printf("-m  max value by byte, greater then it will be printed.\n");
	printf("\n");
	return;
}

/*
 * print char in line
 * */
void print_line(const u_char *start,int len){
	int i;
	for(i = 0; i < len; i++) {
			if (isprint(*start))
				fprintf(stdout, "%c", *start);
			else
				fprintf(stdout, ".");
			start++;
	}
}

/**
 * parse redis write command protocal
 */
void parse_redis_payload(const u_char *payload, int payload_len, char *src_ip, char *dst_ip, int src_port, int dst_port,int value_max_len){
	/*print_line(payload,payload_len);
	printf("\n");*/
	const u_char *start = payload;
	int count_len = 0;
	const u_char *cmd = NULL;
	int cmd_len = 0;
	const u_char *key = NULL;
	int key_len = 0;
	int parse_len = 0;
	int part_len = 0;
	int i = 0;
	char *cmd_set = "SET";
	char *cmd_hset = "HSET";

	if(payload_len>SNAP_LEN || payload_len<=0)
		return;
	/*parse*/
	if(*start++ == '*'){
		parse_len ++;
		/*parse count*/
		while(*start != '\r'){
			if(*start >= '0' && *start <= '9'){
				count_len = (count_len * 10) + (*start - '0');
			}
			start ++;
			parse_len ++;
		}
		start += 2; /*add 2 means add \r\n 2 char, no other value char skip */
		parse_len += 2;

		if(count_len<=1)
			return;
		if(parse_len >= payload_len|| parse_len <= 0){
			fprintf(stderr, "Error! count parse lengh:%d,payload lengh:%d",parse_len,payload_len);
			print_line(payload,payload_len);
			fprintf(stderr,"\n");
			return;
		}


		/*cmd parse*/
		if(*start++ == '$'){
			parse_len ++;
			while(*start != '\r'){
				if(*start >= '0' && *start <= '9'){
					cmd_len = (cmd_len * 10) + (*start - '0');
				}
				start ++;
				parse_len ++;
			}
			if(cmd_len<=0)
				return;

			start += 2; /*add 2 char of '\r\n' */
			cmd = start;
			/*printf("cmd:%c \n",*cmd);*/
			start += (cmd_len + 2); /*add 2 char of '\r\n' */
			parse_len += (cmd_len + 4);

			/*only these cmd be parsed, other return
			printf("cmd:%d",strncmp((const char *)cmd,cmd_set,cmd_len));*/
			if(strncmp((const char *)cmd,cmd_set,cmd_len) != 0 &&
			   strncmp((const char *)cmd,cmd_hset,cmd_len) != 0
			)
				return;


			/*length check*/
			if(parse_len >= payload_len || parse_len <= 0){
					fprintf(stderr,"End of this payload in cmd parse! parse lengh:%d,payload lengh:%d",parse_len,payload_len);
					print_line(payload,payload_len);
					fprintf(stderr,"\n");
					return;
			}

		}


		/*value,field-value parse*/
		if(strncmp((const char *)cmd,cmd_set,cmd_len)==0){ /*SET command*/
			for(i=0;i<count_len-1;i++){
				if(*start++ == '$'){
					parse_len ++;
					int value_len = 0;

					while(*start != '\r'){
						if(*start >= '0' && *start <= '9'){
								part_len = (part_len * 10) + (*start - '0');
						}
						start ++;
						parse_len ++;
					}
					if(part_len<=0)
						return;

					start += 2; /*add 2 char of '\r\n' */
					if(i%2==0){
						key_len = part_len;
						key = start;
						/*printf("key:%c \n",*key);*/
					}else if(i%2==1){
						value_len = part_len;
					}
					start += (part_len + 2); /*add 2 char of '\r\n' */
					parse_len += (part_len + 4);

					/*clear everytime*/
					part_len = 0;

					/*print*/
					if(value_len > value_max_len){
						/*printf("count_len:%d,cmd_len:%d,key_len:%d,value_len:%d \n",count_len,cmd_len,key_len,value_len);*/
						fprintf(stdout, "%s:%d -> %s:%d	%d	",src_ip,src_port,dst_ip,dst_port,value_len);
						print_line(cmd,cmd_len);
						fprintf(stdout, "	");
						print_line(key,key_len);
						fprintf(stdout, "\n");
					}

					if(parse_len >= payload_len || parse_len <= 0){
						/*
						fprintf(stderr,"End of this payload in value/field-value parse! parse lengh:%d,payload lengh:%d",parse_len,payload_len);
						print_line(payload,payload_len);
						fprintf(stderr,"\n");
						*/
						return;
					}


				}

			}


		}else if(strncmp((const char *)cmd,cmd_hset,cmd_len)==0){
								print_line(cmd,cmd_len);
								printf("--MSET\n");
		}



	}

	return;
}

void get_ip_host(char *ip_host){
	struct ifaddrs *addrs, *tmp;
	char *lo = "127.0.0.1";
	int status = getifaddrs(&addrs);
	if (status != 0){
	    return;
	}

	tmp = addrs;
	while (tmp){
	    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
	        struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
	        if(strncmp(lo,inet_ntoa(pAddr->sin_addr),3)!=0){
	        	/*printf("###%s\n",inet_ntoa(pAddr->sin_addr));*/
	        	char *ip = inet_ntoa(pAddr->sin_addr);
	        	strncpy(ip_host,ip,16);
	        }
	    }
	    tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);
	return;
}

/*
 * pop packet
 */
void pop_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct header_ethernet *headerethernet;  /* The ethernet header [1] */
	const struct header_ip *headerip;              /* The IP header */
	const struct header_tcp *headertcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */
	int size_ip;
	int size_tcp;
	int size_payload;
	char ip_host[20];
	memset(ip_host, '\0', sizeof(ip_host));

	headerethernet = (struct header_ethernet*)(packet);
	headerip = (struct header_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(headerip)*4;
	if (size_ip < 20) {
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	/*printf("From: %s,To: %s\n", inet_ntoa(headerip->ip_src),inet_ntoa(headerip->ip_dst));
	switch(headerip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}*/
	if(headerip->ip_p != IPPROTO_TCP){
		fprintf(stderr, "Protocal is not TCP, return\n");
		return;
	}
	headertcp = (struct header_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(headertcp)*4;
	if (size_tcp < 20) {
		fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	/*printf("Src port: %d,Dst port: %d\n", ntohs(headertcp->th_sport),ntohs(headertcp->th_dport));*/
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(headerip->ip_len) - (size_ip + size_tcp);
	
	/*fprintf(stderr, "%s,%s",inet_ntoa(headerip->ip_src),inet_ntoa(headerip->ip_dst));
	*/

	if (size_payload > 0) {
		/*printf("Payload (%d bytes):\n", size_payload);*/
		get_ip_host(ip_host);
		parse_redis_payload(payload, size_payload, inet_ntoa(headerip->ip_src), ip_host,
				ntohs(headertcp->th_sport),ntohs(headertcp->th_dport),maxvalue);
	}

	return;
}

int is_number(char *ch,size_t len){
	size_t l = 0;
	while(l<len){
		if(!isdigit(ch[l])){
			return 0;
		}
		l++;
	}
	return 1;
}


int main(int argc, char **argv)
{
	while((opt=getopt_long(argc,argv,"i:p:m:?hv",long_options,&options_index))!=EOF ){
	  switch(opt) {
	   case  0 : break;
	   case 'i':
		   	   interface=optarg;break;
	   case 'p':
		   	     port=optarg;
	   	   	   	 if(!is_number(port,strlen(port))){
	   	   	   		 printf("port(p) must be number!");
	   	   	   		 return 2;
	   	   	   	 }
	   	   	   	 break;
	   case 'm':
		   	   	 maxvalue=atoi(optarg);
		   	   	 if(maxvalue<0){
		   	   		 printf("maxvalue must be greater then zero!");
		   	   		 return 2;
		   	   	 }
		   	   	 break;
	   case 'v': printf(APP_VERSION"\n");exit(0);
	   case ':':
	   case 'h':
	   case '?': show_usage();return 2;break;
	  }
	 }


	 char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	 pcap_t *handle;
	 char filter_exp[] = "tcp port ";
	 if(port == NULL){
		 fprintf(stderr, "Please set port using -p first.\n");
		 exit(EXIT_FAILURE);
	 }
	 strcat(filter_exp,port);
	 /*printf("filter_exp:%s",filter_exp);*/
	 struct bpf_program fp;			/* compiled filter program (expression) */
	 bpf_u_int32 mask;			/* subnet mask */
	 bpf_u_int32 net;			/* ip */

	 show_banner();

	if (interface == NULL){
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",interface, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", interface);
	/*printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);*/

	handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
	/*dev*/
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(EXIT_FAILURE);
	}

	/*filter*/
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, -1, pop_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nComplete.\n");

	return 0;
}

