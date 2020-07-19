#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define PATHR "/usr/share/Spectre/wordlist.txt" // Wordlist para bruteforce em dominios
#define TOTAL_PACKETS_ICMP 2        // Quantidade de pacotes que sera enviado
#define ETH_ALEN	6				// Tamanho de um endereço ethernet
#define ETH_HLEN	14				// Tamanho total do cabeçalho ethernet
#define	ETH_FRAME_LEN	1514		// Tamanho total de um quadro ethernet
#define ETH_DATA_LEN	1500

// Cabeçalho ARP
struct arp_hdr{
	unsigned short _hardware_type;				// Tipo de hardware (ethernet = 1)
	unsigned short _protocol_type;				// Tipo do protocolo (ipv4 = 0x800)
	unsigned char _hardware_address_length;		// Tamanho do hardware (ethernet = 6)
	unsigned char _protocol_address_length;		// Tamanho do protocolo (ipv4 = 4)
	unsigned short _opcode;						// Operação (1 = ARP request / 2 = ARP reply)
	unsigned char _src_mac[ETH_ALEN];			// Endereço MAC de origem
	unsigned char _src_ip[4];					// Endereço IP de origem
	unsigned char _dest_mac[ETH_ALEN];			// Endereço MAC de destino (0x00 caso seja ARP request)
	unsigned char _dest_ip[4];					// Endereço IP de destino
	char fill[18];								// O pacote ARP é menor que 64 bytes, aqui preenche para 64
};

struct hostent *host; // Resoluçao de dns
struct sockaddr_in target , dst_addr , src_addr; // Origem,destino e alvo
struct timeval timeout; // Timeout do socket
struct icmphdr icmph; // Cabeçalho ICMP

// Estruturas para pacote ARP
struct in_addr in; // Endereço IP de origem
struct in_addr dest; // Endereço IP de destino
struct sockaddr destino; // Destino do pacote
struct arp_hdr *pacote_arp; // Pacote ARP
struct ethhdr *ethernet_hdr; // Cabeçalho ethernet

char *get_ip(char *host_name);
void dns_enum(char *domain , char *wordlist);
int port_scan(char *ip , int port);
unsigned short checksum(void *b, int len);
int ping(char *ip);
int arp_scan(char *ip , char *buf , const char *my_addr , const char *device , const char *mac_src);
char *get_local_addr(char *device);
char *network(char *net);
void help(char *progname);

int main(int argc , char *argv[])
{
    // Verifica a entreada do usuario
    if(argc < 2)
    {
        help(argv[0]);
        return 1;
    }
    else if(getuid() != 0)
    {
        fprintf(stderr , "> Para executar este software é necessario root.\n");
        return 126;
    }

    int status;

    // Processando os argumentos
    if(argc == 2 && strlen(argv[1]) > 8)
    {
        printf("> Scanning: %s\n\n",get_ip(argv[1]));
        for(int i = 20; i <= 1000; ++i)
        {
            status = port_scan(get_ip(argv[1]) ,i);
            if(status == 1) printf("> Porta %i [ABERTA].\n",i);
            else if(status == -1) fprintf(stderr, "> [ERRO]: Erro ao crir socket.\n");
        }
    }
    else if(strcmp("-p" , argv[1]) == 0 && argc > 3)
    {
        printf("> Scanning: %s\n\n",get_ip(argv[2]));
        for(int i = 1; i <= (argc - 3); ++i)
        {
            status = port_scan(get_ip(argv[2]) ,atoi(argv[2 + i]));
            if(status == 1) printf("> Porta %i [ABERTA].\n",atoi(argv[2 + i]));
            else if(status == -1) fprintf(stderr , "> [ERRO]: Erro ao criar socket.\n");
            else printf("> Porta %i [FECHADA].\n",atoi(argv[2 + i]));
        }
    }
    else if(strcmp("-ap" , argv[1]) == 0 && argc == 3)
    {
        printf("> Scanning: %s\n\n",get_ip(argv[2]));
        for(int i = 1; i <= 65535; ++i)
        {
            status = port_scan(get_ip(argv[2]) ,i);
            if(status == 1) printf("> Porta %i [ABERTA].\n",i);
            else if(status == -1) fprintf(stderr , "> [ERRO]: Erro ao criar socket.\n");
        }
    }
    else if(strcmp("-r" , argv[1]) == 0 && argc == 3)
    {
        char *result =  get_ip(argv[2]);
        if(result != NULL) printf("> Host: %s ---> IP: %s\n",argv[2], result);
        else printf("> Não foi possivel resolver: %s\n",argv[2]);
    }
    else if(strcmp("-e" , argv[1]) == 0 && argc == 4) dns_enum(argv[2] , argv[3]);
    else if(strcmp("-e" , argv[1]) == 0 && argc == 3) dns_enum(argv[2] , PATHR);
    else if(strcmp("-ps" , argv[1]) == 0 && argc == 3)
    {
        char *rede = network(argv[2]);
        char result[30] , ip[30];
        strncpy(result , rede , strlen(rede) -1);
        result[strlen(rede) - 1] = '\0';
        printf("> Scanning: %s\n\n",rede);

        for(int i = 1; i <= 254; ++i)
        {
            sprintf(ip , "%s%i" , result , i);
            status = ping(ip);
            if(status == 1) printf("> Host ativo: %s\n",ip);
            else if(status == -1) fprintf(stderr , "> [ERRO]: Erro ao criar socket.\n");
        }

    }
    else if(strcmp("-as" , argv[1]) == 0 && argc == 5)
    {
        printf("> Scanning: %s\n\n" , argv[2]);
        char buff[40];
        status = arp_scan(argv[2] , buff , get_local_addr(argv[3]) , argv[3] , argv[4]);
        if(status == 1) printf("[IP]: %s [MAC]: %s\n" , argv[2]  , buff);
        else if(status == -1) fprintf(stderr , "> [ERRO]: %s\n" , buff);
        else printf("> %s\n",buff);
    }
    else if(strcmp("-as-all" , argv[1]) == 0 && argc == 4)
    {
        char result[30] , ip[30] , buff[40];
        char *rede = network(get_local_addr(argv[2]));
        printf("> Scanning: %s\n\n",rede);

        strncpy(result , rede , strlen(rede) - 1);
        for(int i = 1; i <= 254;++i)
        {
            sprintf(ip , "%s%i" , result , i);
            status = arp_scan(ip , buff , get_local_addr(argv[2])  , argv[2] , argv[3]);
            if(status == 1) printf("[IP]: %s [MAC]: %s\n", ip , buff);
            else if(status == -1) fprintf(stderr , "> [ERRO]: %s\n" , buff);
        }

    }
    else
    {
        help(argv[0]);
        return 1;
    }

    return 0;
}

// Faz a resolução do nome e retorna o ip.
char *get_ip(char *host_name)
{
    // Recebe um ponteiro para uma estrutura com informaçoes sobre o host.
    host = gethostbyname(host_name);
    if(host == NULL) return NULL;

    // Retorna o ip
    return inet_ntoa(*((struct in_addr *)host->h_addr));
}

// Faz um brute force em um dominio
void dns_enum(char *domain , char *wordlist)
{
    // Variaveis
    char subdomain[30] , host_complete[100] , *target;

    // Verifica se existe 'https://' na string domain.
    if(strncmp("https://" , domain , 8) == 0 || strncmp("http://" , domain , 7) == 0)
    {
        fprintf(stderr , "> Entre apenas com o nome de domino.\nEx: google.com\n");
        return;
    }

    // Abre a wordlist para o bruteforce
    FILE *wdList = fopen(wordlist, "r");
    if(wdList == NULL)
    {
        fprintf(stderr , "> [ERRO]: ao abrir wordlist: %s\n",wordlist);
        return;
    }

    // bruteforce
    while(fscanf(wdList , "%s" , subdomain) != EOF)
    {
        snprintf(host_complete , sizeof(host_complete) , "%s%s" , subdomain , domain);
        target = get_ip(host_complete);
        if(target == NULL) continue;
        else printf("> Host encontrado: %s ---> IP: %s\n",host_complete , target);
    }

    fclose(wdList);
    return;
}

// Verifica se uma porta esta aberta
// Retorna 1 se a porta estiver aberta e 0 se estiver fechada.
int port_scan(char *ip , int port)
{
    int status = 0;

    // Cria o socket
    int sock = socket(AF_INET , SOCK_STREAM , 0);
    if(sock == -1) return -1;

    // Configurando informaçoes para a conexão
    target.sin_addr.s_addr = inet_addr(ip);
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    // Configurando o tempo de envio e espera para cada pacote
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    setsockopt(sock , SOL_SOCKET , SO_SNDTIMEO , (char *)&timeout , sizeof(timeout));
    setsockopt(sock , SOL_SOCKET , SO_RCVTIMEO , (char *)&timeout , sizeof(timeout));

    // Conecta no ip e porta de destino
    if(connect(sock , (struct sockaddr*)&target , sizeof(target)) == 0) status = 1;

    // Fecha a conexão e retorna o status
    close(sock);
    return status;
}

// Envia pacotes ICMP simples para o host alvo
int ping(char *ip)
{
    int status_snd = 0 , status_rcv = 0 , size_addr = sizeof(struct sockaddr_in) , bytes_rcv = 0, bytes_snd = 0;

    // Cria o socket
    int sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
    if(sock == -1) return -1;

    // Informaçãos do host de destino
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(ip);

    // Tempo de espera limite
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    setsockopt(sock , SOL_SOCKET , SO_RCVTIMEO , (const char*)&timeout , sizeof(timeout));

    // Envia e recebe 2 pacotes ICMP
    for(int i = 1; i <= TOTAL_PACKETS_ICMP;++i)
    {
        bytes_rcv = 0 , bytes_snd = 0;
        memset(&icmph , 0 ,sizeof(struct icmphdr));

        // Cabeçalho ICMP
        icmph.code = 0;
        icmph.type = ICMP_ECHO;
        icmph.un.echo.id = getpid();
        icmph.un.echo.sequence = htons(i);
        icmph.checksum = checksum(&icmph , sizeof(struct icmphdr));

        // Envia o pacote
        bytes_snd = sendto(sock , &icmph , sizeof(icmph) , 0 , (struct sockaddr*)&dst_addr , size_addr);
        if(bytes_snd > 0) ++status_snd;

        // Recebe o pacote
        bytes_rcv = recvfrom(sock , &icmph , sizeof(icmph), 0 , (struct sockaddr*)&src_addr , &size_addr);
        if(strcmp(ip, inet_ntoa(src_addr.sin_addr)) == 0 && bytes_rcv > 0) ++status_rcv;
    }

    // Verifica se algum pacote foi enviado/recebido com sucesso
    if(status_rcv > 0 && status_snd > 0)
    {
        close(sock);
        return 1;
    }
    else
    {
        close(sock);
        return 0;
    }

}

// Calcula o checksum para o protocolo icmp
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Preenche o buf com o endereço MAC do ip passado e retorna 1 em casa de sucesso
int arp_scan(char *ip , char *buf , const char *my_addr , const char *device , const char *mac_src)
{
    // Variaveis
	int sock , bytes_snd = 0, bytes_rcv = 0;
	char buffer[1024] , pacote_eth[ETH_FRAME_LEN];
	char eth_dest[ETH_ALEN]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    // Endereço ethernet de destino
    char eth_dest_alvo[ETH_ALEN]={0x00,0x00,0x00,0x00,0x00,0x00}; // Endereço ethernet alvo
	unsigned char mac[6];

	// Cria o socket para envio de pacotes ethernet
	sock = socket(AF_INET , SOCK_PACKET , htons(0x0003));
	if(sock == -1)
	{
        sprintf(buf , "Erro ao criar socket");
        return -1;
    }

	// Construindo pacote ethernet
	ethernet_hdr = (struct ethhdr *)pacote_eth;
	memcpy(ethernet_hdr->h_dest, eth_dest, ETH_ALEN);
	ethernet_hdr->h_proto = htons(0x0806); // 0x0806 "codigo" do protocolo ARP

	// Construindo pacote ARP
	pacote_arp = pacote_eth + ETH_HLEN;	// Aponta nos proximos bytes depois do cabeçalho eth do pacote ethernet
	pacote_arp->_hardware_type = htons(0x1);	// Tipo de hardware ethernet
	pacote_arp->_protocol_type = htons (0x800); // Tipo do protoclo ipv4
	pacote_arp->_hardware_address_length = ETH_ALEN; // Tamanho do endereço de hardware
	pacote_arp->_protocol_address_length = 4; // Tamanho do protocolo
	pacote_arp->_opcode = htons(0x0001);	// Codigo de operação do ARP request

	// Configurando endereço IP de origem
  	in.s_addr = inet_addr(my_addr);
  	memcpy(pacote_arp->_src_ip,&in.s_addr,4);

	// Configurando endereço IP de destino
  	dest.s_addr = inet_addr(ip);
	memcpy(pacote_arp->_dest_ip,&dest.s_addr,4);

	// Configurando endereço MAC de origem
	sscanf(mac_src,"%x:%x:%x:%x:%x:%x",&mac[0],&mac[1]
							          ,&mac[2],&mac[3]
							          ,&mac[4],&mac[5]);
	memcpy(pacote_arp->_src_mac,&mac,6);
	memcpy(ethernet_hdr->h_source,&mac,6);

    // Configura o endereço MAC de destino para 00:00:00:00:00:00
	memcpy(pacote_arp->_dest_mac,eth_dest_alvo,ETH_ALEN);
	bzero(pacote_arp->fill,18); // Zerando o resto do pacote ARP

	// Interface que vai enviar o pacote
	strcpy(destino.sa_data,device);

	// Ajustar timeout para espera do pacote reply
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000;
	if(setsockopt(sock , SOL_SOCKET , SO_RCVTIMEO , (const char*)&timeout , sizeof(timeout)) == -1)
	{
		memcpy(buf , "Erro ao setar timeout" , 23);
		return 0;
	}

	// Envia o pacote
	bytes_snd = sendto(sock , &pacote_eth , 64 , 0 , &destino , sizeof(destino));
	if(bytes_snd <= 0)
	{
		sprintf(buf , "Erro ao enviar pacote");
		return 0;
	}

	// Pacote ARP reply sera guardado aqui
	struct arp_hdr * arp_rply;
    arp_rply = (struct arp_hdr*)(buffer + 14);

    int cont = 0;
    while(recv(sock,buffer,sizeof(buffer),0))
    {
        ++cont;
        if(cont == 3)
        {
            sprintf(buf , "Nenhuma resposta de: %s", ip);
            close(sock);
            return 0;
        }
		if((((buffer[12])<<8)+buffer[13])!=ETH_P_ARP) continue;
		if(ntohs(arp_rply->_opcode)!=2) continue;

		// Pega o ip do pacote recebido
        char ip_src[9];
        sprintf(ip_src , "%u.%u.%u.%u" , arp_rply->_src_ip[0],
                                         arp_rply->_src_ip[1],
                                         arp_rply->_src_ip[2],
                                         arp_rply->_src_ip[3]);

        // Verifica se é igual ao ip passado para a função
        if(strcmp(ip , ip_src) == 0)
        {
            sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",arp_rply->_src_mac[0],
                                                        arp_rply->_src_mac[1],
                                                        arp_rply->_src_mac[2],
                                                        arp_rply->_src_mac[3],
                                                        arp_rply->_src_mac[4],
                                                        arp_rply->_src_mac[5]);
            close(sock);
            return 1;
        }
	}

}

// Retorna o IP associado a interface escolhida
char *get_local_addr(char *device)
{
    // Estrutura que vai conter informações sobre a interface
    struct ifreq ifr;

    // Abrindo um descritor
    int sock = socket(AF_INET , SOCK_DGRAM , 0);
    if(sock == -1) return NULL;

    // Informando que é o protocolo IPv4
    ifr.ifr_addr.sa_family = AF_INET;

    // Informando a interface
    strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFADDR, &ifr);

    // Fecha o descritor
    close(sock);

    // Retorna o IP
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

// Calcula a rede
char *network(char *net)
{
    // Variaveis
    char *rede;
    struct sockaddr_in ip_addr , mask_addr;

    // Faz a conversão
	ip_addr.sin_addr.s_addr = inet_addr(net);
	mask_addr.sin_addr.s_addr = inet_addr("255.255.255.0");

    // Faz o calculo do IP com a mascara
    unsigned long result_bin = ip_addr.sin_addr.s_addr & mask_addr.sin_addr.s_addr;

    // Resultado
    ip_addr.sin_addr.s_addr = result_bin;
    rede = inet_ntoa(ip_addr.sin_addr);

    return rede;
}

// Função de ajuda
void help(char *progname)
{
    puts("\t\t# Spectre - By: Usuario #\n");
    printf("> Use: %s [OPÇÕES].\n",progname);
    puts("> Opções: -p [Especificar uma ou mais portas] -ap [Escanear todas as portas (65535)]");
    puts("> -r [Retorna o IP de um dominio] -e [Faz a um bruteforce em um dominio]");
    puts("> -ps [Retorna todos os hosts ativos em uma rede] -as [Retorna o endereço MAC de um ou mais host na rede]");
    puts("> -as-all [Retorna o IP e o endereço MAC de todos os hosts ativos na rede]\n");
    puts("> Exemplos:\n");
    printf("> Port Scan: %s -p 192.168.0.1 81 21 8080 443\n", progname);
    printf("> Port Scan: %s -ap 192.168.0.1\n", progname);
    printf("> Port Scan: %s 192.168.0.1 (Escanear as portas padrão)\n\n",progname);
    printf("> Resolver DNS: %s -r www.dominio.com\n" , progname);
    printf("> Resolver DNS: %s -e dominio.com wordlist.txt\n" , progname);
    printf("> Resolver DNS: %s -e dominio.com (Usar wordlist padrão)\n\n",progname);
    printf("> Host Scan: %s -ps [DIGITE A REDE OU SEU IP]/ %s -ps 192.168.0.100\n\n" , progname , progname);
    printf("> Arp Scan: %s -as 192.168.0.1 [INTERFACE DE REDE] [SEU ENDEREÇO MAC].\n",progname);
    printf("> Arp Scan: %s -as-all [INTERFACE DE REDE] [SEU ENDEREÇO MAC]\n", progname);
}



