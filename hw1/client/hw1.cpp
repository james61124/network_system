#include <iostream>
#include <stdlib.h>
#include <pcap/pcap.h> 
#include <string.h>
#include <vector>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

using namespace std;
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
    u_char ip_vhl;                      /* version << 4 | header length >> 2 */
    u_char ip_tos;                      /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
    #define IP_RF 0x8000                /* reserved fragment flag */
    #define IP_DF 0x4000                /* dont fragment flag */
    #define IP_MF 0x2000                /* more fragments flag */
    #define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                     /* time to live */
    u_char  ip_p;                       /* protocol */
    u_short ip_sum;                     /* checksum */
    struct  in_addr ip_src,ip_dst;      /* source and dest address */
};
#define     IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define     IP_V(ip)     (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;                   /* source port */
    u_short th_dport;                   /* destination port */
    tcp_seq th_seq;                     /* sequence number */
    tcp_seq th_ack;                     /* acknowledgement number */
    u_char  th_offx2;                   /* data offset,rsvd */
    #define TH_OFF(th)       (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                     /* window */
    u_short th_sum;                     /* checksum */
    u_short th_urp;                     /* urgent pointer */
};

void print_hex_ascii_line(const u_char *payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;
    ch = payload;
    for(i = 0; i < len;i++) {
        printf("%02x ",*ch);
        ch++;
    }
    printf("\n");

    return;
}

void print_payload(const u_char *payload,int len){
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;
    
    if(len <= 0) return;

    if (len <= line_width) {
        print_hex_ascii_line(ch,len,offset);
        return;
    }

    for (int i=0;i<1;i++){
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch,line_len,offset);
    }
    return;
}

// return payload and length by skipping headers in a packet
const u_char* get_payload(const u_char *packet, u_int *length) {
    const ip* ip_;
    const udphdr* udphdr_;

    u_int ip_length;
    u_int udphdr_length;

    // Ethernet header starts with destination and source addresses
    const u_char* payload = packet;
    payload += 12;

    // search for IP header; assume all other Ethernet types are vlan
    while (ntohs(*reinterpret_cast<const u_short*>(payload)) != ETHERTYPE_IP) {
        payload += 4;
    }
    payload += 2;

    // IP header can vary in length
    ip_ = reinterpret_cast<const ip*>(payload);
    ip_length = ip_->ip_hl * 4;
    payload += ip_length;

    // ensure this is UDP
    if (ip_->ip_p != IPPROTO_UDP) {
        *length = 0;
        payload = nullptr;
    }
    else {
        // UDP header is static length
        udphdr_ = reinterpret_cast<const udphdr*>(payload);
        udphdr_length = sizeof(udphdr);
        *length = ntohs(udphdr_->uh_ulen) - udphdr_length;
        payload += udphdr_length;
    }

    return payload;
}





int main(int argc, const char * argv[]) 
{
    
    pcap_if_t *devices = NULL; 
    char errbuf[PCAP_ERRBUF_SIZE];
    char ntop_buf[256];
    struct ether_header* eptr;
    vector<pcap_if_t*> vec; // vec is a vector of pointers pointing to pcap_if_t 
    string interface_s;
    string filter_s;
    int count;
    struct pcap_pkthdr header; 

    int is_interface = 0;
    int is_count = 0;
    int is_filter = 0;   

    for(int i=1;i<argc;i++){
        string arg = argv[i];
        if(arg=="-i" || arg=="--interface" && i+1<argc){
            is_interface = 1;
            interface_s = argv[i+1];
            i++;
        }else if(arg=="-c" || arg=="--count" && i+1<argc){
            is_count = 1;
            string arg2 = argv[i+1];
            for(int j=0;j<arg2.size();j++){
                if(isdigit(arg2[j])==0){
                    cout<<"Usage"<<endl;
                    return 0;
                }
            }
            count = stoi(arg2);
            i++;
        }else if(arg=="-f" || arg=="--filter" && i+1<argc){
            is_filter = 1;
            filter_s = argv[i+1];
            i++;
        }else{
            cout<<"Usage"<<endl;
            return 0;
        }
    }

    if(is_interface==0){
        cout<<"you should input interface"<<endl;
        return 0;
    }

    if(is_count==0){
        count = -1;
    }

    if(filter_s=="tcp"){
        filter_s = "tcp and not port ssh";
    }else if(filter_s=="all" || is_filter==0){
        filter_s = "not port ssh";
    }
    
    //get all devices 
    if(-1 == pcap_findalldevs(&devices, errbuf)) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf); // if error, fprint error message --> errbuf
        exit(1);
    }

    //list all device
    int cnt = 0;
    for(pcap_if_t *d = devices; d ; d = d->next, cnt++)
    {
        vec.push_back(d);
        cout<<"Name: "<<d->name<<endl;
    }

    struct bpf_program fp; // for filter, compiled in "pcap_compile"
    pcap_t *handle;
    handle = pcap_open_live(interface_s.c_str(), 65535, 1, 1, errbuf);  
    //pcap_open_live(device, snaplen, promise, to_ms, errbuf), interface is your interface, type is "char *"   
    

    if(!handle|| handle == NULL)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
 
    if(-1 == pcap_compile(handle, &fp, filter_s.c_str(), 1, PCAP_NETMASK_UNKNOWN) ) // compile "your filter" into a filter program, type of {your_filter} is "char *"
    {
        pcap_perror(handle, "pkg_compile compile error\n");
        exit(1);
    }
    if(-1 == pcap_setfilter(handle, &fp)) { // make it work
        pcap_perror(handle, "set filter error\n");
        exit(1);
    }


    // make it work
    for(int j=0;j<count||count==-1;j++) 
    {   
        const u_char *content = NULL;
        const unsigned char* packet = pcap_next(handle, &header);
        const struct sniff_ip *ip; 
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        switch(ip->ip_p){
            case IPPROTO_TCP:
                printf("Transport type: TCP\n");

                const struct sniff_tcp *tcp;   
                int size_ip;
                printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
                size_ip = IP_HL(ip)*4;
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET +size_ip);
                printf("Source port: %d\n",ntohs(tcp->th_sport));
                printf("Destination port: %d\n",ntohs(tcp->th_dport));

                int size_payload;
                int size_tcp;
                const u_char* payload;
                size_tcp = TH_OFF(tcp)*4;
                size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                payload = (const u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
                printf("Payoad: ");
                print_payload(payload,size_payload);
                printf("\n");

                break;
            case IPPROTO_UDP:
                printf("Transport type: UDP\n");

                printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
                size_ip = IP_HL(ip)*4;
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET +size_ip);
                printf("Source port: %d\n",ntohs(tcp->th_sport));
                printf("Destination port: %d\n",ntohs(tcp->th_dport));

                u_int payload_length;
                payload = get_payload(packet, &payload_length);
                printf("Payoad: ");
                print_payload(payload,payload_length);
                printf("\n");

                break;
            case IPPROTO_ICMP:
                printf("Transport type: ICMP\n");

                printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));

                struct iphdr *ip_header;
                struct icmphdr *icmp_header;
                int ip_header_size;
                ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
                ip_header_size = ip_header->ihl * 4;
                icmp_header = (struct icmphdr*)(packet + sizeof(struct ethhdr) + ip_header_size);
                if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY) {
                    cout << "ICMP type value:" << (int)icmp_header->type << endl;
                }
                cout<<endl;

                break;
            case IPPROTO_IP:
                printf("Transport type: IP\n");
                return 0;
            default:
                break;
        }
    }

    pcap_freealldevs(devices);

    return 0;
    
}