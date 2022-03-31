#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#define __LITTLE_ENDIAN_BITFIELD 1
#define BUFSIZE 2048

int debug = 1;
char *progname;


#define IPQUAD_FMT              "%u.%u.%u.%u"
#define IPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define swap(m, n) { \
        typeof(m) __t = m; m = n; n = __t; }

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                        ihl:4;
#else
#error  "Please, edit Makefile and add -D__(LITTLE|BIG)_ENDIAN_BITFIEND"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

/*
 * UDP header
 */
struct udphdr {
        __u16 sport;     /* source port */
        __u16 dport;     /* destination port */
        __u16 ulen;      /* udp length */
        __u16 sum;       /* udp checksum */
};

struct pseudohdr {
        __be32          saddr;
        __be32          daddr;
        __u8            pad;
        __u8            protocol;
        __be16          len;
};


__u16 cksum(__u16 *buf, int nbytes)
{
        __u32 sum;

        sum = 0;
        while (nbytes > 1) {
                sum += *buf++;
                nbytes -= 2;
        }

        if (nbytes == 1) {
                sum += *((__u8*)buf);
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        return (__u16) ~sum;
}


int tun_alloc(char *dev, int flags) {

        struct ifreq ifr;
        int fd, err;
        char *clonedev = "/dev/net/tun";

        if( (fd = open(clonedev , O_RDWR)) < 0 ) {
                perror("Opening /dev/net/tun");
                return fd;
        }

        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = flags;

        if (*dev) {
                strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        }

        if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
                perror("ioctl(TUNSETIFF)");
                close(fd);
                return err;
        }

        strcpy(dev, ifr.ifr_name);

        return fd;
}

int cread(int fd, char *buf, int n){

        int nread;

        if((nread=read(fd, buf, n)) < 0){
                perror("Reading data");
                exit(1);
        }
        return nread;
}

int cwrite(int fd, char *buf, int n){

        int nwrite;

        if((nwrite=write(fd, buf, n)) < 0){
                perror("Writing data");
                exit(1);
        }
        return nwrite;
}

int read_n(int fd, char *buf, int n) {

        int nread, left = n;

        while(left > 0) {
                if ((nread = cread(fd, buf, left)) == 0){
                        return 0 ;
                }else {
                        left -= nread;
                        buf += nread;
                }
        }
        return n;
}

void do_debug(char *msg, ...){

        va_list argp;

        if(debug) {
                va_start(argp, msg);
                vfprintf(stderr, msg, argp);
                va_end(argp);
        }
}

void my_err(char *msg, ...) {

        va_list argp;

        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
}

void usage(void) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
        fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
        fprintf(stderr, "-d: outputs debug information while running\n");
        fprintf(stderr, "-h: prints this help text\n");
        exit(1);
}

int main(int argc, char *argv[]) {

        int tap_fd, option;
        int flags = IFF_TUN;
        char if_name[IFNAMSIZ] = "";
        int maxfd;
        uint16_t nread, nwrite, plength;
        char buffer[BUFSIZE];
        unsigned long int tap2net = 0, net2tap = 0;

        progname = argv[0];

        /* Check command line options */
        while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
                switch(option) {
                        case 'd':
                                debug = 1;
                                break;
                        case 'h':
                                usage();
                                break;
                        case 'i':
                                strncpy(if_name,optarg, IFNAMSIZ-1);
                                break;
                        case 'u':
                                flags = IFF_TUN;
                                break;
                        case 'a':
                                flags = IFF_TAP;
                                break;
                        default:
                                my_err("Unknown option %c\n", option);
                                usage();
                }
        }

        argv += optind;
        argc -= optind;

        if(argc > 0) {
                my_err("Too many options!\n");
                usage();
        }

        /* initialize tun/tap interface */
        if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
                my_err("Error connecting to tun/tap interface %s!\n", if_name);
                exit(1);
        }

        do_debug("Successfully connected to interface %s\n", if_name);

        maxfd = tap_fd;
        while(1) {
                int ret;
                fd_set rd_set;

                FD_ZERO(&rd_set);
                FD_SET(tap_fd, &rd_set);

                ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

                if (ret < 0 && errno == EINTR){
                        continue;
                }

                if (ret < 0) {
                        perror("select()");
                        exit(1);
                }

                if(FD_ISSET(tap_fd, &rd_set)) {
                        memset(buffer, 0, BUFSIZE);
                        nread = cread(tap_fd, buffer, BUFSIZE);

                        tap2net++;
                        do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

                        struct iphdr *iph = (void *)&buffer[0];
                        struct udphdr *udph = (void *)&buffer[sizeof(*iph)];
                        const char *data = (void *)&buffer[sizeof(*iph) + sizeof(*udph)];
                        int data_len = udph->ulen - sizeof(*udph);

                        if (iph->protocol != 17)
                                continue;

                        do_debug("Recv: "IPQUAD_FMT":%d ---> "IPQUAD_FMT":%d\n", IPQUAD(iph->saddr),\
                                                ntohs(udph->sport), IPQUAD(iph->daddr), ntohs(udph->dport));
                        do_debug("Data: %s", data);


                        /* UDP header */
                        char packet[sizeof(struct pseudohdr) + BUFSIZE];
                        struct pseudohdr pdoh = {
                                        .saddr = iph->daddr, // Network order
                                        .daddr = iph->saddr, // Network order
                                        .pad = 0,
                                        .protocol = 17,
                                        .len = udph->ulen, // Network order
                                };

                        udph->sum = 0;
                        udph->ulen = udph->ulen;
                        swap(udph->sport, udph->dport);

                        memcpy(packet, &pdoh, sizeof(pdoh));
                        memcpy(&packet[sizeof(pdoh)], udph, ntohs(udph->ulen));

                        udph->sum = cksum((__u16 *)packet, ntohs(udph->ulen) + sizeof(pdoh));

                        /* IP header */
                        iph->check = 0;
                        swap(iph->saddr, iph->daddr);
                        iph->ttl = 64;
                        iph->id = iph->id + 1;
                        iph->protocol = 17;
                        iph->check = cksum((__u16 *)iph, iph->ihl * 4);
                        do_debug("Send: "IPQUAD_FMT":%d ---> "IPQUAD_FMT":%d csum: %02x\n", IPQUAD(iph->saddr),\
                                                ntohs(udph->sport), IPQUAD(iph->daddr), ntohs(udph->dport), iph->check);
                        do_debug("Data: %s", data);

                        nwrite = cwrite(tap_fd, (char *)iph, ntohs(iph->tot_len));
                        //nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
                        //nwrite = cwrite(net_fd, buffer, nread);

                        //do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
                }
        }

        return(0);
}
