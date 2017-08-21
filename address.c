#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
/*
Description:
    Provides a simple header file to deal with common tasks carryed out
    by networking programs.

Author: Dylan Halls
Date: Sun 6 Aug 03:11:20 BST 2017
*/

#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>

char macp[19];
char ip[INET6_ADDRSTRLEN] = {0};

char* retrieve_system_address(const char* type) {
  //https://stackoverflow.com/questions/6762766/mac-address-with-getifaddrs#12878352
  //https://stackoverflow.com/users/785721/shaggy <-- credit for this function
  /*
          #include "NetworkUtility.h"
          char mac[19];
          sprintf(mac, "%s", retrieve_system_address("mac"));
          printf("%s\n", mac);

  Change the retrieve_system_address("mac") to retrieve_system_address("ip")
  for ip address.
  */
  char buf[8192] = {0};
  struct ifconf ifc = {0};
  struct ifreq *ifr = NULL;
  int sck = 0;
  int nInterfaces = 0;
  int i = 0;
  struct ifreq *item;
  struct sockaddr *addr;

  /* Get a socket handle. */
  sck = socket(PF_INET, SOCK_DGRAM, 0);
  if(sck < 0)
  {
    perror("socket");
    return "NULL ON SOCKET";
  }

  /* Query available interfaces. */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0)
  {
    perror("ioctl(SIOCGIFCONF)");
    return "NULL ON IOCTL";
  }

  /* Iterate through the list of interfaces. */
  ifr = ifc.ifc_req;
  nInterfaces = ifc.ifc_len / sizeof(struct ifreq);

  for(i = 1; i < nInterfaces; i++)
  {
    item = &ifr[i];

    addr = &(item->ifr_addr);

    /* Get the IP address*/
    if(ioctl(sck, SIOCGIFADDR, item) < 0)
    {
      perror("ioctl(OSIOCGIFADDR)");
    }

    if (inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ip, sizeof ip) == NULL)
        {
           perror("inet_ntop");
           continue;
        }

    /* Get the MAC address */
    if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
      perror("ioctl(SIOCGIFHWADDR)");
      //return "NULL ON ioctl(SIOCGIFHWADDR)";
    }

    /* display result */
    sprintf(macp, "%02x:%02x:%02x:%02x:%02x:%02x",
    (unsigned char)item->ifr_hwaddr.sa_data[0],
    (unsigned char)item->ifr_hwaddr.sa_data[1],
    (unsigned char)item->ifr_hwaddr.sa_data[2],
    (unsigned char)item->ifr_hwaddr.sa_data[3],
    (unsigned char)item->ifr_hwaddr.sa_data[4],
    (unsigned char)item->ifr_hwaddr.sa_data[5]);
  }

  if (strncmp(type, "mac", 3) == 0){
    return macp;
  }
  else if (strncmp(type, "ip", 2) == 0) {
    return ip;
  }
}
