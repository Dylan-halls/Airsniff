#include <iwlib.h>
#include <pcap.h>

char* handleargs(const char *argv[], int argc){
	return (char*)argv[1];
}

int main(int argc, char const *argv[])
{
  char error_buffer[PCAP_ERRBUF_SIZE];
  wireless_scan_head head;
  wireless_scan *result;
  char buffer[128];
  iwrange range;
  char *device;
  int sock;

  sock = iw_sockets_open();

  device = pcap_lookupdev(error_buffer);
  if (device == NULL) {
    printf("finding a device");
    return 1;
  }

  printf("Scanning on %s...\n\n", device);

  if (iw_get_range_info(sock, device, &range) < 0) {
    printf("Error during iw_get_range_info. Aborting.\n");
    exit(2);
  }

  if (iw_scan(sock, device, range.we_version_compiled, &head) < 0) {
    printf("Error during iw_scan. Aborting.\n");
    exit(2);
  }

	result = head.result;
	while (NULL != result) {
	  printf("%s ", result->b.essid);
	  printf("(%s)\n", iw_sawap_ntop(&result->ap_addr, buffer));
	  result = result->next;
	}

	return 0;
}
