#include <pcap.h>
#include <nids.h>
#include <string.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>

#include "buf.h"
#include "base64.h"

#define PCAP_FILTER "tcp port 80 or tcp port 8080"

int process_http_request(struct tuple4 *addr, u_char *data, int len) {
	struct buf *msg, buf;
	char *p, *req, *uri, *user, *vhost, *referer, *agent, *cookie;
	int i;

	buf_init(&buf, data, len);

	while ((i = buf_index(&buf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&buf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&buf, 4);

		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL){
    }


    if ((uri = strchr(req, ' ')) == NULL)
			continue;

		*uri++ = '\0';
		if (strncmp(uri, "http://", 7) == 0) {
			for (uri += 7; *uri != '/'; uri++)
				;
		}
		user = vhost = referer = agent = cookie = NULL;

		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Host: ", 6) == 0) {
				vhost = p + 6;
        printf("\n[%s] %s\n\t http://%s/%s/\n", libnet_addr2name4(addr->saddr, (u_short)1), req, vhost,uri+1);
			}
			else if (strncasecmp(p, "Referer: ", 9) == 0) {
				referer = p + 9;
        printf("\t %s\n", referer);
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p + 12;
        printf("\t %s\n", agent);
			}
      else if (strncasecmp(p, "Cookie: ", 8) == 0) {
        cookie = p + 8;
        printf("\t %s\n", cookie);
      }
		}
    if (user == NULL)
			user = "-";
		if (vhost == NULL)
			vhost = libnet_addr2name4(addr->daddr, (u_short)1);
		if (referer == NULL)
			referer = "-";
		if (agent == NULL)
			agent = "-";
	}
	fflush(stdout);

	return (len - buf_len(&buf));
}

void sniff_http_client(struct tcp_stream *ts, void **yoda)
{
	int i;

	if ((ts->nids_state) == NIDS_JUST_EST){
		ts->server.collect = 1;
  }

	if ((ts->nids_state) == NIDS_DATA){
		if (ts->server.count_new != 0) {
			i = process_http_request(&ts->addr, ts->server.data, ts->server.count - ts->server.offset);
			nids_discard(ts, i);
		}
  }

	else if (ts->server.count != 0) {
			process_http_request(&ts->addr, ts->server.data, ts->server.count - ts->server.offset);
	}
}

void checkroot(){
  if (getuid() != 0) {
    printf("Must be root\n");
    exit(-1);
  }
}

int main(int argc, char const *argv[]) {
  char *device;
  char error_buffer[PCAP_ERRBUF_SIZE];

  checkroot();
  device = pcap_lookupdev(error_buffer);
  if (device == NULL) {
    printf("finding a device");
    return 1;
  }
  nids_params.device = device;
  nids_params.pcap_filter = PCAP_FILTER;
  nids_params.scan_num_hosts = 0;
  printf("airsnuffler [%s]\n", nids_params.device);
  if (!nids_init())
    perror("Error");
  nids_register_tcp(sniff_http_client);
	nids_run();
  return 0;
}
