#include "dhcp_captive.h"
#include "dhcp_build.h"
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/ip.h>

#define DHCP_SRV_PORT 67
#define DHCP_CLI_PORT 68

static struct udp_pcb *dhcp_pcb = NULL;

// Same lwip raw-UDP callback shape delfy uses for DNS (cast on udp_recv below).
static void dhcp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         struct ip_addr *addr, uint16_t port) {
    (void)arg; (void)addr; (void)port;
    if (p == NULL) return;

    static uint8_t reqbuf[600];
    static uint8_t repbuf[600];
    uint16_t rlen = (p->tot_len < sizeof(reqbuf)) ? p->tot_len : (uint16_t)sizeof(reqbuf);
    pbuf_copy_partial(p, reqbuf, rlen, 0);
    pbuf_free(p);

    size_t n = dhcp_build_reply(repbuf, sizeof(repbuf), reqbuf, rlen);
    if (n == 0) return;  // not a DISCOVER/REQUEST we answer

    struct pbuf *op = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
    if (op == NULL) return;
    pbuf_take(op, repbuf, (u16_t)n);
    // Client has no IP yet -> always broadcast the OFFER/ACK to :68.
    udp_sendto(pcb, op, IP_ADDR_BROADCAST, DHCP_CLI_PORT);
    pbuf_free(op);
}

void start_DHCP_Server() {
    if (dhcp_pcb != NULL) return;
    dhcp_pcb = udp_new();
    if (dhcp_pcb == NULL) return;
    dhcp_pcb->so_options |= SOF_BROADCAST;  // allow broadcast sends
    udp_bind(dhcp_pcb, IP4_ADDR_ANY, DHCP_SRV_PORT);
    udp_recv(dhcp_pcb, (udp_recv_fn)dhcp_recv_cb, NULL);
}

void stop_DHCP_Server() {
    if (dhcp_pcb != NULL) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = NULL;
    }
}
