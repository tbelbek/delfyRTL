#include "dhcp_captive.h"
#include "dhcp_build.h"
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <stdio.h>

#define DHCP_SRV_PORT 67
#define DHCP_CLI_PORT 68

// AmebaD WLAN interfaces: xnetif[0]=STA, xnetif[1]=SoftAP (concurrent mode).
extern "C" struct netif xnetif[];

static struct udp_pcb *dhcp_pcb = NULL;
static struct netif *ap_netif = NULL;

// Pick the netif that owns the AP IP (192.168.1.1), regardless of index/mode.
static struct netif *find_ap_netif(void) {
    for (int i = 0; i < 2; i++) {
        uint32_t ip = ip_addr_get_ip4_u32(&xnetif[i].ip_addr);
        uint8_t a = ip & 0xFF, b = (ip >> 8) & 0xFF, c = (ip >> 16) & 0xFF, d = (ip >> 24) & 0xFF;
        if (a == DHCP_AP_IP[0] && b == DHCP_AP_IP[1] && c == DHCP_AP_IP[2] && d == DHCP_AP_IP[3])
            return &xnetif[i];
    }
    return &xnetif[1];  // fallback: SoftAP index in concurrent mode
}

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
    // Client has no IP yet -> broadcast the OFFER/ACK OUT THE AP NETIF (plain udp_sendto
    // has no route for 255.255.255.255 and silently drops it).
    ip_addr_t bcast;
    IP_ADDR4(&bcast, 255, 255, 255, 255);
    err_t e = udp_sendto_if(pcb, op, &bcast, DHCP_CLI_PORT, ap_netif ? ap_netif : find_ap_netif());
    printf("DHCP: reply type=%d len=%u send=%d\n", repbuf[DHCP_FIXED_LEN + 6], (unsigned)n, (int)e);
    pbuf_free(op);
}

void start_DHCP_Server() {
    if (dhcp_pcb != NULL) return;
    ap_netif = find_ap_netif();
    dhcp_pcb = udp_new();
    if (dhcp_pcb == NULL) { printf("DHCP: udp_new failed\n"); return; }
    dhcp_pcb->so_options |= SOF_BROADCAST;
    err_t e = udp_bind(dhcp_pcb, IP4_ADDR_ANY, DHCP_SRV_PORT);
    udp_recv(dhcp_pcb, (udp_recv_fn)dhcp_recv_cb, NULL);
    printf("DHCP: server up on :67 (bind=%d, ap_netif=%p)\n", (int)e, (void *)ap_netif);
}

void stop_DHCP_Server() {
    if (dhcp_pcb != NULL) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = NULL;
    }
}
