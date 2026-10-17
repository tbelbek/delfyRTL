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
static int ap_ifindex = 0;   // which xnetif[] carries the AP - set by start_DHCP_Server()
// Option-114 captive-portal URL (set by the sketch at AP start; host-based, not the IP).
static char dhcp_cp_uri[96] = "http://192.168.4.1/cp.json";

// Move the SoftAP netif off the SDK default (192.168.1.1) onto our captive subnet.
//
// Which netif? The core's apActivate() chooses it from arduino_wifi_mode_check:
//   0x11 (STA_AP) -> WLAN1 / xnetif[1];  anything else -> WLAN0 / xnetif[0].
// createAP() forces 0x10 for a pure softAP, so the AP is xnetif[0]. Use that same rule (passed
// in as ap_if) instead of the old "find whichever netif holds 192.168.1.1" search: if the SDK's
// default AP IP ever differs, that search matches nothing and the fallback (xnetif[1]) is the
// WRONG interface in pure AP mode - every DHCP offer would then leave through a dead netif and
// no client would ever get a lease.
static void retarget_ap_netif(void) {
    ip4_addr_t nip, nmask, ngw;
    IP4_ADDR(&nip,  DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
    IP4_ADDR(&nmask, DHCP_AP_MASK[0], DHCP_AP_MASK[1], DHCP_AP_MASK[2], DHCP_AP_MASK[3]);
    IP4_ADDR(&ngw,  DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
    netif_set_addr(&xnetif[ap_ifindex], &nip, &nmask, &ngw);
    printf("DHCP: retargeted netif %d -> %d.%d.%d.%d\n", ap_ifindex,
           DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
}

// The AP netif, by the same interface rule apActivate() used.
static struct netif *find_ap_netif(void) {
    return &xnetif[ap_ifindex];
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

    size_t n = dhcp_build_reply(repbuf, sizeof(repbuf), reqbuf, rlen, dhcp_cp_uri);
    if (n == 0) return;  // not a DISCOVER/REQUEST we answer

    struct pbuf *op = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
    if (op == NULL) return;
    pbuf_take(op, repbuf, (u16_t)n);
    // Client has no IP yet -> broadcast the OFFER/ACK OUT THE AP NETIF (plain udp_sendto
    // has no route for 255.255.255.255 and silently drops it).
    ip_addr_t bcast;
    IP_ADDR4(&bcast, 255, 255, 255, 255);
    err_t e = udp_sendto_if(pcb, op, &bcast, DHCP_CLI_PORT, ap_netif ? ap_netif : find_ap_netif());
    printf("DHCP: reply type=%d len=%d send=%d\n", repbuf[DHCP_FIXED_LEN + 6], (int)n, (int)e);
    pbuf_free(op);
}

void start_DHCP_Server(const char *cp_uri, int ap_if) {
    if (cp_uri && cp_uri[0]) {                 // remember the portal URL for option 114
        strncpy(dhcp_cp_uri, cp_uri, sizeof(dhcp_cp_uri) - 1);
        dhcp_cp_uri[sizeof(dhcp_cp_uri) - 1] = 0;
    }
    if (dhcp_pcb != NULL) return;
    ap_ifindex = (ap_if == 1) ? 1 : 0;    // same rule apActivate() used to pick WLAN0/WLAN1
    retarget_ap_netif();          // move SoftAP from 192.168.1.1 to our captive subnet
    ap_netif = find_ap_netif();
    dhcp_pcb = udp_new();
    if (dhcp_pcb == NULL) { printf("DHCP: udp_new failed\n"); return; }
    dhcp_pcb->so_options |= SOF_BROADCAST;
    err_t e = udp_bind(dhcp_pcb, IP4_ADDR_ANY, DHCP_SRV_PORT);
    udp_recv(dhcp_pcb, (udp_recv_fn)dhcp_recv_cb, NULL);
    printf("DHCP: server up on :67 (bind=%d, ap_netif=%p, opt114=%s)\n",
           (int)e, (void *)ap_netif, dhcp_cp_uri);
}

void stop_DHCP_Server() {
    if (dhcp_pcb != NULL) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = NULL;
    }
}
