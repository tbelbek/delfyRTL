/* Host self-test for dhcp_build.h — assert OFFER/ACK layout + option 114.
   cc -I<sketchdir> test_dhcp_build.c -o t && ./t  */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "dhcp_build.h"

static size_t make_req(uint8_t *b, uint8_t msgtype) {
    memset(b, 0, 600);
    b[0] = 1; b[1] = 1; b[2] = 6;            /* BOOTREQUEST, ether, 6 */
    b[4]=0xDE; b[5]=0xAD; b[6]=0xBE; b[7]=0xEF; /* xid */
    b[10]=0x80;                               /* broadcast flag */
    uint8_t mac[6]={0x02,0x11,0x22,0x33,0x44,0x7B}; memcpy(b+28, mac, 6);
    memcpy(b + DHCP_FIXED_LEN, DHCP_MAGIC, 4);
    uint8_t *o = b + DHCP_FIXED_LEN + 4;
    *o++=53; *o++=1; *o++=msgtype;            /* option 53 */
    *o++=255;
    return (size_t)(o - b);
}

static const uint8_t* find(const uint8_t*r,size_t n,uint8_t code,uint8_t*l){return dhcp_find_opt(r,n,code,l);}

int main(void) {
    uint8_t req[600], rep[600];

    /* DISCOVER -> OFFER */
    size_t rn = make_req(req, 1);
    size_t n = dhcp_build_reply(rep, sizeof(rep), req, rn);
    assert(n >= DHCP_MIN_REPLY);
    assert(rep[0] == 2);                               /* BOOTREPLY */
    assert(memcmp(rep+4, req+4, 4) == 0);              /* xid echoed */
    assert(memcmp(rep+28, req+28, 16) == 0);           /* chaddr echoed */
    assert(memcmp(rep+DHCP_FIXED_LEN, DHCP_MAGIC, 4)==0);
    assert(rep[16]==DHCP_AP_IP[0] && rep[17]==DHCP_AP_IP[1] && rep[18]==DHCP_AP_IP[2]); /* yiaddr in AP subnet */
    assert(rep[19] == 100 + (0x7B % 101));             /* stateless per-MAC */

    uint8_t l=0; const uint8_t *v;
    v = find(rep,n,53,&l); assert(v && l==1 && v[0]==2);          /* OFFER */
    v = find(rep,n,54,&l); assert(v && l==4 && v[0]==192);        /* server id */
    v = find(rep,n,6,&l);  assert(v && l==4 && memcmp(v,DHCP_AP_IP,4)==0); /* DNS=AP */
    v = find(rep,n,1,&l);  assert(v && l==4);                     /* subnet */
    v = find(rep,n,3,&l);  assert(v && l==4);                     /* router */
    v = find(rep,n,51,&l); assert(v && l==4);                     /* lease */
    v = find(rep,n,114,&l);                                       /* OPTION 114 */
    assert(v && l==(uint8_t)(sizeof(DHCP_CP_URI)-1));
    assert(memcmp(v, DHCP_CP_URI, l)==0);

    /* REQUEST -> ACK */
    rn = make_req(req, 3);
    n = dhcp_build_reply(rep, sizeof(rep), req, rn);
    v = find(rep,n,53,&l); assert(v && v[0]==5);                  /* ACK */
    v = find(rep,n,114,&l); assert(v && memcmp(v,DHCP_CP_URI,l)==0);

    /* Non DISCOVER/REQUEST ignored; bad magic ignored */
    assert(dhcp_build_reply(rep,sizeof(rep),req,DHCP_FIXED_LEN)==0);
    rn = make_req(req, 8); assert(dhcp_build_reply(rep,sizeof(rep),req,rn)==0);
    req[DHCP_FIXED_LEN]=0; rn=make_req(req,1); req[DHCP_FIXED_LEN]=0xAA;
    assert(dhcp_build_reply(rep,sizeof(rep),req,rn)==0);

    printf("OK: option-114 DHCP builder passes (OFFER+ACK, full options)\n");
    return 0;
}
