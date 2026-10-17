// Minimal captive-portal DHCP server (replaces the SDK's built-in dhcps) so we can
// advertise DHCP option 114 (RFC 8910) and make the portal auto-open on Android 11+.
// Start it right after WiFi.apbegin() + dhcps_deinit(). Mirrors delfy's DNS server.
// ap_if is the lwIP interface index that actually carries the SoftAP, and it must match what
// the core's apActivate() picked: 0x11 (STA_AP) -> 1, anything else (pure AP) -> 0. Passing it
// in is deliberate - the old code guessed by IP and fell back to index 1, which in pure AP mode
// is the wrong (STA) netif, so DHCP offers would be sent out of a dead interface.
#ifndef DHCP_CAPTIVE_H
#define DHCP_CAPTIVE_H

void start_DHCP_Server(const char *cp_uri, int ap_if);   // cp_uri = option-114 portal URL
void stop_DHCP_Server();

#endif
