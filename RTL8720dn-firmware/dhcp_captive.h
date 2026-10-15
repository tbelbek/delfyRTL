// Minimal captive-portal DHCP server (replaces the SDK's built-in dhcps) so we can
// advertise DHCP option 114 (RFC 8910) and make the portal auto-open on Android 11+.
// Start it right after WiFi.apbegin() + dhcps_deinit(). Mirrors delfy's DNS server.
#ifndef DHCP_CAPTIVE_H
#define DHCP_CAPTIVE_H

void start_DHCP_Server(const char *cp_uri);   // cp_uri = option-114 portal URL
void stop_DHCP_Server();

#endif
