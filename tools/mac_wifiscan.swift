// Mac-side Wi-Fi scanner: proves whether the board's raw frames actually reach the air.
//
// macOS has no CLI scanner any more (the `airport` binary is gone and `wdutil` needs sudo), but
// CoreWLAN works from a plain Swift script. Feed it a unique fake SSID from the board (e.g.
// `BSSID DELFYTEST`, or an AP-clone) and this is the ground truth for "is the TX on the air?".
//
// Usage: swift tools/mac_wifiscan.swift
//
// Notes:
//  - macOS caches scan results, so an SSID that stopped transmitting can linger for a while.
//    Treat "appeared" as proof and "still listed right after BEACONOFF" as cache.
//  - RSSI around -20/-30 means the board is right next to the Mac.
import Foundation
import CoreWLAN

guard let iface = CWWiFiClient.shared().interface() else {
    print("NO INTERFACE")
    exit(1)
}
guard let nets = try? iface.scanForNetworks(withName: nil) else {
    print("SCAN FAILED")
    exit(1)
}
print("COUNT \(nets.count)")
for n in nets.sorted(by: { ($0.ssid ?? "") < ($1.ssid ?? "") }) {
    print("\(n.ssid ?? "<hidden>") | ch \(n.wlanChannel?.channelNumber ?? 0) | rssi \(n.rssiValue)")
}
