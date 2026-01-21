#!/usr/bin/env swift
//
// wifi_info.swift - CoreWLAN WiFi Information Extractor
// Outputs WiFi details as KEY=VALUE pairs for bash parsing
//
// Usage: ./wifi_info
// Compile: swiftc -O -o wifi_info wifi_info.swift
//

import Foundation
import CoreWLAN

func main() {
    // Get the default WiFi interface
    let client = CWWiFiClient.shared()
    guard let interface = client.interface() else {
        print("CONNECTED=false")
        print("INTERFACE=none")
        print("ERROR=No WiFi interface found")
        return
    }

    let interfaceName = interface.interfaceName ?? "unknown"
    print("INTERFACE=\(interfaceName)")

    // Check if powered on
    guard interface.powerOn() else {
        print("CONNECTED=false")
        print("POWER=off")
        return
    }
    print("POWER=on")

    // Check if connected
    guard let ssid = interface.ssid(), !ssid.isEmpty else {
        print("CONNECTED=false")
        print("SSID=")
        return
    }

    print("CONNECTED=true")
    print("SSID=\(ssid)")

    // BSSID (Access Point MAC Address)
    if let bssid = interface.bssid() {
        print("BSSID=\(bssid)")
    } else {
        print("BSSID=unknown")
    }

    // Channel information
    if let channel = interface.wlanChannel() {
        print("CHANNEL=\(channel.channelNumber)")

        // Band mapping
        let band: String
        switch channel.channelBand {
        case .band2GHz:
            band = "2.4GHz"
        case .band5GHz:
            band = "5GHz"
        case .band6GHz:
            band = "6GHz"
        case .bandUnknown:
            band = "unknown"
        @unknown default:
            band = "unknown"
        }
        print("BAND=\(band)")

        // Channel width mapping
        let width: Int
        switch channel.channelWidth {
        case .width20MHz:
            width = 20
        case .width40MHz:
            width = 40
        case .width80MHz:
            width = 80
        case .width160MHz:
            width = 160
        case .widthUnknown:
            width = 0
        @unknown default:
            width = 0
        }
        print("WIDTH_MHZ=\(width)")
    } else {
        print("CHANNEL=0")
        print("BAND=unknown")
        print("WIDTH_MHZ=0")
    }

    // Signal quality metrics
    let rssi = interface.rssiValue()
    let noise = interface.noiseMeasurement()
    let snr = rssi - noise

    print("RSSI_DBM=\(rssi)")
    print("NOISE_DBM=\(noise)")
    print("SNR_DB=\(snr)")

    // Transmit rate
    let txRate = interface.transmitRate()
    print("TX_RATE_MBPS=\(txRate)")

    // Security type
    let security = interface.security()
    let securityString: String
    switch security {
    case .none:
        securityString = "None"
    case .WEP:
        securityString = "WEP"
    case .wpaPersonal:
        securityString = "WPA Personal"
    case .wpaPersonalMixed:
        securityString = "WPA Personal Mixed"
    case .wpa2Personal:
        securityString = "WPA2 Personal"
    case .personal:
        securityString = "Personal"
    case .dynamicWEP:
        securityString = "Dynamic WEP"
    case .wpaEnterprise:
        securityString = "WPA Enterprise"
    case .wpaEnterpriseMixed:
        securityString = "WPA Enterprise Mixed"
    case .wpa2Enterprise:
        securityString = "WPA2 Enterprise"
    case .enterprise:
        securityString = "Enterprise"
    case .wpa3Personal:
        securityString = "WPA3 Personal"
    case .wpa3Enterprise:
        securityString = "WPA3 Enterprise"
    case .wpa3Transition:
        securityString = "WPA3 Transition"
    case .oweTransition:
        securityString = "OWE Transition"
    case .OWE:
        securityString = "OWE"
    case .unknown:
        securityString = "Unknown"
    @unknown default:
        securityString = "Unknown"
    }
    print("SECURITY=\(securityString)")

    // PHY Mode
    let phyMode = interface.activePHYMode()
    let phyString: String
    switch phyMode {
    case .mode11a:
        phyString = "802.11a"
    case .mode11b:
        phyString = "802.11b"
    case .mode11g:
        phyString = "802.11g"
    case .mode11n:
        phyString = "802.11n"
    case .mode11ac:
        phyString = "802.11ac"
    case .mode11ax:
        phyString = "802.11ax"
    case .modeNone:
        phyString = "None"
    @unknown default:
        phyString = "Unknown"
    }
    print("PHY_MODE=\(phyString)")

    // Country code
    if let countryCode = interface.countryCode() {
        print("COUNTRY_CODE=\(countryCode)")
    }
}

main()
