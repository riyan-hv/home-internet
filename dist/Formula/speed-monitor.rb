class SpeedMonitor < Formula
  desc "Organization-wide internet speed monitoring with WiFi analytics, VPN detection, and dashboard"
  homepage "https://github.com/hyperkishore/home-internet"
  url "https://github.com/hyperkishore/home-internet/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "0209a10d5edb34f896e42b7b36c79b6bcf84d603b5641e795b37ea47acb72011"
  license "MIT"
  version "2.0.0"

  depends_on "speedtest-cli"
  depends_on "node"
  depends_on :macos

  def install
    # Compile Swift WiFi helper (CoreWLAN for WiFi metrics)
    system "swiftc", "-O", "-o", "wifi_info", "dist/src/wifi_info.swift",
           "-framework", "CoreWLAN", "-framework", "Foundation"

    # Install binaries
    bin.install "wifi_info"
    bin.install "dist/bin/nkspeedtest"

    # Install the enhanced bash speed monitor script
    bin.install "speed_monitor.sh" => "speed-monitor-collect"

    # Install SwiftBar plugin template
    (share/"speed-monitor").install "dist/lib/swiftbar-speed.5m.sh"

    # Install server files
    (libexec/"server").install Dir["dist/server/*"]

    # Create data directories
    (var/"speed-monitor/data").mkpath
    (var/"speed-monitor/logs").mkpath
  end

  def post_install
    ohai "Speed Monitor v2.0.0 installed!"
    ohai ""
    ohai "New in v2.0.0:"
    ohai "  - WiFi analytics (SSID, BSSID, Band, Channel, Signal)"
    ohai "  - VPN detection (Zscaler, Cisco AnyConnect, GlobalProtect, etc.)"
    ohai "  - Jitter and packet loss measurement"
    ohai "  - Enhanced organization dashboard"
    ohai ""
    ohai "Run 'nkspeedtest setup' to configure"
  end

  def caveats
    <<~EOS
      Speed Monitor v2.0.0 - Organization-Wide Monitoring

      Quick Start:
        nkspeedtest setup          # Configure (run first)
        nkspeedtest run            # Run a speed test now
        nkspeedtest start          # Start automatic monitoring
        nkspeedtest dashboard      # Open local dashboard

      New Features:
        - WiFi metrics: SSID, BSSID, Band, Channel, Signal strength
        - VPN detection: Zscaler, Cisco AnyConnect, GlobalProtect, etc.
        - Jitter & packet loss measurement
        - Organization dashboard with fleet view

      Server (for centralized monitoring):
        cd #{libexec}/server && npm install && npm start

      Data locations:
        Config: ~/.config/nkspeedtest/
        Data:   ~/.local/share/nkspeedtest/
        Logs:   #{var}/speed-monitor/logs/

      WiFi Helper:
        The wifi_info binary uses CoreWLAN to collect WiFi metrics.
        It requires no additional permissions on macOS.
    EOS
  end

  service do
    run [opt_bin/"speed-monitor-collect"]
    run_type :interval
    interval 600  # Run every 10 minutes
    log_path var/"speed-monitor/logs/launchd.log"
    error_log_path var/"speed-monitor/logs/launchd-error.log"
    working_dir var/"speed-monitor"
    environment_variables SPEED_MONITOR_SERVER: ""
  end

  test do
    # Test WiFi helper exists and runs
    assert_predicate bin/"wifi_info", :exist?
    assert_predicate bin/"wifi_info", :executable?

    # Test main CLI
    assert_match "nkspeedtest", shell_output("#{bin}/nkspeedtest --help")

    # Test version
    assert_match "2.0", shell_output("#{bin}/nkspeedtest --version")
  end
end
