package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/fatih/color"
    "log"
    "time"
)

var (
    int_face       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main() {

    color.Blue("DNS TIME")
    handle, err = pcap.OpenLive(int_face, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    var filter string = "udp and port 53"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }


    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        fmt.Println(packet)
    }
}
