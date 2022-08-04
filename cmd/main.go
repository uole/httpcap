package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/uole/httpcap"
	"github.com/uole/httpcap/version"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"strconv"
	"time"
)

var (
	numReg = regexp.MustCompile(`^\d+$`)
)

var (
	ifaceFlag   = flag.String("i", "", "name or index of interface")
	filterFlag  = flag.String("f", "", "BPF filter in libpcap filter syntax")
	portFlag    = flag.Int("p", 0, "filter source or target port")
	ipFlag      = flag.String("ip", "", "filter source or target ip")
	hostFlag    = flag.String("host", "", "filter http request host, using wildcard match(*)")
	versionFlag = flag.Bool("v", false, "display version info and exit")
	deviceFlag  = flag.Bool("l", false, "list of interfaces and exit")
	pprofFlag   = flag.Bool("pprof", false, "Enable http debug pprof")
)

func printInterface(ins []pcap.Interface) {
	var (
		maxLength int
	)
	for _, i := range ins {
		if len(i.Name) > maxLength {
			maxLength = len(i.Name)
		}
	}
	fmt.Printf("%-6s %-"+strconv.Itoa(maxLength+2)+"s %-16s %s\n", "Index", "Name", "IP", "Description")
	for idx, i := range ins {
		ipAddr := ""
		if len(i.Addresses) > 0 {
			for _, addr := range i.Addresses {
				if len(addr.IP) == net.IPv4len {
					ipAddr = addr.IP.String()
				}
			}
		}
		fmt.Printf("%-6d %-"+strconv.Itoa(maxLength+2)+"s %-16s %s\n", idx, i.Name, ipAddr, i.Description)
	}
}

func main() {
	var (
		err   error
		iface string
		ins   []pcap.Interface
	)
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Info())
		os.Exit(0)
	}
	if ins, err = pcap.FindAllDevs(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	if *deviceFlag {
		printInterface(ins)
		os.Exit(0)
	}
	if *pprofFlag {
		go func() {
			_ = http.ListenAndServe(":8080", nil)
		}()
	}
	if numReg.MatchString(*ifaceFlag) {
		i, _ := strconv.Atoi(*ifaceFlag)
		if i < len(ins) {
			iface = ins[i].Name
		}
	} else {
		for _, i := range ins {
			if i.Name == *ifaceFlag {
				iface = i.Name
				break
			}
		}
	}
	if iface == "" {
		printInterface(ins)
		os.Exit(0)
	}
	fmt.Println(iface)
	time.Sleep(time.Second)
	app := httpcap.NewApp(&httpcap.Filter{
		IP:   *ipFlag,
		Port: *portFlag,
		Host: *hostFlag,
		BPF:  *filterFlag,
	})
	if err = app.Run(context.Background(), iface); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
