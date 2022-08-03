package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/uole/httpcap"
	"github.com/uole/httpcap/version"
	"net/http"
	_ "net/http/pprof"
	"os"
)

var (
	ifaceFlag   = flag.String("i", "eth0", "name of interface")
	filterFlag  = flag.String("f", "", "packet filter in libpcap filter syntax")
	portFlag    = flag.Int("p", 0, "filter source or target port")
	ipFlag      = flag.String("ip", "", "filter source or target ip")
	hostFlag    = flag.String("host", "", "filter http request host, using wildcard match(*)")
	versionFlag = flag.Bool("v", false, "display version info and exit")
	deviceFlag  = flag.Bool("l", false, "list of interfaces and exit")
	pprofFlag   = flag.Bool("pprof", false, "Enable http debug pprof")
)

func main() {
	var (
		err error
		ins []pcap.Interface
	)
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Info())
		os.Exit(0)
	}
	if *deviceFlag {
		if ins, err = pcap.FindAllDevs(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Printf("%-36s %s\n", "Name", "Description")
		for _, i := range ins {
			fmt.Printf("%-36s %s\n", i.Name, i.Description)
		}
		os.Exit(0)
	}
	if *pprofFlag {
		go func() {
			_ = http.ListenAndServe(":8080", nil)
		}()
	}
	app := httpcap.NewApp(&httpcap.Filter{
		IP:   *ipFlag,
		Port: *portFlag,
		Host: *hostFlag,
		BPF:  *filterFlag,
	})
	if err = app.Run(context.Background(), *ifaceFlag); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
