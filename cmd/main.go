package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/uole/httpcap"
	"github.com/uole/httpcap/version"
	"os"
)

var (
	ifaceFlag   = flag.String("iface", "\\Device\\NPF_{2BB79E5F-A4A4-4897-962F-81D4026235D0}", "name of interface")
	portFlag    = flag.Int("port", 0, "filter source or target port")
	ipFlag      = flag.String("ip", "", "filter source or target ip")
	hostFlag    = flag.String("host", "", "filter http request host, using wildcard match(*)")
	versionFlag = flag.Bool("version", false, "display version info and exit")
)

func main() {
	var (
		err error
	)
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Info())
		os.Exit(0)
	}
	app := httpcap.NewApp(&httpcap.Filter{
		IP:   *ipFlag,
		Port: *portFlag,
		Host: *hostFlag,
	})
	if err = app.Run(context.Background(), *ifaceFlag); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
