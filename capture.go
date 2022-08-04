package httpcap

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/uole/httpcap/http"
	"github.com/uole/httpcap/internal/factory"
	tcpFactory "github.com/uole/httpcap/internal/factory/tcp"
	"strconv"
	"strings"
	"time"
)

type Capture struct {
	ctx        context.Context
	iface      string
	snaplen    int
	filter     *Filter
	packChan   chan gopacket.Packet
	handle     *pcap.Handle
	handleFunc factory.HandleFunc
}

func (cap *Capture) process(req *http.Request, res *http.Response) {
	if !cap.filter.Match(req.Host) {
		req.Release()
		res.Release()
		return
	}
	if cap.handleFunc != nil {
		cap.handleFunc(req, res)
	}
}

func (cap *Capture) ioLoop(assembler *reassembly.Assembler) {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		ticker.Stop()
		assembler.FlushAll()
	}()
	for {
		select {
		case pkg := <-cap.packChan:
			if pkg == nil {
				return
			}
			if tcp, ok := pkg.TransportLayer().(*layers.TCP); ok {
				assembler.AssembleWithContext(pkg.NetworkLayer().NetworkFlow(), tcp, &AssemblerContext{captureInfo: pkg.Metadata().CaptureInfo})
			}
		case <-ticker.C:
			assembler.FlushCloseOlderThan(time.Now().Add(time.Minute * -3))
		case <-cap.ctx.Done():
			return
		}
	}
}

func (cap *Capture) grantRules() []string {
	rules := make([]string, 0)
	rules = append(rules, "tcp")
	if cap.filter.Port > 0 {
		rules = append(rules, "port "+strconv.Itoa(cap.filter.Port))
	}
	if cap.filter.IP != "" {
		rules = append(rules, "host "+cap.filter.IP)
	}
	return rules
}

func (cap *Capture) WithHandle(f factory.HandleFunc) *Capture {
	cap.handleFunc = f
	return cap
}

func (cap *Capture) Start(ctx context.Context) (err error) {
	var (
		ifs       []pcap.Interface
		rules     []string
		assembler *reassembly.Assembler
	)
	cap.ctx = ctx
	if cap.iface == "" {
		if ifs, err = pcap.FindAllDevs(); err != nil {
			return
		}
		for _, i := range ifs {
			fmt.Println(i.Name, i.Description, i.Addresses)
		}
	}
	if cap.handle, err = pcap.OpenLive(cap.iface, int32(cap.snaplen), true, pcap.BlockForever); err != nil {
		return
	}
	if cap.filter.BPF != "" {
		if err = cap.handle.SetBPFFilter(cap.filter.BPF); err != nil {
			return
		}
	} else {
		rules = cap.grantRules()
		if len(rules) > 0 {
			bpf := strings.Join(rules, " and ")
			if err = cap.handle.SetBPFFilter(bpf); err != nil {
				return
			}
		}
	}
	streamFactory := tcpFactory.New(cap.ctx, cap.process)
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler = reassembly.NewAssembler(streamPool)
	source := gopacket.NewPacketSource(cap.handle, cap.handle.LinkType())
	source.NoCopy = true
	cap.packChan = source.Packets()
	go cap.ioLoop(assembler)
	return
}

func (cap *Capture) Stop() (err error) {
	cap.handle.Close()
	return
}

func NewCapture(iface string, snaplen int, filter *Filter) *Capture {
	return &Capture{
		iface:   iface,
		snaplen: snaplen,
		filter:  filter,
	}
}
