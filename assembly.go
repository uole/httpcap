package httpcap

import "github.com/google/gopacket"

type (
	AssemblerContext struct {
		captureInfo gopacket.CaptureInfo
	}
)

func (ctx *AssemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return ctx.captureInfo
}
