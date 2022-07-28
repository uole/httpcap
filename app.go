package httpcap

import (
	"context"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/jroimartin/gocui"
	"github.com/uole/httpcap/http"
	"github.com/uole/httpcap/widget"
	"github.com/valyala/bytebufferpool"
	"strconv"
	"strings"
	"time"
)

type (
	packet struct {
		request  *http.Request
		response *http.Response
	}

	State struct {
		paused       bool
		NumOfCapture int
	}

	App struct {
		filter        *Filter
		ctx           context.Context
		cancelFun     context.CancelFunc
		ui            *gocui.Gui
		capture       *Capture
		state         *State
		sideWidget    *widget.ListView
		contentWidget *widget.ContentView
		footerWidget  *widget.ContentView
	}
)

func (app *App) Handle(req *http.Request, res *http.Response) {
	if app.state.paused {
		return
	}
	app.state.NumOfCapture++
	app.sideWidget.Push(&packet{request: req, response: res})
}

func (app *App) ioLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			app.updateSummary()
		}
	}
}

func (app *App) formatRequest(idx int, v interface{}) string {
	if p, ok := v.(*packet); ok {
		method := fmt.Sprintf("%-4s", p.request.Method)
		return fmt.Sprintf("[%3d] %s %s", idx, method, p.request.RequestURI)
	}
	return ""
}

func (app *App) updateSummary() {
	msg := make([]string, 0)
	if app.state.paused {
		msg = append(msg, color.New(color.FgBlack, color.BgRed).Sprintf("%-8s", "Pause"))
	} else {
		msg = append(msg, color.New(color.FgBlack, color.BgGreen).Sprintf("%-8s", "Capture"))
	}
	msg = append(msg, color.BlueString("Requests")+" "+strconv.Itoa(app.state.NumOfCapture))
	msg = append(msg, fmt.Sprintf("%s %s Exit %s Swtich %s Clear %s Pause/Capture",
		color.BlueString("Shortcut"),
		color.MagentaString("^C"),
		color.MagentaString("Tab"),
		color.MagentaString("F5"),
		color.MagentaString("F6"),
	))

	app.footerWidget.SetContent(strings.Join(msg, "    "))
}

func (app *App) handleSelectedChange(i int, v interface{}) {
	if p, ok := v.(*packet); ok {
		buf := bytebufferpool.Get()
		_, _ = p.request.WriteTo(buf)
		_, _ = buf.WriteString("\r\n\r\n")
		_, _ = p.response.WriteTo(buf)
		b := buf.Bytes()
		for idx := 0; idx < len(b); idx++ {
			if b[idx] == '\r' {
				b[idx] = ' '
			}
		}
		_, _ = app.contentWidget.Write(b)
		bytebufferpool.Put(buf)
	}
}

func (app *App) initLayout() (err error) {
	app.sideWidget = widget.NewListView("side", 36, -4).Title("Requests").
		WithFormat(app.formatRequest).
		WithChange(app.handleSelectedChange)
	app.contentWidget = widget.NewContentView("main", 0, -4).Offset(37, 0).Editable().Title("Raw Content")
	app.footerWidget = widget.NewContentView("footer", 0, 2).Offset(0, -3).Title("Summary")
	return
}

func (app *App) initCapture(iface string) (err error) {
	app.capture = NewCapture(iface, 65535, app.filter)
	app.capture.WithHandle(app.Handle)
	err = app.capture.Start(app.ctx)
	return
}

func (app *App) initKeybindings() (err error) {
	if err = app.ui.SetKeybinding("", gocui.KeyF5, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
		app.sideWidget.Reset()
		app.state.NumOfCapture = 0
		app.updateSummary()
		return nil
	}); err != nil {
		return
	}
	if err = app.ui.SetKeybinding("", gocui.KeyF6, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
		app.state.paused = !app.state.paused
		app.updateSummary()
		return nil
	}); err != nil {
		return
	}
	if err = app.ui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
		return gocui.ErrQuit
	}); err != nil {
		return
	}
	if err = app.ui.SetKeybinding("", gocui.KeyTab, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
		if view != nil {
			if view.Name() == "side" {
				_, _ = gui.SetCurrentView("main")
			} else {
				_, _ = gui.SetCurrentView("side")
			}
		}
		return nil
	}); err != nil {
		return
	}
	return
}

func (app *App) render() (err error) {
	if err = app.initLayout(); err != nil {
		return
	}
	app.ui.SetManager(app.sideWidget, app.contentWidget, app.footerWidget)
	app.ui.Highlight = true
	app.ui.SelFgColor = gocui.ColorGreen
	err = app.initKeybindings()
	return
}

func (app *App) Run(ctx context.Context, iface string) (err error) {
	app.ctx, app.cancelFun = context.WithCancel(ctx)
	defer func() {
		app.cancelFun()
	}()
	if app.ui, err = gocui.NewGui(gocui.OutputNormal); err != nil {
		return
	}
	defer func() {
		app.ui.Close()
	}()
	if err = app.render(); err != nil {
		return
	}
	if err = app.initCapture(iface); err != nil {
		return
	}
	app.updateSummary()
	go app.ioLoop()
	if err = app.ui.MainLoop(); err != nil {
		if errors.Is(err, gocui.ErrQuit) {
			err = nil
		}
	}
	return
}

func NewApp(filter *Filter) *App {
	return &App{
		state:  &State{},
		filter: filter,
	}
}
