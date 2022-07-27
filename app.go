package httpcap

import (
	"context"
	"errors"
	"fmt"
	"github.com/jroimartin/gocui"
	"github.com/uole/httpcap/http"
	"github.com/uole/httpcap/widget"
	"github.com/valyala/bytebufferpool"
)

type (
	packet struct {
		request  *http.Request
		response *http.Response
	}

	App struct {
		filter        *Filter
		ctx           context.Context
		cancelFun     context.CancelFunc
		ui            *gocui.Gui
		capture       *Capture
		pauseFlag     bool
		sideWidget    *widget.ListView
		contentWidget *widget.ContentView
	}
)

func (app *App) Handle(req *http.Request, res *http.Response) {
	if app.pauseFlag {
		return
	}
	app.sideWidget.Push(&packet{request: req, response: res})
}

func (app *App) initLayout() (err error) {
	app.sideWidget = widget.NewListView("side", 50, 0).Title("Requests").
		WithFormat(func(i int, v interface{}) string {
			if p, ok := v.(*packet); ok {
				return fmt.Sprintf("[%3d] %s %s", i, p.request.Method, p.request.RequestURI)
			}
			return ""
		}).
		WithChange(func(i int, v interface{}) {
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
		})
	app.contentWidget = widget.NewContentView("main", 0, 0).Offset(51, 0).Editable().Title("Raw")
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
		app.pauseFlag = !app.pauseFlag
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
	app.ui.SetManager(app.sideWidget, app.contentWidget)
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
	if err = app.ui.MainLoop(); err != nil {
		if errors.Is(err, gocui.ErrQuit) {
			err = nil
		}
	}
	return
}

func NewApp(filter *Filter) *App {
	return &App{
		filter: filter,
	}
}
