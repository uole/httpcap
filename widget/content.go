package widget

import (
	"errors"
	"fmt"
	"github.com/jroimartin/gocui"
)

type ContentView struct {
	name          string
	title         string
	content       string
	clientWidth   int
	clientHeight  int
	offsetX       int
	offsetY       int
	contentWidth  int
	contentHeight int
	editable      bool
	ui            *gocui.Gui
	view          *gocui.View
}

func (widget *ContentView) Write(p []byte) (n int, err error) {
	if widget.editable {
		_ = widget.view.SetOrigin(0, 0)
		_ = widget.view.SetCursor(0, 0)
	}
	widget.view.Clear()
	n, err = widget.view.Write(p)
	widget.ui.Update(func(gui *gocui.Gui) error {
		return nil
	})
	return
}

func (widget *ContentView) draw() {
	if widget.ui == nil {
		return
	}
	widget.ui.Update(func(gui *gocui.Gui) error {
		if view, err := gui.View(widget.name); err == nil {
			view.Clear()
			if widget.editable {
				_ = view.SetOrigin(0, 0)
				_ = view.SetCursor(0, 0)
			}
			_, _ = fmt.Fprintln(view, widget.content)
		}
		return nil
	})
}

func (widget *ContentView) SetContent(s string) *ContentView {
	widget.content = s
	widget.draw()
	return widget
}

func (widget *ContentView) AppendString(s string) {
	widget.content += s
	widget.draw()
}

func (widget *ContentView) Offset(x, y int) *ContentView {
	widget.offsetX = x
	widget.offsetY = y
	return widget
}

func (widget *ContentView) Title(s string) *ContentView {
	widget.title = s
	return widget
}

func (widget *ContentView) Editable() *ContentView {
	if widget.view != nil {
		widget.view.Editable = true
	}
	widget.editable = true
	return widget
}

func (widget *ContentView) Layout(ui *gocui.Gui) (err error) {
	var (
		x, y             int
		offsetX, offsetY int
	)
	widget.ui = ui
	widget.clientWidth, widget.clientHeight = ui.Size()
	if widget.offsetX < 0 {
		offsetX = widget.clientWidth + widget.offsetX
	} else {
		offsetX = widget.offsetX
	}
	if widget.offsetY < 0 {
		offsetY = widget.clientHeight + widget.offsetY
	} else {
		offsetY = widget.offsetY
	}
	if widget.contentWidth == 0 {
		x = widget.clientWidth - 1
	} else {
		if widget.contentWidth < 0 {
			x = offsetX + (widget.clientWidth + widget.contentWidth)
		} else {
			x = offsetX + widget.contentWidth
		}
	}
	if widget.contentHeight == 0 {
		y = widget.clientHeight - widget.offsetY - 1
	} else {
		if widget.contentHeight < 0 {
			y = offsetY + (widget.clientHeight + widget.contentHeight)
		} else {
			y = offsetY + widget.contentHeight
		}
	}
	if widget.view, err = ui.SetView(widget.name, offsetX, offsetY, x, y); err != nil {
		if !errors.Is(err, gocui.ErrUnknownView) {
			return
		}
		err = nil
	}
	if widget.title != "" {
		widget.view.Title = widget.title
	}
	if widget.content != "" {
		_, _ = fmt.Fprintln(widget.view, widget.content)
	}
	if widget.editable {
		widget.view.Editable = true
		widget.view.Wrap = true
		ui.Cursor = true
	}
	return
}

func NewContentView(name string, width int, height int) *ContentView {
	return &ContentView{
		name:          name,
		contentWidth:  width,
		contentHeight: height,
	}
}
