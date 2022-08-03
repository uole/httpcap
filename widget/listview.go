package widget

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/jroimartin/gocui"
	"sync"
)

type (
	FormatFunc func(i int, v interface{}) string

	ChangeFunc func(i int, v interface{})

	ListView struct {
		name          string
		title         string
		cursor        int
		ui            *gocui.Gui
		view          *gocui.View
		formatFunc    FormatFunc
		changeFunc    ChangeFunc
		clientWidth   int
		clientHeight  int
		offsetX       int
		offsetY       int
		contentWidth  int
		contentHeight int
		visibleOffset int
		once          sync.Once
		mutex         sync.RWMutex
		values        []interface{}
	}
)

func (widget *ListView) draw() {
	contentVisibleLines := widget.visibleLines() - 2 //2px border
	if widget.cursor > widget.visibleOffset {
		if widget.cursor-widget.visibleOffset > contentVisibleLines {
			widget.visibleOffset = widget.cursor - contentVisibleLines
		}
	}
	if widget.cursor < widget.visibleOffset {
		widget.visibleOffset = widget.cursor
	}
	widget.ui.Update(func(gui *gocui.Gui) error {
		if view, err := gui.View(widget.name); err == nil {
			view.Clear()
			for i := widget.visibleOffset; i < len(widget.values); i++ {
				var str string
				if widget.formatFunc == nil {
					str = fmt.Sprint(widget.values[i])
				} else {
					str = widget.formatFunc(i, widget.values[i])
				}
				if i == widget.cursor {
					_, _ = color.New(color.FgGreen).Fprintln(view, str)
				} else {
					_, _ = fmt.Fprintln(view, str)
				}
			}
		}
		return nil
	})
}

func (widget *ListView) Title(s string) *ListView {
	widget.title = s
	return widget
}

func (widget *ListView) Offset(x, y int) *ListView {
	widget.offsetX = x
	widget.offsetY = y
	return widget
}

func (widget *ListView) WithFormat(f FormatFunc) *ListView {
	widget.formatFunc = f
	return widget
}

func (widget *ListView) WithChange(f ChangeFunc) *ListView {
	widget.changeFunc = f
	return widget
}

func (widget *ListView) Push(v interface{}) {
	widget.mutex.Lock()
	defer widget.mutex.Unlock()
	widget.values = append(widget.values, v)
	contentVisibleLines := widget.visibleLines() - 2
	if len(widget.values) < contentVisibleLines || len(widget.values) <= widget.visibleOffset+contentVisibleLines+1 {
		widget.draw()
	}
}

func (widget *ListView) visibleLines() int {
	var (
		n int
	)
	if widget.contentHeight == 0 {
		n = widget.clientHeight - widget.offsetY - 1
	} else {
		if widget.contentHeight < 0 {
			n = (widget.clientHeight + widget.contentHeight)
		} else {
			n = widget.contentHeight
		}
	}
	return n
}

func (widget *ListView) MoveNext() (v interface{}) {
	widget.mutex.RLock()
	defer widget.mutex.RUnlock()
	if len(widget.values) == 0 {

		return nil
	}
	if widget.cursor < len(widget.values)-1 {
		widget.cursor++
	}
	v = widget.values[widget.cursor]
	if widget.changeFunc != nil {
		widget.changeFunc(widget.cursor, v)
	}
	widget.draw()
	return v
}

func (widget *ListView) MovePrev() (v interface{}) {
	widget.mutex.RLock()
	defer widget.mutex.RUnlock()
	if len(widget.values) == 0 {
		return nil
	}
	if widget.cursor > 0 {
		widget.cursor--
	}
	v = widget.values[widget.cursor]
	if widget.changeFunc != nil {
		widget.changeFunc(widget.cursor, v)
	}
	widget.draw()
	return v
}

func (widget *ListView) Reset(f func(v interface{})) {
	widget.mutex.Lock()
	defer widget.mutex.Unlock()
	if f == nil {
		for _, v := range widget.values {
			f(v)
		}
	}
	widget.values = make([]interface{}, 0)
	widget.visibleOffset = 0
	widget.cursor = 0
	widget.ui.Update(func(gui *gocui.Gui) error {
		if view, err := gui.View(widget.name); err == nil {
			view.Clear()
			return nil
		} else {
			return err
		}
	})
}

func (widget *ListView) Layout(ui *gocui.Gui) (err error) {
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
	widget.once.Do(func() {
		err = ui.SetKeybinding(widget.name, gocui.KeyArrowUp, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
			if view.Name() == widget.name {
				widget.MovePrev()
			}
			return nil
		})
		err = ui.SetKeybinding(widget.name, gocui.KeyArrowDown, gocui.ModNone, func(gui *gocui.Gui, view *gocui.View) error {
			if view.Name() == widget.name {
				widget.MoveNext()
			}
			return nil
		})
	})
	if ui.CurrentView() == nil {
		_, _ = ui.SetCurrentView(widget.name)
	}
	return
}

func NewListView(name string, width int, height int) *ListView {
	return &ListView{
		name:          name,
		contentWidth:  width,
		contentHeight: height,
		values:        make([]interface{}, 0),
	}
}
