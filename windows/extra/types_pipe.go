package extra

import (
	wincall "golang.org/x/sys/windows"
)

// PipeHandle Make an Input/Output Anonymous Pipe
type PipeHandle []wincall.Handle

func MakePipe() (p PipeHandle, err error) {
	p = make(PipeHandle, 2)
	err = wincall.Pipe(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PipeHandle) Init() (err error) {
	return wincall.Pipe(*p)
}

func (p PipeHandle) Read(b []byte) (n int, err error) {
	return wincall.Read(p[0], b)
}

func (p PipeHandle) Write(b []byte) (n int, err error) {
	return wincall.Write(p[1], b)
}
