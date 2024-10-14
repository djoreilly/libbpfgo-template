//go:build linux

package main

import (
	_ "embed"

	"bytes"
	"encoding/binary"
	"flag"
	"log/slog"

	bpf "github.com/aquasecurity/libbpfgo"
)

//go:embed main.bpf.o
var bpfCode []byte

type Event struct {
	Pid      uint32
	Filename [256]byte
}

func main() {
	verbose := flag.Bool("v", false, "enable libbpf debug logging")
	flag.Parse()
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			switch level {
			case bpf.LibbpfInfoLevel:
				slog.Info(msg)
			case bpf.LibbpfWarnLevel:
				slog.Warn(msg)
			case bpf.LibbpfDebugLevel:
				slog.Debug(msg)
			}
		},
	})

	// bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(bpfCode, "")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		_, err = prog.AttachGeneric()
		if err != nil {
			panic(err)
		}
	}

	eventsChan := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChan)
	if err != nil {
		panic(err)
	}
	rb.Poll(300)

	for rawData := range eventsChan {
		var event Event
		err := binary.Read(bytes.NewBuffer(rawData), binary.NativeEndian, &event)
		if err != nil {
			panic(err)
		}
		endIndex := bytes.Index(event.Filename[:], []byte{0})
		filename := event.Filename[:endIndex]
		slog.Info("Event", "PID", event.Pid, "Filename", filename)
	}
}
