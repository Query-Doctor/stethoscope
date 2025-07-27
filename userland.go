// main.go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall" bpf ebpf/bpf.c -- -I./ebpf

type ConnectionEvent struct {
	Fd   uint32
	Ip   uint32
	Port uint16
	_    [2]byte // Padding to match C struct alignment
}

// This struct must match the C struct layout exactly.
type QueryHeader struct {
	Pid          uint32
	Tid          uint32
	QueryLength  uint32
	DatabaseName DatabaseType // Database name, e.g., "postgres" or "sqlite"
	Connection   ConnectionEvent
	Encrypted    uint8
	Comm         [16]byte // Process name, 16 bytes
	Data         [65355]byte
}

type QueryTiming struct {
	Delta      uint32
	Connection ConnectionEvent
}

type DatabaseType uint32

// enum of query types
const (
	DatabasePostgres DatabaseType = iota
	DatabaseSQLite
)

func main() {
	// Subscribe to signals for graceful shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	pg_queries := make(map[ConnectionEvent]QueryHeader)
	pg_timings := make(map[ConnectionEvent]QueryTiming)
	var query_lock sync.Mutex

	// Allow the BPF subsystem to lock memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load BPF objects from the compiled ELF file.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("verifier error: %+v\n", verr)
		} else {
			log.Fatalf("loading BPF objects: %v", err)
		}
	}
	defer objs.Close()

	sslCollector := NewSSLCollector("/proc", &objs)
	defer sslCollector.Close()

	tracepoints := []struct {
		name string
		fn   *ebpf.Program
	}{
		{name: "sys_enter_sendto", fn: objs.HandleSendto},
		{name: "sys_enter_connect", fn: objs.HandleConnect},
		{name: "sys_enter_close", fn: objs.HandleClose},
		{name: "sys_enter_recvfrom", fn: objs.HandleRecvfrom},
		{name: "sys_exit_recvfrom", fn: objs.HandleExitRecvfrom},
	}

	// Attach the tracepoint
	for _, tp := range tracepoints {
		tp, err := link.Tracepoint("syscalls", tp.name, tp.fn, nil)
		if err != nil {
			log.Fatalf("attaching tracepoint: %+v", err)
		}
		defer tp.Close()
	}

	err := sslCollector.AttachSSLUprobes("/usr/lib/x86_64-linux-gnu/libssl.so.3", "v3.0.0")
	if err != nil {
		log.Fatalf("error attaching ssl uprobes: %v", err)
	}

	log.Println("Attached to syscalls:sys_enter_sendto. Waiting for events... (Press Ctrl+C to exit)")

	// Open a perf event reader from the BPF map.
	// The buffer size is set to 64 pages, which should be plenty.
	rd, err := ringbuf.NewReader(objs.PostgresQueries)
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}
	defer rd.Close()

	rd_timing, err := ringbuf.NewReader(objs.QueryTimings)
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}
	defer rd_timing.Close()

	go func() {
		// This goroutine will be stopped when rd.Close() is called.
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %v", err)
				continue
			}

			var header QueryHeader
			headerSize := binary.Size(header)
			if len(record.RawSample) < headerSize {
				log.Printf("raw sample too short")
				continue
			}

			// fmt.Printf("raw sample: %+v\n", record.RawSample[:uint32(headerSize)+header.QueryLength])

			// The data from the kernel is in little-endian format.
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &header); err != nil {
				log.Printf("parsing perf event: %v", err)
				continue
			}

			// Then get Data slice with exact total_len bytes
			// if int(header.TotalLen) > len(record.RawSample)-headerSize {
			// 	log.Printf("total_len larger than available data")
			// 	continue
			// }
			// data := header.Data[:header.QueryLength]

			// ip := header.Connection.Ip
			// formattedIp := fmt.Sprintf("%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
			// log.Printf("%s (%d) [%s:%d] %s", header.Comm, header.Pid,
			// 	formattedIp, header.Connection.Port, string(data))

			query_lock.Lock()
			timing, ok := pg_timings[header.Connection]
			if ok {
				delete(pg_timings, header.Connection)
				emit_query(header, timing)
			} else {
				pg_queries[header.Connection] = header
			}
			query_lock.Unlock()
		}
	}()

	go func() {
		for {
			record, err := rd_timing.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
			}
			var timing QueryTiming
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &timing); err != nil {
				log.Printf("parsing perf event: %v", err)
				continue
			}
			query_lock.Lock()
			query, ok := pg_queries[timing.Connection]
			if ok {
				emit_query(query, timing)
				delete(pg_queries, timing.Connection)
			} else {
				pg_timings[timing.Connection] = timing
			}
			query_lock.Unlock()
		}
	}()

	// Wait for a signal before exiting
	<-stopper
	log.Println("Received signal, exiting...")
}

type QueryResult struct {
	Database        string  `json:"db"`
	Ip          string  `json:"ip"`
	Port        uint16  `json:"port"`
	Pid         uint32  `json:"pid"`
	ProcessName string  `json:"process_name"`
	Query       string  `json:"query"`
	Delta       float64 `json:"delta"`
	Encrypted   bool    `json:"encrypted"`
}

func database_type_to_string(database_type DatabaseType) string {
	switch database_type {
	case DatabasePostgres:
		return "postgres"
	case DatabaseSQLite:
		return "sqlite"
	}
	return "unknown"
}

func emit_query(header QueryHeader, timing QueryTiming) {
	ms := float64(timing.Delta) / 1000000
	query := string(header.Data[:header.QueryLength-1])
	output, err := json.Marshal(QueryResult{
		Database:    database_type_to_string(header.DatabaseName),
		Ip:          fmt.Sprintf("%d.%d.%d.%d", header.Connection.Ip&0xFF, (header.Connection.Ip>>8)&0xFF, (header.Connection.Ip>>16)&0xFF, (header.Connection.Ip>>24)&0xFF),
		Port:        header.Connection.Port,
		Pid:         header.Pid,
		ProcessName: strings.Trim(string(header.Comm[:]), "\x00"),
		Query:       query,
		Delta:       ms,
		Encrypted:   header.Encrypted == 1,
	})
	if err != nil {
		log.Printf("error marshalling query result")
		log.Printf("error: %v", err)
		return
	}
	fmt.Println(string(output))
}
