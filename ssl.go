// code is partially adopted from https://github.com/getanteon/alaz/blob/master/ebpf/collector.go
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/mod/semver"
)

type SSLCollector struct {
	procfs string
	objs   *bpfObjects
	links  []link.Link
}

func NewSSLCollector(procfs string, objs *bpfObjects) *SSLCollector {
	return &SSLCollector{
		procfs: procfs,
		links:  make([]link.Link, 3),
		objs:   objs,
	}
}

func (s *SSLCollector) Close() error {
	for _, link := range s.links {
		if err := link.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *SSLCollector) AttachSSLUprobes(executablePath string, version string) error {
	ex, err := link.OpenExecutable(executablePath)
	if err != nil {
		log.Printf("error opening executable %s", executablePath)
		return err
	}

	if semver.Compare(version, "v3.0.0") >= 0 {
		log.Printf("attaching ssl uprobes v3")

		s.links[0], err = ex.Uprobe("SSL_write", s.objs.SslWrite, nil)
		if err != nil {
			log.Printf("error attaching %s uprobe", "SSL_write")
			return err
		}
		s.links[1], err = ex.Uprobe("SSL_read", s.objs.SslRead, nil)
		if err != nil {
			log.Printf("error attaching %s uprobe", "SSL_read")
			return err
		}
		s.links[2], err = ex.Uretprobe("SSL_read", s.objs.SslRetRead, nil)
		if err != nil {
			log.Printf("error attaching %s uprobe", "SSL_read")
			return err
		}
	} else {
		return fmt.Errorf("unsupported ssl version: %s", version)
	}

	return err
}

func (s *SSLCollector) AttachSslUprobesOnProcess(pid uint32) []error {
	errors := make([]error, 0)
	sslLibs, err := findSSLExecutablesByPid(s.procfs, pid)

	if err != nil {
		log.Printf("error finding ssl lib: %v", err)
		return errors
	}

	if len(sslLibs) == 0 {
		log.Printf("no ssl lib found")
		return errors
	}

	for _, sslLib := range sslLibs {
		err = s.AttachSSLUprobes(sslLib.path, sslLib.version)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

func findSSLExecutablesByPid(procfs string, pid uint32) (map[string]*sslLib, error) {
	// look for memory mapping of the process
	file, err := os.Open(fmt.Sprintf("%s/%d/maps", procfs, pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	libsMap, err := parseSSLlib(toString(fileContent))
	if err != nil {
		return nil, err
	}

	for libPath, _ := range libsMap {
		fullpath := fmt.Sprintf("%s/%d/root%s", procfs, pid, libPath)

		// modify parsed path to match the full path
		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			delete(libsMap, libPath)
		} else {
			l := libsMap[libPath]
			l.path = fullpath
		}
	}

	// key : parsed path
	// value : full path and version
	return libsMap, nil
}

var libSSLRegex string = `.*libssl(?P<AdjacentVersion>\d)*-*.*\.so\.*(?P<SuffixVersion>[0-9\.]+)*.*`
var re *regexp.Regexp

func init() {
	re = regexp.MustCompile(libSSLRegex)
}

type sslLib struct {
	path    string
	version string
}

func parseSSLlib(text string) (map[string]*sslLib, error) {
	res := make(map[string]*sslLib)
	matches := re.FindAllStringSubmatch(text, -1)

	if matches == nil {
		return nil, fmt.Errorf("no ssl lib found")
	}

	for _, groups := range matches {
		match := groups[0]

		paramsMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i > 0 && i <= len(groups) {
				paramsMap[name] = groups[i]
			}
		}

		// paramsMap
		// k : AdjacentVersion or SuffixVersion
		// v : 1.0.2 or 3 ...

		var version string
		if paramsMap["AdjacentVersion"] != "" {
			version = paramsMap["AdjacentVersion"]
		} else if paramsMap["SuffixVersion"] != "" {
			version = paramsMap["SuffixVersion"]
		} else {
			continue
		}

		// add "v." prefix
		if version != "" {
			version = "v" + version
		}

		path := getPath(match)
		res[path] = &sslLib{
			path:    path,
			version: version,
		}
	}

	return res, nil
}

func getPath(mappingLine string) string {
	mappingLine = strings.TrimSpace(mappingLine)
	elems := strings.Split(mappingLine, " ")

	// edge case
	// /usr/lib64/libssl.so.1.0.2k (deleted)

	path := elems[len(elems)-1]

	if strings.Contains(path, "(deleted)") {
		path = elems[len(elems)-2]
	}

	return path
}

// to avoid allocations
func toBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}
func toString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
