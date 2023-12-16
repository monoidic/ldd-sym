package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type parseOptions struct {
	getFunc   bool
	getObject bool
	getOther  bool
}

type baseInfo struct {
	syms    []elf.Symbol
	sonames []string
	runpath string

	symnameToSonames map[string][]string
}

func parseBase(elfPath string, options parseOptions) baseInfo {
	f := check1(elf.Open(elfPath))
	defer f.Close()

	var syms []elf.Symbol

	for _, sym := range check1(f.DynamicSymbols()) {
		stt := elf.ST_TYPE(sym.Info)
		isFunc := stt == elf.STT_FUNC
		isObj := stt == elf.STT_OBJECT
		// does not match argument filters
		if !((options.getFunc && isFunc) || (options.getObject && isObj) || (options.getOther && !(isFunc || isObj))) {
			continue
		}
		// defined within this file
		if sym.Section != elf.SHN_UNDEF {
			continue
		}

		syms = append(syms, sym)
	}

	return baseInfo{
		syms:    syms,
		sonames: check1(f.DynString(elf.DT_NEEDED)),
		runpath: getRunPath(f),
	}
}

func getRunPath(f *elf.File) string {
	runpath, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		return runpath[0]
	}
	runpath, err = f.DynString(elf.DT_RPATH)
	if err != nil {
		return runpath[0]
	}
	return ""
}

var seenConfs = map[string]bool{}

func parseLdSoConfFile(filename string) []string {
	if seenConfs[filename] {
		return nil
	}
	seenConfs[filename] = true

	var out []string

	ldSoConf := check1(os.ReadFile(filename))
	for _, line := range bytes.Split(ldSoConf, []byte("\n")) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if bytes.HasPrefix(line, []byte("include")) {
			for _, filename := range check1(filepath.Glob(filepath.Join("/etc", string(line[8:])))) {
				out = append(out, parseLdSoConfFile(filename)...)
			}
		} else {
			out = append(out, string(line))
		}

	}

	return out
}

func (base *baseInfo) getSymMatches(searchdirs []string) {
	base.symnameToSonames = make(map[string][]string, len(base.syms))
	for _, sym := range base.syms {
		base.symnameToSonames[sym.Name] = nil
	}

	for _, soname := range base.sonames {
		path := getSonamePath(soname, searchdirs)
		for _, sym := range getSyms(path) {
			if sl, exists := base.symnameToSonames[sym.Name]; exists {
				base.symnameToSonames[sym.Name] = append(sl, soname)
			}
		}
	}
}

func getSyms(path string) []elf.Symbol {
	f := check1(elf.Open(path))
	defer f.Close()

	var out []elf.Symbol
	seen := make(map[string]bool)

	for _, sym := range check1(f.DynamicSymbols()) {
		if sym.Section != elf.SHN_UNDEF && !seen[sym.Name] {
			out = append(out, sym)
			seen[sym.Name] = true
		}
	}

	return out
}

func getSonamePath(soname string, searchdirs []string) string {
	for _, dir := range searchdirs {
		path := filepath.Join(dir, soname)
		if fileExists(path) {
			return path
		}
	}
	panic(fmt.Sprintf("cannot find SONAME=%q with searchdirs %#v", soname, searchdirs))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if !errors.Is(err, os.ErrNotExist) {
		check(err)
	}
	return false
}

func main() {
	var elfPath string
	var options parseOptions
	flag.StringVar(&elfPath, "path", "", "path to file")
	flag.BoolVar(&options.getFunc, "funcs", true, "track functions")
	flag.BoolVar(&options.getObject, "objects", true, "track objects")
	flag.BoolVar(&options.getOther, "other", false, "track other symbols")
	flag.Parse()

	if elfPath == "" {
		fmt.Println("path not specified")
		os.Exit(1)
	}

	if !(options.getFunc || options.getObject || options.getOther) {
		fmt.Println("all symbol types disabled")
		os.Exit(1)
	}

	base := parseBase(elfPath, options)

	var searchdirs []string
	if base.runpath != "" {
		searchdirs = append(searchdirs, base.runpath)
	}
	searchdirs = append(searchdirs, "/lib64", "/usr/lib64")
	searchdirs = append(searchdirs, parseLdSoConfFile("/etc/ld.so.conf")...)
	base.getSymMatches(searchdirs)

	for _, sym := range base.syms {
		sym := sym.Name
		sonames := base.symnameToSonames[sym]
		if sonames == nil {
			fmt.Printf("%s: NO MATCHES\n", sym)
		} else {
			fmt.Printf("%s: %s\n", sym, strings.Join(sonames, ", "))
		}
	}
}

func check(err error) {
	if err != nil {
		log.Panicf("%v", err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}
