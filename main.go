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
	"slices"
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
	runpath []string

	symnameToSonames map[string][]string
	unneededSonames  []string
}

func parseBase(elfPath string, options parseOptions) (*baseInfo, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var syms []elf.Symbol

	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		return nil, err
	}

	for _, sym := range dynSyms {
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

	return &baseInfo{
		syms:    syms,
		sonames: check1(f.DynString(elf.DT_NEEDED)),
		runpath: getRunPath(f, elfPath),
	}, nil
}

func getRunPath(f *elf.File, elfPath string) []string {
	dirs := readRunPath(f)
	if dirs == nil {
		return dirs
	}

	base := filepath.Dir(elfPath)

	for i, dir := range dirs {
		if !strings.Contains(dir, "$ORIGIN") {
			continue
		}
		dirs[i] = check1(filepath.Abs(strings.Replace(dir, "$ORIGIN", base, -1)))
	}
	return dirs
}

func readRunPath(f *elf.File) []string {
	runpath, err := f.DynString(elf.DT_RUNPATH)
	if err == nil && len(runpath) != 0 {
		return strings.Split(runpath[0], ":")
	}

	runpath, err = f.DynString(elf.DT_RPATH)
	if err == nil && len(runpath) != 0 {
		return strings.Split(runpath[0], ":")
	}

	return nil
}

func parseLdSoConfFile(filename string, seenConfs map[string]bool) []string {
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
				out = append(out, parseLdSoConfFile(filename, seenConfs)...)
			}
		} else {
			out = append(out, string(line))
		}

	}

	return out
}

func (base *baseInfo) getSymMatches(searchdirs []string) error {
	base.symnameToSonames = make(map[string][]string, len(base.syms))
	for _, sym := range base.syms {
		base.symnameToSonames[sym.Name] = nil
	}

	seenSonames := make(map[string]bool)
	for _, soname := range base.sonames {
		seenSonames[soname] = true
	}

	var sonameStack stack[string]
	sonameStack.pushMultipleRev(base.sonames)

	var unneededSonames []string

	for {
		soname, success := sonameStack.pop()
		if !success {
			break
		}

		sonameNeeded := false

		for _, path := range getSonamePaths(soname, searchdirs) {
			syms, sonames, err := getSyms(path)
			if err != nil {
				return err
			}

			for _, soname := range sonames {
				if !seenSonames[soname] {
					sonameStack.push(soname)
					seenSonames[soname] = true
				}
			}

			for _, sym := range syms {
				if sl, exists := base.symnameToSonames[sym.Name]; exists {
					if !slices.Contains(sl, soname) {
						base.symnameToSonames[sym.Name] = append(sl, soname)
						sonameNeeded = true
					}
				}
			}
		}

		if !sonameNeeded && slices.Contains(base.sonames, soname) {
			unneededSonames = append(unneededSonames, soname)
		}
	}

	base.unneededSonames = unneededSonames
	return nil
}

func getSyms(path string) ([]elf.Symbol, []string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var out []elf.Symbol
	seen := make(map[string]bool)

	for _, sym := range check1(f.DynamicSymbols()) {
		if sym.Section != elf.SHN_UNDEF && !seen[sym.Name] {
			out = append(out, sym)
			seen[sym.Name] = true
		}
	}

	sonames := check1(f.DynString(elf.DT_NEEDED))

	return out, sonames, nil
}

func getSonamePaths(soname string, searchdirs []string) []string {
	var ret []string
	for _, dir := range searchdirs {
		path := filepath.Join(dir, soname)
		if fileExists(path) {
			ret = append(ret, path)
		}
	}
	return ret
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
		fmt.Fprintln(os.Stderr, "path not specified")
		os.Exit(1)
	}

	elfPath = check1(filepath.EvalSymlinks(check1(filepath.Abs(elfPath))))

	if !(options.getFunc || options.getObject || options.getOther) {
		fmt.Println("all symbol types disabled")
		os.Exit(1)
	}

	base, err := parseBase(elfPath, options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parseBase: %v\n", err)
		os.Exit(1)
	}


	searchdirs := getSearchdirs(base.runpath)

	err = base.getSymMatches(searchdirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getSymMatches: %v\n", err)
		os.Exit(1)
	}

	var undefinedSyms []string

	for _, sym := range base.syms {
		sym := sym.Name
		sonames := base.symnameToSonames[sym]
		if sonames == nil {
			fmt.Printf("%s: NO MATCHES\n", sym)
			undefinedSyms = append(undefinedSyms, sym)
		} else {
			fmt.Printf("%s: %s\n", sym, strings.Join(sonames, ", "))
		}
	}

	if !(len(base.unneededSonames) > 0 || len(undefinedSyms) > 0) {
		return
	}

	fmt.Println()
	if len(base.unneededSonames) > 0 {
		fmt.Printf("UNNEEDED: %s\n", strings.Join(base.unneededSonames, ", "))
	}

	if len(undefinedSyms) > 0 {
		fmt.Printf("UNDEFINED: %s\n", strings.Join(undefinedSyms, ", "))
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

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	// reverse sorted order, to pop in "the right" order
	slices.Reverse(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) push(e T) {
	s.l = append(s.l, e)
}

func (s *stack[T]) pop() (T, bool) {
	var top T
	size := len(s.l)
	if size == 0 {
		return top, false
	}

	top = s.l[size-1]
	s.l = s.l[:size-1]
	return top, true
}
