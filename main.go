package main

import (
	"bytes"
	"debug/elf"
	"encoding/json"
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
	full      bool
}

type sonameWithSearchdirs struct {
	soname     string
	searchdirs []string
}

type baseInfo struct {
	syms    []string
	sonames []string
	runpath []string

	symnameToSonames map[string][]string
	unneededSonames  []string

	options parseOptions
	machine elf.Machine
	class   elf.Class
}

type LddResults struct {
	// for correct order
	Syms    []string
	Sonames []string

	SymnameToSonames map[string][]string
	UnneededSonames  []string
	UndefinedSyms    []string
}

func parseBase(elfPath string, options parseOptions) (*baseInfo, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var syms []string

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

		syms = append(syms, sym.Name)
	}

	sonames := check1(f.DynString(elf.DT_NEEDED))
	if sonames == nil {
		sonames = []string{}
	}

	return &baseInfo{
		syms:    syms,
		sonames: sonames,
		runpath: getRunPath(f, elfPath),
		options: options,
		machine: f.Machine,
		class:   f.Class,
	}, nil
}

func getRunPath(f *elf.File, elfPath string) []string {
	dirs := readRunPath(f)
	if dirs == nil {
		return nil
	}

	elfPath = check1(filepath.EvalSymlinks(elfPath))
	base := filepath.Dir(elfPath)
	var out []string

	for _, dir := range dirs {
		if strings.Contains(dir, "$ORIGIN") {
			dir = strings.Replace(dir, "$ORIGIN", base, -1)
			dir = check1(filepath.Abs(dir))
			dir = check1(filepath.EvalSymlinks(dir))
		}
		if !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}

	return out
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
		line = bytes.Trim(line, " \t\r")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if !bytes.HasPrefix(line, []byte("include")) {
			out = append(out, string(line))
			continue
		}

		path := string(line[8:])
		if !filepath.IsAbs(path) {
			path = filepath.Join("/etc", path)
		}
		for _, filename := range check1(filepath.Glob(path)) {
			out = append(out, parseLdSoConfFile(filename, seenConfs)...)
		}

	}

	return out
}

func (base *baseInfo) getSymMatches(searchdirs []string) error {
	base.symnameToSonames = make(map[string][]string, len(base.syms))
	requiredSymnames := make(map[string]bool, len(base.syms))
	for _, sym := range base.syms {
		requiredSymnames[sym] = true
	}

	seenSonames := make(map[string]bool)
	var sonameQueue queue[sonameWithSearchdirs]

	for _, soname := range base.sonames {
		sonameQueue.push(sonameWithSearchdirs{
			soname:     soname,
			searchdirs: searchdirs,
		})
		seenSonames[soname] = true
	}

	unneededSonames := slices.Clone(base.sonames)

	for {
		element, success := sonameQueue.pop()
		if !success {
			break
		}

		soname := element.soname

		sonameNeeded := false
		searchdirs = element.searchdirs

		for _, path := range getSonamePaths(soname, searchdirs) {
			syms, sonames, runpath, err := getSyms(path, base.machine, base.class)
			if err != nil {
				return err
			}

			for _, soname := range sonames {
				if !seenSonames[soname] {
					sonameQueue.push(sonameWithSearchdirs{
						soname:     soname,
						searchdirs: getSearchdirs(runpath),
					})
					seenSonames[soname] = true
				}
			}

			for _, sym := range syms {
				if requiredSymnames[sym.Name] {
					sl := base.symnameToSonames[sym.Name]
					if !slices.Contains(sl, soname) {
						base.symnameToSonames[sym.Name] = append(sl, soname)
						sonameNeeded = true
					}
				}
			}
		}

		if sonameNeeded && slices.Contains(unneededSonames, soname) {
			index := slices.Index(unneededSonames, soname)
			unneededSonames = slices.Delete(unneededSonames, index, index+1)
		}

		if !base.options.full && len(base.symnameToSonames) == len(base.syms) {
			break
		}
	}

	base.unneededSonames = unneededSonames
	return nil
}

func getSyms(path string, machine elf.Machine, class elf.Class) (syms []elf.Symbol, sonames, runpath []string, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	if !(f.Machine == machine && f.Class == class) {
		return nil, nil, nil, nil
	}

	seen := make(map[string]bool)

	for _, sym := range check1(f.DynamicSymbols()) {
		if sym.Section != elf.SHN_UNDEF && !seen[sym.Name] {
			syms = append(syms, sym)
			seen[sym.Name] = true
		}
	}

	sonames = check1(f.DynString(elf.DT_NEEDED))
	runpath = getRunPath(f, path)

	return syms, sonames, runpath, nil
}

func getSonamePaths(soname string, searchdirs []string) []string {
	if strings.Contains(soname, "/") {
		return []string{check1(filepath.Abs(soname))}
	}

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
	return err == nil
	/*
		if !errors.Is(err, os.ErrNotExist) {
			check(err)
		}
	*/
}

func lddSym(elfPath string, options parseOptions) (*LddResults, error) {
	if elfPath == "" {
		return nil, errors.New("path not specified")
	}

	if !(options.getFunc || options.getObject || options.getOther) {
		return nil, errors.New("all symbol types disabled")
	}

	elfPath, err := filepath.Abs(elfPath)
	if err != nil {
		return nil, fmt.Errorf("elfPath abs: %w", err)
	}

	base, err := parseBase(elfPath, options)
	if err != nil {
		return nil, fmt.Errorf("parseBase: %w", err)
	}

	searchdirs := getSearchdirs(base.runpath)

	err = base.getSymMatches(searchdirs)
	if err != nil {
		return nil, fmt.Errorf("getSymMatches: %w", err)
	}

	var undefinedSyms []string

	for _, sym := range base.syms {
		if len(base.symnameToSonames[sym]) == 0 {
			undefinedSyms = append(undefinedSyms, sym)
		}
	}

	if undefinedSyms == nil {
		undefinedSyms = []string{}
	}

	ret := &LddResults{
		Syms:             base.syms,
		Sonames:          base.sonames,
		SymnameToSonames: base.symnameToSonames,
		UnneededSonames:  base.unneededSonames,
		UndefinedSyms:    undefinedSyms,
	}

	return ret, nil
}

func (lddRes *LddResults) print() {
	for _, sym := range lddRes.Syms {
		sonames := lddRes.SymnameToSonames[sym]
		if len(sonames) == 0 {
			continue
		}
		fmt.Printf("%s: %s\n", sym, strings.Join(sonames, ", "))
	}

	if !(len(lddRes.UnneededSonames) > 0 || len(lddRes.UndefinedSyms) > 0) {
		return
	}

	fmt.Println()
	if len(lddRes.UnneededSonames) > 0 {
		fmt.Printf("UNNEEDED: %s\n", strings.Join(lddRes.UnneededSonames, ", "))
	}

	if len(lddRes.UndefinedSyms) > 0 {
		fmt.Printf("UNDEFINED: %s\n", strings.Join(lddRes.UndefinedSyms, ", "))
	}
}

func main() {
	var elfPath string
	var options parseOptions
	var jsonOut bool
	flag.StringVar(&elfPath, "path", "", "path to file")
	flag.BoolVar(&options.getFunc, "funcs", true, "track functions")
	flag.BoolVar(&options.getObject, "objects", true, "track objects")
	flag.BoolVar(&options.getOther, "other", false, "track other symbols")
	flag.BoolVar(&options.full, "full", true, "do not exit out early if all symbols are resolved")
	flag.BoolVar(&jsonOut, "json", false, "output json")
	flag.Parse()

	lddRes, err := lddSym(elfPath, options)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if jsonOut {
		encoded := check1(json.Marshal(lddRes))
		fmt.Println(string(encoded))
	} else {
		lddRes.print()
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

type queue[T any] struct {
	l []T
}

func (q *queue[T]) push(e T) {
	q.l = append(q.l, e)
}

func (q *queue[T]) pop() (T, bool) {
	var next T
	if len(q.l) == 0 {
		return next, false
	}

	next = q.l[0]
	q.l = q.l[1:]
	return next, true
}
