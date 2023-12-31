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
	sonamePaths      map[string][]string
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
	SonamePaths      map[string][]string
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

	sonames, err := f.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil, fmt.Errorf("parseBase DT_NEEDED: %w", err)
	}
	if sonames == nil {
		sonames = []string{}
	}

	runpath, err := getRunPath(f, elfPath)
	if err != nil {
		return nil, fmt.Errorf("parseBase getRunPath: %w", err)
	}

	return &baseInfo{
		syms:    syms,
		sonames: sonames,
		runpath: runpath,
		options: options,
		machine: f.Machine,
		class:   f.Class,
	}, nil
}

func getRunPath(f *elf.File, elfPath string) ([]string, error) {
	dirs := readRunPath(f)
	if len(dirs) == 0 {
		return nil, nil
	}

	var err error
	elfPath, err = filepath.EvalSymlinks(elfPath)
	if err != nil {
		return nil, fmt.Errorf("getRunPath EvalSymlinks: %w", err)
	}

	base := filepath.Dir(elfPath)
	var out []string

	for _, dir := range dirs {
		if strings.Contains(dir, "$ORIGIN") {
			dir = strings.Replace(dir, "$ORIGIN", base, -1)
			dir, err = filepath.Abs(dir)
			if err != nil {
				return nil, fmt.Errorf("getRunPath Abs: %w", err)
			}
			dir, err = filepath.EvalSymlinks(dir)
			if err != nil {
				return nil, fmt.Errorf("getRunPath EvalSymlinksOrigin: %w", err)
			}
		}
		if !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}

	return out, nil
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

	// might not exist on non-glibc systems
	ldSoConf, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}

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
		filenames, err := filepath.Glob(path)
		if err != nil {
			continue
		}

		for _, filename := range filenames {
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

	sonamePaths := make(map[string][]string)

	var allSonames []string

	for {
		element, success := sonameQueue.pop()
		if !success {
			break
		}

		soname := element.soname
		if base.options.full {
			allSonames = append(allSonames, soname)
		}

		sonameNeeded := false
		searchdirs = element.searchdirs

		for _, path := range getSonamePaths(soname, searchdirs) {
			syms, sonames, runpath, archMatch, err := getSyms(path, base.machine, base.class)
			if err != nil {
				return err
			}

			if !archMatch {
				continue
			}

			if base.options.full || slices.Contains(base.sonames, soname) {
				sonamePaths[soname] = append(sonamePaths[soname], path)
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
				if requiredSymnames[sym] {
					sl := base.symnameToSonames[sym]
					if !slices.Contains(sl, soname) {
						base.symnameToSonames[sym] = append(sl, soname)
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
	base.sonamePaths = sonamePaths
	if base.options.full {
		base.sonames = allSonames
	}

	return nil
}

func getSyms(path string, machine elf.Machine, class elf.Class) (syms, sonames, runpath []string, archMatch bool, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer f.Close()

	if !(f.Machine == machine && f.Class == class) {
		return nil, nil, nil, false, nil
	}

	seen := make(map[string]bool)

	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("getSyms dynsyms: %w", err)
	}

	for _, sym := range dynSyms {
		if sym.Section != elf.SHN_UNDEF && !seen[sym.Name] {
			syms = append(syms, sym.Name)
			seen[sym.Name] = true
		}
	}

	sonames, err = f.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("getSyms DynString: %w", err)
	}
	runpath, err = getRunPath(f, path)
	if err != nil {
		return nil, nil, nil, false, err
	}

	return syms, sonames, runpath, true, nil
}

func getSonamePaths(soname string, searchdirs []string) []string {
	if strings.Contains(soname, "/") {
		path, err := filepath.Abs(soname)
		if err != nil {
			return nil
		}
		return []string{path}
	}

	var ret []string
	for _, dir := range searchdirs {
		path := filepath.Join(dir, soname)
		if fileExists(path) {
			ret = append(ret, path)
		}
	}

	return uniqExistsPath(ret)
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

	undefinedSyms := []string{}

	for _, sym := range base.syms {
		if len(base.symnameToSonames[sym]) == 0 {
			undefinedSyms = append(undefinedSyms, sym)
		}
	}

	ret := &LddResults{
		Syms:             base.syms,
		Sonames:          base.sonames,
		SymnameToSonames: base.symnameToSonames,
		SonamePaths:      base.sonamePaths,
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

	fmt.Println()

	for _, soname := range lddRes.Sonames {
		paths := lddRes.SonamePaths[soname]
		fmt.Printf("%s: %s\n", soname, strings.Join(paths, ", "))
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

// preserves order
func uniqExistsPath(arr []string) []string {
	var ret []string
	var err error

	for _, path := range arr {
		path, err = filepath.Abs(path)
		if !(err == nil && fileExists(path)) {
			continue
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil || slices.Contains(ret, path) {
			continue
		}
		ret = append(ret, path)
	}

	return ret
}
