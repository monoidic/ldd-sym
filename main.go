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
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
)

type parseOptions struct {
	elfPath   string
	root      string
	getFunc   bool
	getObject bool
	getOther  bool
	full      bool
	linux     bool
	android   bool
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

	UnneededSonames []string
	UndefinedSyms   []string
}

func parseBase(options parseOptions) (*baseInfo, error) {
	f, err := elf.Open(options.elfPath)
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

	runpath, err := getRunPath(f, options.elfPath, "/")
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

func getRunPath(f *elf.File, elfPath, root string) ([]string, error) {
	dirs := readRunPath(f)
	if len(dirs) == 0 {
		return nil, nil
	}

	origin := filepath.Dir(elfPath)
	var out []string
	var err error

	for _, dir := range dirs {
		if strings.Contains(dir, "$ORIGIN") {
			dir = strings.Replace(dir, "$ORIGIN", origin, -1)
			dir, err = absEvalSymlinks(dir, root, true)
			if err != nil {
				return nil, fmt.Errorf("getRunPath absEvalSymlinks: %w", err)
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

func parseLdSoConfFile(filename string, seenConfs map[string]bool, options parseOptions) []string {
	var err error
	filename, err = absEvalSymlinks(filename, options.root, true)
	if err != nil {
		return nil
	}

	if seenConfs[filename] {
		return nil
	}
	seenConfs[filename] = true

	var out []string

	// might not exist on non-glibc systems
	ldSoConf, err := os.ReadFile(filepath.Join(options.root, filename))
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
			path = filepath.Join(filepath.Dir(filename), path)
		}

		path, err = absEvalSymlinks(path, options.root, false)
		if err != nil {
			continue
		}
		filenames, err := filepath.Glob(filepath.Join(options.root, path))
		if err != nil {
			continue
		}

		for _, filename := range filenames {
			filename = removeRoot(filename, options.root)
			out = append(out, parseLdSoConfFile(filename, seenConfs, options)...)
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

		for _, path := range getSonamePaths(soname, searchdirs, base.options) {
			syms, sonames, runpath, archMatch, err := getSyms(path, base)
			if err != nil {
				return fmt.Errorf("getSymMatches: %w", err)
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
						searchdirs: getSearchdirs(runpath, base.options),
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

func getSyms(path string, base *baseInfo) (syms, sonames, runpath []string, archMatch bool, err error) {
	f, err := elf.Open(filepath.Join(base.options.root, path))
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer f.Close()

	if !(f.Machine == base.machine && f.Class == base.class) {
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
	runpath, err = getRunPath(f, path, base.options.root)
	if err != nil {
		return nil, nil, nil, false, err
	}

	return syms, sonames, runpath, true, nil
}

func getSonamePaths(soname string, searchdirs []string, options parseOptions) []string {
	if strings.Contains(soname, "/") {
		path, err := absEvalSymlinks(soname, options.root, true)
		if err != nil {
			return nil
		}
		return []string{path}
	}

	var ret []string
	for _, dir := range searchdirs {
		path := filepath.Join(dir, soname)
		ret = append(ret, path)
	}

	ret = uniqExistsPath(ret, options)
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

func lddSym(options parseOptions) (*LddResults, error) {
	if options.elfPath == "" {
		return nil, errors.New("path not specified")
	}

	if !(options.getFunc || options.getObject || options.getOther) {
		return nil, errors.New("all symbol types disabled")
	}
	var err error

	options.elfPath, err = absEvalSymlinks(options.elfPath, "/", true)
	if err != nil {
		return nil, fmt.Errorf("elfPath abs: %w", err)
	}

	options.root, err = absEvalSymlinks(options.root, "/", true)
	if err != nil {
		return nil, fmt.Errorf("lddSym root abs: %w", err)
	}

	base, err := parseBase(options)
	if err != nil {
		return nil, fmt.Errorf("lddSym parseBase: %w", err)
	}

	searchdirs := getSearchdirs(base.runpath, base.options)

	err = base.getSymMatches(searchdirs)
	if err != nil {
		return nil, fmt.Errorf("lddSym: %w", err)
	}

	var undefinedSyms []string

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

func (lddRes *LddResults) noNil() {
	for _, slicePtr := range []*[]string{&lddRes.Sonames, &lddRes.Syms, &lddRes.UnneededSonames, &lddRes.UndefinedSyms} {
		if *slicePtr == nil {
			*slicePtr = make([]string, 0)
		}
	}

	for _, mapPtr := range []*map[string][]string{&lddRes.SonamePaths, &lddRes.SymnameToSonames} {
		if *mapPtr == nil {
			*mapPtr = make(map[string][]string)
		}
	}
}

func (lddRes *LddResults) print() {
	for _, sym := range lddRes.Syms {
		sonames := lddRes.SymnameToSonames[sym]
		if len(sonames) == 0 {
			continue
		}
		fmt.Printf("%s: %s\n", sym, strings.Join(sonames, ", "))
	}

	if len(lddRes.Syms) > 0 {
		fmt.Println()
	}

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
	var options parseOptions
	var jsonOut bool
	var profFile string
	flag.StringVar(&options.elfPath, "path", "", "path to file")
	flag.StringVar(&options.root, "root", "/", "directory to consider the root for SONAME resolution")
	flag.StringVar(&profFile, "profile", "", "path to CPU pprof file (only profiled if set)")
	flag.BoolVar(&options.getFunc, "funcs", true, "track functions")
	flag.BoolVar(&options.getObject, "objects", true, "track objects")
	flag.BoolVar(&options.getOther, "other", false, "track other symbols")
	flag.BoolVar(&options.full, "full", true, "do not exit out early if all symbols are resolved")
	flag.BoolVar(&jsonOut, "json", false, "output json")
	flag.BoolVar(&options.linux, "linux", runtime.GOOS == "linux", "search Linux paths")
	flag.BoolVar(&options.android, "android", runtime.GOOS == "android", "search Android paths")
	flag.Parse()

	if profFile != "" {
		f := check1(os.Create(profFile))
		check(pprof.StartCPUProfile(f))
		defer pprof.StopCPUProfile()
	}

	lddRes, err := lddSym(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if jsonOut {
		lddRes.noNil()
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

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	slices.Reverse(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) pop() (T, bool) {
	var next T
	if len(s.l) == 0 {
		return next, false
	}

	size := len(s.l)
	next = s.l[size-1]
	s.l = s.l[:size-1]

	return next, true
}

func (s *stack[T]) isEmpty() bool {
	return len(s.l) == 0
}

// preserves order
func uniqExistsPath(paths []string, options parseOptions) []string {
	var ret []string
	var err error
	seen := make(map[string]bool)

	for _, path := range paths {
		path, err = absEvalSymlinks(path, options.root, true)
		if err != nil || seen[path] {
			continue
		}

		seen[path] = true
		ret = append(ret, path)
	}

	return ret
}

var searchDirCached []string

func getSearchdirs(runpath []string, options parseOptions) (ret []string) {
	ret = append(ret, runpath...)
	if searchDirCached == nil {
		if options.linux {
			searchDirCached = append(searchDirCached, getSearchDirCachedLinux(options)...)
		}

		if options.android {
			searchDirCached = append(searchDirCached, getSearchDirCachedAndroid(options)...)
		}
	}

	ret = append(ret, searchDirCached...)
	ret = uniqExistsPath(ret, options)
	return ret
}

func getSearchDirCachedLinux(options parseOptions) []string {
	// based on glibc and musl defaults
	ret := []string{
		"/lib64", "/lib",
		"/usr/lib64", "/usr/lib",
		"/usr/local/lib64", "/usr/local/lib",
	}

	ret = append(ret, parseLdSoConfFile("/etc/ld.so.conf", make(map[string]bool), options)...)
	ret = uniqExistsPath(ret, options)
	return ret
}

func getSearchDirCachedAndroid(options parseOptions) []string {
	// from https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp
	ret := []string{
		"/system/lib64", "/system/lib",
		"/odm/lib64", "/odm/lib",
		"/vendor/lib64", "/vendor/lib",
	}

	ret = uniqExistsPath(ret, options)
	return ret
}

const SYMLINK_LIMIT = 256

// do abs and evaluate symlinks, but keep the returned path relative to the specified root
func absEvalSymlinks(path, root string, mustExist bool) (string, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}

	sep := "/"
	splitRoot := strings.Split(root, sep)
	splitRoot[0] = sep
	if len(splitRoot) > 1 && splitRoot[len(splitRoot)-1] == "" {
		splitRoot = splitRoot[:len(splitRoot)-1]
	}
	retSl := slices.Clone(splitRoot)

	var pathStack stack[string]
	pathStack.pushMultipleRev(strings.Split(path, sep)[1:])

	var symlinksWalked int

	for {
		entry, exists := pathStack.pop()
		if !exists {
			break
		}

		if entry == "." {
			continue
		} else if entry == ".." {
			if len(retSl) > len(splitRoot) {
				retSl = retSl[:len(retSl)-1]
			}
			continue
		}

		entryPath := filepath.Join(append(retSl, entry)...)
		fi, err := os.Lstat(entryPath)
		if err != nil {
			if !mustExist && errors.Is(err, os.ErrNotExist) && pathStack.isEmpty() {
				// final element in path that does not need to actually exist
				retSl = append(retSl, entry)
				break
			}
			return "", err
		}

		mode := fi.Mode()
		if mode&os.ModeSymlink == 0 {
			retSl = append(retSl, entry)
			continue
		}

		symlinksWalked++
		if symlinksWalked > SYMLINK_LIMIT {
			return "", errors.New("symlinks too deep")
		}

		target, err := os.Readlink(entryPath)
		if err != nil {
			return "", err
		}

		targetSplit := strings.Split(target, sep)
		if filepath.IsAbs(target) {
			retSl = append(retSl[:0], splitRoot...)
			targetSplit = targetSplit[1:]
		}
		pathStack.pushMultipleRev(targetSplit)
	}

	realPath := filepath.Join(append([]string{"/"}, retSl...)...)
	if mustExist && !fileExists(realPath) {
		return "", errors.New("non-existent path")
	}

	ret := removeRoot(realPath, root)
	return ret, nil
}

func removeRoot(path, root string) string {
	return filepath.Join("/", strings.TrimPrefix(path, root))
}
