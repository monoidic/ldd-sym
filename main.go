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
	elfPath   multiPath
	root      string
	getFunc   bool
	getObject bool
	getOther  bool
	full      bool
	getWeak   bool
	std       bool
	android   bool
}

type sonameWithSearchdirs struct {
	soname     string
	searchdirs []multiPath
}

type baseInfo struct {
	syms    []string
	sonames []string
	runpath []multiPath

	symnameToSonames map[string][]string
	sonamePaths      map[string][]multiPath
	unneededSonames  []string

	options *parseOptions
	machine elf.Machine
	class   elf.Class
}

type LddResults struct {
	// for correct order
	Syms    []string
	Sonames []string

	SymnameToSonames map[string][]string
	SonamePaths      map[string][]multiPath

	UnneededSonames []string
	UndefinedSyms   []string
}

type multiPath struct {
	// on the system
	realPath string
	// relative to the -root= argument
	rootPath string
	// the -root= argument
	root      string
	mustExist bool
	filled    bool
}

func (mp *multiPath) fill() (err error) {
	if mp.filled {
		return nil
	}

	if mp.root == "" {
		return errors.New("no root in multipath")
	}

	if mp.realPath == "" && mp.rootPath == "" {
		return errors.New("no path in multipath")
	}

	if mp.rootPath == "" {
		mp.rootPath = removeRoot(mp.realPath, mp.root)
	} else {
		mp.rootPath, err = absEvalSymlinks(mp.rootPath, mp.root, mp.mustExist)
		if err != nil {
			return err
		}
		mp.realPath = filepath.Join(mp.root, mp.rootPath)
	}

	mp.filled = true
	return nil
}

func (mp *multiPath) getReal() string {
	if !mp.filled {
		check(mp.fill())
	}
	return mp.realPath
}

func (mp *multiPath) getRooted() string {
	if !mp.filled {
		check(mp.fill())
	}
	return mp.rootPath
}

func (mp *multiPath) MarshalJSON() ([]byte, error) {
	if !mp.filled {
		panic("not filled")
	}
	return json.Marshal(mp.getRooted())
}

func parseBase(options *parseOptions) (*baseInfo, error) {
	f, err := elf.Open(options.elfPath.getReal())
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
		stb := elf.ST_BIND(sym.Info)
		isWeak := stb == elf.STB_WEAK
		// does not match argument filters
		if !((options.getFunc && isFunc) || (options.getObject && isObj) || (options.getOther && !(isFunc || isObj))) {
			continue
		}
		// defined within this file
		if sym.Section != elf.SHN_UNDEF {
			continue
		}
		// weak symbol
		if isWeak && !options.getWeak {
			continue
		}

		syms = append(syms, sym.Name)
	}

	sonames, err := f.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil, fmt.Errorf("parseBase DT_NEEDED: %w", err)
	}

	runpath, err := getRunPath(f, &options.elfPath, options)
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

func getRunPath(f *elf.File, fPath *multiPath, options *parseOptions) ([]multiPath, error) {
	dirs := readRunPath(f, fPath.root)
	if len(dirs) == 0 {
		return nil, nil
	}

	origin := multiPath{
		rootPath:  filepath.Dir(fPath.getRooted()),
		root:      fPath.root,
		mustExist: true,
	}

	err := origin.fill()
	if err != nil {
		return nil, err
	}

	for i, dir := range dirs {
		if !strings.Contains(dir.getRooted(), "$ORIGIN") {
			continue
		}
		dir.rootPath = strings.Replace(dir.getRooted(), "$ORIGIN", origin.getRooted(), -1)
		dir.filled = false
		err = dir.fill()
		if err != nil {
			return nil, fmt.Errorf("getRunPath absEvalSymlinks: %w", err)
		}
		dirs[i] = dir
	}

	dirs = uniqExistsPath(dirs, options)

	return dirs, nil
}

func readRunPath(f *elf.File, root string) []multiPath {
	runpath, err := f.DynString(elf.DT_RUNPATH)
	if err == nil && len(runpath) != 0 {
		return rootedSlToMultiPathSl(strings.Split(runpath[0], ":"), root, true)
	}

	runpath, err = f.DynString(elf.DT_RPATH)
	if err == nil && len(runpath) != 0 {
		return rootedSlToMultiPathSl(strings.Split(runpath[0], ":"), root, true)
	}

	return nil
}

func rootedSlToMultiPathSl(sl []string, root string, mustExist bool) []multiPath {
	var out []multiPath

	for _, s := range sl {
		mp := multiPath{
			rootPath:  s,
			root:      root,
			mustExist: mustExist,
		}
		if err := mp.fill(); err != nil {
			continue
		}
		out = append(out, mp)
	}

	return out
}

func multiPathSlToRootedSl(sl []multiPath) []string {
	ret := make([]string, len(sl))

	for i, mp := range sl {
		ret[i] = mp.getRooted()
	}

	return ret
}

func parseLdSoConfFile(filename multiPath, seenConfs set[string], options *parseOptions) []multiPath {
	if seenConfs.contains(filename.getRooted()) {
		return nil
	}
	seenConfs.add(filename.getRooted())

	var out []multiPath

	// might not exist on non-glibc systems
	ldSoConf, err := os.ReadFile(filename.getReal())
	if err != nil {
		return nil
	}

	for _, line := range bytes.Split(ldSoConf, []byte("\n")) {
		line = bytes.Trim(line, " \t\r")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if !bytes.HasPrefix(line, []byte("include")) {
			path := string(line)
			mp := multiPath{
				rootPath:  path,
				root:      options.root,
				mustExist: true,
			}
			err = mp.fill()
			if err == nil {
				out = append(out, mp)
			}
			continue
		}

		path := string(line[8:])
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(filename.getRooted()), path)
		}

		mp := multiPath{
			rootPath:  path,
			root:      options.root,
			mustExist: false,
		}
		err = mp.fill()
		if err != nil {
			continue
		}

		filenames, err := filepath.Glob(mp.getReal())
		if err != nil {
			continue
		}

		for _, filename := range filenames {
			mp := multiPath{
				realPath:  filename,
				root:      options.root,
				mustExist: true,
			}
			err = mp.fill()
			if err == nil {
				out = append(out, parseLdSoConfFile(mp, seenConfs, options)...)
			}
		}
	}

	return out
}

func (base *baseInfo) getSymMatches(searchdirs []multiPath) error {
	base.symnameToSonames = make(map[string][]string, len(base.syms))
	requiredSymnames := newSet[string]()
	for _, sym := range base.syms {
		requiredSymnames.add(sym)
	}

	seenSonames := newSet[string]()
	var sonameQueue queue[sonameWithSearchdirs]

	for _, soname := range base.sonames {
		sonameQueue.push(sonameWithSearchdirs{
			soname:     soname,
			searchdirs: searchdirs,
		})
		seenSonames.add(soname)
	}

	unneededSonames := slices.Clone(base.sonames)

	sonamePaths := make(map[string][]multiPath)

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
			syms, sonames, runpath, archMatch, err := getSyms(&path, base)
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
				if !seenSonames.contains(soname) {
					sonameQueue.push(sonameWithSearchdirs{
						soname:     soname,
						searchdirs: getSearchdirs(runpath, base.options),
					})
					seenSonames.add(soname)
				}
			}

			for _, sym := range syms {
				if requiredSymnames.contains(sym) {
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

func getSyms(path *multiPath, base *baseInfo) (syms, sonames []string, runpath []multiPath, archMatch bool, err error) {
	f, err := elf.Open(path.getReal())
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer f.Close()

	if !(f.Machine == base.machine && f.Class == base.class) {
		return nil, nil, nil, false, nil
	}

	seen := newSet[string]()

	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("getSyms dynsyms: %w", err)
	}

	for _, sym := range dynSyms {
		if sym.Section != elf.SHN_UNDEF && !seen.contains(sym.Name) {
			syms = append(syms, sym.Name)
			seen.add(sym.Name)
		}
	}

	sonames, err = f.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("getSyms DynString: %w", err)
	}
	runpath, err = getRunPath(f, path, base.options)
	if err != nil {
		return nil, nil, nil, false, err
	}

	return syms, sonames, runpath, true, nil
}

func getSonamePaths(soname string, searchdirs []multiPath, options *parseOptions) []multiPath {
	if strings.Contains(soname, "/") {
		path, err := absEvalSymlinks(soname, options.root, true)
		if err != nil {
			return nil
		}
		mp := multiPath{
			rootPath:  path,
			root:      options.root,
			mustExist: true,
		}
		err = mp.fill()
		if err != nil {
			return nil
		}
		return []multiPath{mp}
	}

	var paths []string
	for _, dir := range searchdirs {
		path := filepath.Join(dir.getRooted(), soname)
		paths = append(paths, path)
	}

	ret := rootedSlToMultiPathSl(paths, options.root, true)
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

func lddSym(options *parseOptions) (*LddResults, error) {
	options.elfPath.root = "/"
	options.elfPath.mustExist = true
	err := options.elfPath.fill()
	if err != nil {
		return nil, fmt.Errorf("elfPath abs: %w", err)
	}

	if !(options.getFunc || options.getObject || options.getOther) {
		return nil, errors.New("all symbol types disabled")
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

	if lddRes.SonamePaths == nil {
		lddRes.SonamePaths = make(map[string][]multiPath)
	}
	if lddRes.SymnameToSonames == nil {
		lddRes.SymnameToSonames = make(map[string][]string)
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
		fmt.Printf("%s: %s\n", soname, strings.Join(multiPathSlToRootedSl(paths), ", "))
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
	flag.StringVar(&options.elfPath.rootPath, "path", "", "path to file")
	flag.StringVar(&options.root, "root", "/", "directory to consider the root for SONAME resolution")
	flag.StringVar(&profFile, "profile", "", "path to CPU pprof file (only profiled if set)")
	flag.BoolVar(&options.getFunc, "funcs", true, "track functions")
	flag.BoolVar(&options.getObject, "objects", true, "track objects")
	flag.BoolVar(&options.getOther, "other", false, "track other symbols")
	flag.BoolVar(&options.full, "full", true, "do not exit out early if all symbols are resolved")
	flag.BoolVar(&jsonOut, "json", false, "output json")
	flag.BoolVar(&options.std, "std", true, "search standard paths")
	flag.BoolVar(&options.android, "android", runtime.GOOS == "android", "search Android paths")
	flag.BoolVar(&options.getWeak, "weak", false, "get weak symbols")
	flag.Parse()

	if profFile != "" {
		f := check1(os.Create(profFile))
		check(pprof.StartCPUProfile(f))
		defer pprof.StopCPUProfile()
	}

	lddRes, err := lddSym(&options)
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

type set[T comparable] struct {
	m map[T]struct{}
}

func newSet[T comparable]() set[T] {
	return set[T]{
		m: make(map[T]struct{}),
	}
}

func (s *set[T]) add(e T) {
	s.m[e] = struct{}{}
}

func (s *set[T]) contains(e T) bool {
	_, ok := s.m[e]
	return ok
}

// preserves order
func uniqExistsPath(paths []multiPath, options *parseOptions) []multiPath {
	var ret []multiPath
	seen := newSet[string]()

	for _, path := range paths {
		err := path.fill()
		if err != nil || seen.contains(path.getRooted()) {
			continue
		}

		seen.add(path.getRooted())
		ret = append(ret, path)
	}

	return ret
}

var searchDirCached []multiPath

func getSearchdirs(runpath []multiPath, options *parseOptions) (ret []multiPath) {
	ret = append(ret, runpath...)
	if searchDirCached == nil {
		if options.std {
			searchDirCached = append(searchDirCached, getSearchDirCachedStd(options)...)
		}

		if options.android {
			searchDirCached = append(searchDirCached, getSearchDirCachedAndroid(options)...)
		}

		searchDirCached = uniqExistsPath(searchDirCached, options)
	}

	ret = append(ret, searchDirCached...)
	ret = uniqExistsPath(ret, options)
	return ret
}

func getSearchDirCachedStd(options *parseOptions) []multiPath {
	// based on glibc and musl defaults
	// also basically applicable to most non-Linux Unix-based systems
	paths := []string{
		"/lib64", "/lib",
		"/usr/lib64", "/usr/lib",
		"/usr/local/lib64", "/usr/local/lib",
	}

	ret := rootedSlToMultiPathSl(paths, options.root, true)

	mp := multiPath{
		rootPath:  "/etc/ld.so.conf",
		root:      options.root,
		mustExist: true,
	}
	if mp.fill() == nil {
		ret = append(ret, parseLdSoConfFile(mp, newSet[string](), options)...)
	}

	return ret
}

func getSearchDirCachedAndroid(options *parseOptions) []multiPath {
	// from https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp
	paths := []string{
		"/system/lib64", "/system/lib",
		"/odm/lib64", "/odm/lib",
		"/vendor/lib64", "/vendor/lib",
	}

	ret := rootedSlToMultiPathSl(paths, options.root, true)
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
