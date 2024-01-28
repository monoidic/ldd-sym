package main

import (
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
		return nil, nil, nil, false, fmt.Errorf("elf.Open: %w", err)
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
		return nil, nil, nil, false, fmt.Errorf("runpath: %w", err)
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
	flag.StringVar(&options.ldLibraryPath, "ldpath", "", "set LD_LIBRARY_PATH")
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
