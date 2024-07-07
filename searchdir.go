package main

import (
	"bytes"
	"iter"
	"os"
	"path/filepath"
	"strings"
)

var searchDirCached []multiPath

func getSearchdirs(runpath []multiPath, options *parseOptions) iter.Seq[multiPath] {
	if searchDirCached == nil {
		var seq iter.Seq[multiPath]
		if options.ldLibraryPath != "" {
			seq = concatSeq(seq, rootedToMultiPath(sliceToSeq(strings.Split(options.ldLibraryPath, ":")), options.root, true))
		}

		if options.std {
			seq = concatSeq(seq, getSearchDirCachedStd(options.root))
		}

		if options.android {
			seq = concatSeq(seq, getSearchDirCachedAndroid(options.root))
		}

		searchDirCached = collect(uniqExistsPath(seq))
	}

	ret := concatSeq(sliceToSeq(runpath), sliceToSeq(searchDirCached))
	ret = uniqExistsPath(ret)
	return ret
}

func getSearchDirCachedStd(root string) iter.Seq[multiPath] {
	// based on glibc and musl defaults
	// also basically applicable to most non-Linux Unix-based systems
	paths := []string{
		"/lib64", "/lib",
		"/usr/lib64", "/usr/lib",
		"/usr/local/lib64", "/usr/local/lib",
	}

	ret := rootedToMultiPath(sliceToSeq(paths), root, true)

	mp := multiPath{
		rootPath:  "/etc/ld.so.conf",
		root:      root,
		mustExist: true,
	}
	if mp.fill() == nil {
		ret = concatSeq(ret, parseLdSoConfFile(mp, root))
	}

	return ret
}

func getSearchDirCachedAndroid(root string) iter.Seq[multiPath] {
	// from https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp
	paths := []string{
		"/system/lib64", "/system/lib",
		"/odm/lib64", "/odm/lib",
		"/vendor/lib64", "/vendor/lib",
	}

	return rootedToMultiPath(sliceToSeq(paths), root, true)
}

func parseLdSoConfFile(filename multiPath, root string) iter.Seq[multiPath] {
	return _parseLdSoConfFile(filename, newSet[string](), root)
}

func _parseLdSoConfFile(filename multiPath, seenConfs set[string], root string) iter.Seq[multiPath] {
	return func(yield func(multiPath) bool) {
		if seenConfs.contains(filename.getRooted()) {
			return
		}
		seenConfs.add(filename.getRooted())

		// might not exist on non-glibc systems
		ldSoConf, err := os.ReadFile(filename.getReal())
		if err != nil {
			return
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
					root:      root,
					mustExist: true,
				}
				err := mp.fill()
				if err != nil {
					continue
				}
				if !yield(mp) {
					return
				}
				continue
			}

			path := string(line[8:])
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(filename.getRooted()), path)
			}

			mp := multiPath{
				rootPath:  path,
				root:      root,
				mustExist: false,
			}
			err := mp.fill()
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
					root:      root,
					mustExist: true,
				}
				err := mp.fill()
				if err == nil {
					for e := range _parseLdSoConfFile(mp, seenConfs, root) {
						if !yield(e) {
							return
						}
					}
				}
			}
		}
	}
}
