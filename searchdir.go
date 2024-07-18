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
	if searchDirCached != nil {
		ret := concatSeq(sliceToSeq(runpath), sliceToSeq(searchDirCached))
		ret = uniqExistsPath(ret)
		return ret
	}

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
	return getSearchdirs(runpath, options)
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
	return func(yield func(multiPath) bool) {
		// might not exist on non-glibc systems
		if !pathExists(filename.getReal()) {
			return
		}

		seenConfs := newSet[string]()
		var pathstack stack[multiPath]
		pathstack.push(filename)

		for {
			filename, ok := pathstack.pop()
			if !ok {
				break
			}
			if seenConfs.contains(filename.getRooted()) {
				continue
			}
			seenConfs.add(filename.getRooted())

			ldSoConf := check1(os.ReadFile(filename.getReal()))

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
						pathstack.push(mp)
					}
				}
			}
		}
	}
}
