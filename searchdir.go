package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

var searchDirCached []multiPath

func getSearchdirs(runpath []multiPath, options *parseOptions) (ret []multiPath) {
	ret = append(ret, runpath...)
	if searchDirCached == nil {
		if options.ldLibraryPath != "" {
			searchDirCached = append(searchDirCached, rootedSlToMultiPathSl(strings.Split(options.ldLibraryPath, ":"), options.root, true)...)
		}

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
				root:      options.root,
				mustExist: true,
			}
			err := mp.fill()
			if err == nil {
				out = append(out, parseLdSoConfFile(mp, seenConfs, options)...)
			}
		}
	}

	return out
}
