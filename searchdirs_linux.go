//go:build !android

package main

import "path/filepath"

var searchDirCached []string

func getSearchdirs(runpath []string, options parseOptions) (ret []string) {
	ret = append(ret, runpath...)
	if searchDirCached == nil {
		searchDirCached = getSearchDirCached(options)
	}

	ret = append(ret, searchDirCached...)
	return ret
}

func getSearchDirCached(options parseOptions) []string {
	// based on glibc and musl defaults
	ret := []string{
		"/lib64", "/lib",
		"/usr/lib64", "/usr/lib",
		"/usr/local/lib64", "/usr/local/lib",
	}
	ret = append(ret, parseLdSoConfFile(filepath.Join(options.root, "/etc/ld.so.conf"), map[string]bool{})...)
	return ret
}
