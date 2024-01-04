package main

var searchDirCached []string

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	if searchDirCached == nil {
		searchDirCached = getSearchDirCached()
	}

	ret = append(ret, searchDirCached)
	return ret
}

func getSearchDirCached() []string {
	// from https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp
	ret := []string{
		"/system/lib64", "/system/lib",
		"/odm/lib64", "/odm/lib",
		"/vendor/lib64", "/vendor/lib",
	}
	return ret
}
