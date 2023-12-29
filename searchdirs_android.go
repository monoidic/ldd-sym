package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	// from https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp
	ret = append(ret,
		"/system/lib64", "/system/lib",
		"/odm/lib64", "/odm/lib",
		"/vendor/lib64", "/vendor/lib",
	)
	return uniqExistsPath(ret)
}
