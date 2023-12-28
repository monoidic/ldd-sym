//go:build !android

package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	// based on glibc and musl defaults
	ret = append(ret,
		"/lib64", "/lib",
		"/usr/lib64", "/usr/lib",
		"/usr/local/lib64", "/usr/local/lib",
	)
	ret = append(ret, parseLdSoConfFile("/etc/ld.so.conf", map[string]bool{})...)
	return ret
}
