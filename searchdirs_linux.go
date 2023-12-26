//go:build !android

package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	ret = append(ret, "/lib64", "/usr/lib64")
	ret = append(ret, parseLdSoConfFile("/etc/ld.so.conf", map[string]bool{})...)
	return ret
}
