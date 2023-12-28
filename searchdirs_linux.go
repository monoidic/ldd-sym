//go:build !android

package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	ret = append(ret, "/lib", "/lib64", "/lib32", "/usr/lib", "/usr/lib64", "/usr/lib32")
	ret = append(ret, parseLdSoConfFile("/etc/ld.so.conf", map[string]bool{})...)
	return ret
}
