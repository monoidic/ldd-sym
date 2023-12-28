package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	ret = append(ret, "/vendor/lib64", "/system/lib64", "/vendor/lib", "/system/lib")
	return ret
}
