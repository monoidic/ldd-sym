package main

func getSearchdirs(runpath []string) (ret []string) {
	ret = append(ret, runpath...)
	ret = append(ret, "/apex/com.android.runtime/lib64", "/apex/com.android.runtime/lib64/bionic", "/odm/lib64", "/system/lib64")
	return ret
}
