package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// preserves order
func uniqExistsPath(paths []multiPath, options *parseOptions) []multiPath {
	var ret []multiPath
	seen := newSet[string]()

	for _, path := range paths {
		err := path.fill()
		if err != nil || seen.contains(path.getRooted()) {
			continue
		}

		seen.add(path.getRooted())
		ret = append(ret, path)
	}

	return ret
}

const SYMLINK_LIMIT = 256

// do abs and evaluate symlinks, but keep the returned path relative to the specified root
func absEvalSymlinks(path, root string, mustExist bool) (string, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}

	sep := "/"
	splitRoot := strings.Split(root, sep)
	splitRoot[0] = sep
	if len(splitRoot) > 1 && splitRoot[len(splitRoot)-1] == "" {
		splitRoot = splitRoot[:len(splitRoot)-1]
	}
	retSl := slices.Clone(splitRoot)

	var pathStack stack[string]
	pathStack.pushMultipleRev(strings.Split(path, sep)[1:])

	var symlinksWalked int

	for {
		entry, exists := pathStack.pop()
		if !exists {
			break
		}

		if entry == "." {
			continue
		} else if entry == ".." {
			if len(retSl) > len(splitRoot) {
				retSl = retSl[:len(retSl)-1]
			}
			continue
		}

		entryPath := filepath.Join(append(retSl, entry)...)
		fi, err := os.Lstat(entryPath)
		if err != nil {
			if !mustExist && errors.Is(err, os.ErrNotExist) && pathStack.isEmpty() {
				// final element in path that does not need to actually exist
				retSl = append(retSl, entry)
				break
			}
			return "", err
		}

		mode := fi.Mode()
		if mode&os.ModeSymlink == 0 {
			retSl = append(retSl, entry)
			continue
		}

		symlinksWalked++
		if symlinksWalked > SYMLINK_LIMIT {
			return "", errors.New("symlinks too deep")
		}

		target, err := os.Readlink(entryPath)
		if err != nil {
			return "", err
		}

		targetSplit := strings.Split(target, sep)
		if filepath.IsAbs(target) {
			retSl = append(retSl[:0], splitRoot...)
			targetSplit = targetSplit[1:]
		}
		pathStack.pushMultipleRev(targetSplit)
	}

	realPath := filepath.Join(append([]string{"/"}, retSl...)...)
	if mustExist && !fileExists(realPath) {
		return "", errors.New("non-existent path")
	}

	ret := removeRoot(realPath, root)
	return ret, nil
}

func removeRoot(path, root string) string {
	return filepath.Join("/", strings.TrimPrefix(path, root))
}

func rootedSlToMultiPathSl(sl []string, root string, mustExist bool) []multiPath {
	var out []multiPath

	for _, s := range sl {
		mp := multiPath{
			rootPath:  s,
			root:      root,
			mustExist: mustExist,
		}
		if err := mp.fill(); err != nil {
			continue
		}
		out = append(out, mp)
	}

	return out
}

func multiPathSlToRootedSl(sl []multiPath) []string {
	ret := make([]string, len(sl))

	for i, mp := range sl {
		ret[i] = mp.getRooted()
	}

	return ret
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
	/*
		if !errors.Is(err, os.ErrNotExist) {
			check(err)
		}
	*/
}
