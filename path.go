package main

import (
	"errors"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// preserves order
func uniqExistsPath(paths iter.Seq[multiPath]) iter.Seq[multiPath] {
	seen := newSet[string]()
	return func(yield func(multiPath) bool) {
		for path := range paths {
			rooted := path.getRooted()
			if seen.contains(rooted) {
				continue
			}
			seen.add(rooted)
			if !pathExists(rooted) {
				continue
			}
			if !yield(path) {
				return
			}
		}
	}
}

const SYMLINK_LIMIT = 256

// do abs and evaluate symlinks, but keep the returned path relative to the specified root
func absEvalSymlinks(path, root string, mustExist bool) (string, error) {
	path, err := filepath.Abs(path)
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

		if mode := fi.Mode(); mode&os.ModeSymlink == 0 {
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

	realPath := filepath.Join(append([]string{sep}, retSl...)...)
	if mustExist && !pathExists(realPath) {
		return "", errors.New("non-existent path")
	}

	ret := removeRoot(realPath, root, sep)
	return ret, nil
}

func removeRoot(path, root, sep string) string {
	return filepath.Join(sep, strings.TrimPrefix(path, root))
}

func rootedToMultiPath(seq iter.Seq[string], root string, mustExist bool) iter.Seq[multiPath] {
	return func(yield func(multiPath) bool) {
		for s := range seq {
			mp := multiPath{
				rootPath:  s,
				root:      root,
				mustExist: mustExist,
			}
			if err := mp.fill(); err != nil {
				continue
			}
			if !yield(mp) {
				return
			}
		}
	}
}

func multiPathToRooted(seq iter.Seq[multiPath]) iter.Seq[string] {
	return func(yield func(string) bool) {
		for mp := range seq {
			if !yield(mp.getRooted()) {
				return
			}
		}
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
