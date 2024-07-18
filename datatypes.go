package main

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
)

type queue[T any] struct {
	l []T
}

func (q *queue[T]) push(e T) {
	q.l = append(q.l, e)
}

func (q *queue[T]) pop() (T, bool) {
	var next T
	if len(q.l) == 0 {
		return next, false
	}

	next = q.l[0]
	q.l = q.l[1:]
	return next, true
}

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	slices.Reverse(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) push(e T) {
	s.l = append(s.l, e)
}

func (s *stack[T]) pop() (T, bool) {
	var next T
	if len(s.l) == 0 {
		return next, false
	}

	size := len(s.l)
	next = s.l[size-1]
	s.l = s.l[:size-1]

	return next, true
}

func (s *stack[T]) isEmpty() bool {
	return len(s.l) == 0
}

type empty struct{}

type set[T comparable] struct {
	m map[T]empty
}

func newSet[T comparable]() set[T] {
	return set[T]{
		m: make(map[T]empty),
	}
}

func (s *set[T]) add(e T) {
	s.m[e] = empty{}
}

func (s *set[T]) contains(e T) bool {
	_, ok := s.m[e]
	return ok
}

type parseOptions struct {
	elfPath       multiPath
	root          string
	ldLibraryPath string
	getFunc       bool
	getObject     bool
	getOther      bool
	full          bool
	getWeak       bool
	std           bool
	android       bool
}

type sonameWithSearchdirs struct {
	soname     string
	searchdirs []multiPath
}

type baseInfo struct {
	syms    []string
	sonames []string
	runpath []multiPath

	symnameToSonames map[string][]string
	sonamePaths      map[string][]multiPath
	unneededSonames  []string

	options *parseOptions
	machine elf.Machine
	class   elf.Class
}

type LddResults struct {
	// for correct order
	Syms    []string
	Sonames []string

	SymnameToSonames map[string][]string
	SonamePaths      map[string][]multiPath

	UnneededSonames []string
	UndefinedSyms   []string
}

type multiPath struct {
	// on the system
	realPath string
	// relative to the -root= argument
	rootPath string
	// the -root= argument
	root      string
	mustExist bool
}

func (mp *multiPath) fill() (err error) {
	if mp.root == "" {
		return errors.New("no root in multipath")
	}

	if mp.realPath == "" && mp.rootPath == "" {
		return errors.New("no path in multipath")
	}

	if mp.rootPath == "" {
		mp.rootPath = removeRoot(mp.realPath, mp.root, "/")
	} else if mp.realPath == "" {
		mp.rootPath, err = absEvalSymlinks(mp.rootPath, mp.root, mp.mustExist)
		if err != nil {
			return err
		}
		mp.realPath = filepath.Join(mp.root, mp.rootPath)
	}

	return nil
}

func (mp *multiPath) getReal() string {
	if mp.realPath == "" {
		check(mp.fill())
	}
	return mp.realPath
}

func (mp *multiPath) getRooted() string {
	if mp.rootPath == "" {
		check(mp.fill())
	}
	return mp.rootPath
}

func (mp *multiPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(mp.getRooted())
}
