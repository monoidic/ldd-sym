package main

import (
	"iter"
	"slices"
)

func emptySeq[T any](yield func(T) bool) {}

func concatSeq[T any](seqs ...iter.Seq[T]) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, seq := range seqs {
			if seq == nil {
				continue
			}
			for e := range seq {
				if !yield(e) {
					return
				}
			}
		}
	}
}

func seqToSet[T comparable](seq iter.Seq[T]) set[T] {
	s := newSet[T]()
	for e := range seq {
		s.add(e)
	}
	return s
}

func uniq[T comparable](seq iter.Seq[T]) []T {
	seen := newSet[T]()
	return slices.Collect(seqMap(seq, func(e T) (T, bool) {
		if seen.contains(e) {
			return e, false
		}
		seen.add(e)
		return e, true
	}))
}

func seqMap[T any, V any](seq iter.Seq[T], f func(T) (V, bool)) iter.Seq[V] {
	return func(yield func(V) bool) {
		for v := range seq {
			v, keep := f(v)
			if !keep {
				continue
			}
			if !yield(v) {
				return
			}
		}
	}
}
