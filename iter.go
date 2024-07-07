package main

import "iter"

func collect[T any](seq iter.Seq[T]) []T {
	var ret []T
	for e := range seq {
		ret = append(ret, e)
	}
	return ret
}

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

func sliceToSeq[T any](sl []T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, e := range sl {
			if !yield(e) {
				return
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

func uniq[T comparable](seq iter.Seq[T]) iter.Seq[T] {
	seen := newSet[T]()
	return func(yield func(T) bool) {
		for e := range seq {
			if seen.contains(e) {
				continue
			}
			seen.add(e)
			if !yield(e) {
				return
			}
		}
	}
}
