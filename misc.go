package main

import (
	"errors"
	"strconv"
	"strings"
)

var (
	errNotFound = errors.New("not found")
	errTimeout  = errors.New("timeout")
	errInternal = errors.New("internal error")
)

func stringJoin(parts []string, sep string) string {
	return strings.Join(parts, sep)
}

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

func strconvAtoiSafe(s string) (int, error) {
	return strconv.Atoi(s)
}

func intToString(n int) string {
	return strconv.Itoa(n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
