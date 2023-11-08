package oomprocesser

import "testing"

func TestWatch2(t *testing.T) {
	t.Run("ebpf oom kill process", func(t *testing.T) {
		WatchOOM()
	})
}
