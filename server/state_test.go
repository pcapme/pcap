package server

import (
	"fmt"
	"log"
	"testing"
	"time"
)

func TestCaptureState(t *testing.T) {
	var captureStates = CaptureStates{
		{
			Name:           "arp-eth0",
			Interfaces:     []string{"eth0"},
			Filter:         "arp",
			SnapshotLength: 64,
			Deadline:       time.Time{},
		},
	}
	log.Printf("%+v\n", captureStates)
	var b = captureStates.ToYAML()
	fmt.Printf("%s", string(b))
}
