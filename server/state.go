package server

import (
	"gopkg.in/yaml.v3"
	"time"
)

type State int

const (
	Pending State = iota
	Active
	Retrying
	Paused
	Finished
)

type CaptureState struct {
	Name string
	Interfaces []string
	Filter string
	SnapshotLength uint32
	Deadline time.Time `yaml:",omitempty"`

	state State
}

type CaptureStates []CaptureState

func (cs* CaptureStates) ToYAML() (out []byte){
	var err error
	out, err = yaml.Marshal(cs)
	if err != nil {
		panic(err)
	}
	return
}
