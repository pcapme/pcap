package server

import (
	"fmt"
	petname "github.com/dustinkirkland/golang-petname"
	"github.com/google/gopacket/pcap"
	"github.com/lxc/lxd/shared/logger"
	"gopkg.in/yaml.v3"
	"log"
	"strings"
	"time"
)

type Event int

const (
	Add Event = iota
	Pause
	Delete
)

type State int

const (
	Pending State = iota
	Active
	Warning
	Error
	Retrying
	Paused
	Finished
)

type InterfaceCaptureState struct {
	state    State
	err      error
	handle   *pcap.Handle
	notifier chan bool
}

type CaptureState struct {
	Name           string
	Interfaces     []string
	Filter         string
	SnapshotLength int
	Deadline       time.Time `yaml:",omitempty"`

	state map[string]InterfaceCaptureState
}

type CaptureStateEvent struct {
	Event        Event
	CaptureState *CaptureState
	Result       chan CaptureStateEventResult
}

type CaptureStateEventResult struct {
	CaptureState CaptureState
	Error        error
}

type CaptureStates []*CaptureState

var captureStates CaptureStates

var EventQueue chan CaptureStateEvent

func init() {
	EventQueue = make(chan CaptureStateEvent, 16)
	go consumeCaptureStateEvents()
}

func consumeCaptureStateEvents() {
	captureStates = make(CaptureStates, 0, 16)
	for {
		event := <-EventQueue
		newState, err := processCaptureEvent(event)
		event.Result <- CaptureStateEventResult{
			CaptureState: *newState,
			Error:        err,
		}
	}
}

// captureIndexByName returns the index into captureStates that corresponds with the
// specified name, if it exists. Otherwise, it returns -1.
func captureIndexByName(name string) int {
	for i, state := range captureStates {
		if state.Name == name {
			return i
		}
	}
	return -1
}

func processCaptureEvent(event CaptureStateEvent) (*CaptureState, error) {
	var err error = nil
	var newState *CaptureState = nil
	fmt.Printf("Event received: %+v\n", event)
	newState = event.CaptureState
	switch eventType := event.Event; eventType {
	case Add:
		name := strings.TrimSpace(newState.Name)
		// Generate a name if one wasn't supplied.
		if name == "" {
			name = petname.Generate(2, "-")
		}
		// Validate that the name doesn't exist in the captureStates slice.
		if captureIndexByName(name) >= 0 {
			// Already exists.
			err = fmt.Errorf("capture already exists with name: %s", name)
			break
		}
		// Now that we know we have a good name, store it in the CaptureState object.
		event.CaptureState.Name = name
		// Validate the interfaces and filter are valid.
		// If the capture started successfully, append it to captureStates.
		captureStates = append(captureStates, newState)
		err = StartCaptures(newState)
		fmt.Printf("Capture states: %+v\n", captureStates)
	default:
		err = fmt.Errorf("unhandled event: %+v", event)
	}
	return newState, err
}

func NewCaptureState(name string, interfaces []string, filter string, snaplen int, deadline time.Time) *CaptureState {
	return &CaptureState{
		Name:           name,
		Interfaces:     interfaces,
		Filter:         filter,
		SnapshotLength: snaplen,
		Deadline:       deadline,
		state:          make(map[string]InterfaceCaptureState, len(interfaces)),
	}
}

func AddCaptureState(state *CaptureState) CaptureStateEventResult {
	event := CaptureStateEvent{
		Event:        Add,
		CaptureState: state,
		Result:       make(chan CaptureStateEventResult),
	}
	EventQueue <- event
	result := <-event.Result
	return result
}

func (cs *CaptureStates) ToYAML() (out []byte) {
	var err error
	out, err = yaml.Marshal(cs)
	if err != nil {
		panic(err)
	}
	return
}

func StartCaptures(state *CaptureState) error {
	log.Printf("StartCaptures(%+v)\n", *state)
	for _, ifname := range state.Interfaces {
		handle, err := StartCapture(ifname, state.Filter, state.SnapshotLength)
		if err != nil {
			logger.Errorf("Error starting capture: %v\n", err)
		} else {
			logger.Info("Started capture on %v, filter=%v, snaplen=%d",
				ifname, state.Filter, state.SnapshotLength)
		}
		ifstate := InterfaceCaptureState{}
		state.state[ifname] = ifstate
		if err != nil {
			ifstate.err = err
			ifstate.state = Error
			continue
		}
		ifstate.state = Active
		ifstate.handle = handle
		log.Println("Reading packets...")
		go ifstate.readPackets()
	}
	return nil
}
