package queue

import (
	"container/list"
	"sync"

	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/generated/api/v1"
	ops "github.com/stackrox/rox/pkg/metrics"
)

// EventQueue provides an interface for a queue that stores SensorEvents.
type EventQueue interface {
	Push(*v1.SensorEvent) error
	Pull() (*v1.SensorEvent, error)
}

type eventQueue struct {
	mutex sync.Mutex

	queue             *list.List
	resourceIDToEvent map[string]*list.Element
}

// NewEventQueue initializes a SensorEvent queue
func NewEventQueue() EventQueue {
	return &eventQueue{
		queue:             list.New(),
		resourceIDToEvent: make(map[string]*list.Element),
	}
}

// Pull attempts to get the next item from the queue.
// When no items are available, both the event and error will be nil.
func (p *eventQueue) Pull() (*v1.SensorEvent, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.queue.Len() == 0 {
		return nil, nil
	}

	metrics.IncrementSensorEventQueueCounter(ops.Remove)
	evt := p.queue.Remove(p.queue.Front()).(*v1.SensorEvent)
	delete(p.resourceIDToEvent, evt.GetId())
	return evt, nil
}

// Push attempts to add an item to the queue, and returns an error if it is unable.
func (p *eventQueue) Push(event *v1.SensorEvent) error {
	metrics.IncrementSensorEventQueueCounter(ops.Add)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if evt, ok := p.resourceIDToEvent[event.GetId()]; ok {
		metrics.IncrementSensorEventQueueCounter(ops.Dedupe)
		p.queue.Remove(evt)
	}

	elemInserted := p.queue.PushBack(event)
	p.resourceIDToEvent[event.GetId()] = elemInserted
	return nil
}
