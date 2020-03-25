package pki

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type backgroundTask struct {
	name           string
	f              func()
	workers        int64
	currentWorkers int64
}

type taskStorageStruct struct {
	tasks []backgroundTask
	sync.RWMutex
}

var TaskStorage taskStorageStruct

func (task *backgroundTask) cancel() {

}

func (s *taskStorageStruct) register(name string, f func(), count int) error {
	s.Lock()
	defer s.Unlock()
	task := backgroundTask{name: name, f: f, workers: int64(count)}
	for i := range s.tasks {
		if s.tasks[i].name == task.name {
			return fmt.Errorf("duplicated task")
		}
	}
	s.tasks = append(s.tasks, task)
	return nil
}

func (s *taskStorageStruct) del(taskName string) {
	s.Lock()
	defer s.Unlock()
	for i := range s.tasks {
		if s.tasks[i].name == taskName {
			s.tasks[i].cancel()
			s.tasks = append(s.tasks[:i], s.tasks[i+1:]...)
			return
		}
	}
}

func (s *taskStorageStruct) Scheduler() {
	for {
		s.RLock()
		for i := range s.tasks {
			if s.tasks[i].currentWorkers < s.tasks[i].workers {
				atomic.AddInt64(&s.tasks[i].currentWorkers, 1)
				go func(counter *int64) {
					defer func(counter *int64) {
						r := recover()
						if r != nil {
							//todo: log
						}
						atomic.AddInt64(counter, -1)
					}(counter)
					s.tasks[i].f()
				}(&s.tasks[i].currentWorkers)
			}
		}
		s.RUnlock()
		time.Sleep(time.Second)
	}
}
