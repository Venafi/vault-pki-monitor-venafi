package pki

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type backgroundTask struct {
	name           string
	f              func()
	workers        int64
	currentWorkers int64
	interval       time.Duration
	lastRun        time.Time
}

type taskStorageStruct struct {
	inited bool
	tasks  []*backgroundTask
	sync.RWMutex
}

func (task *backgroundTask) cancel() {

}

func (s *taskStorageStruct) getTasksNames() []string {
	s.RLock()
	defer s.RUnlock()
	l := make([]string, len(s.tasks))
	for i := range s.tasks {
		l[i] = s.tasks[i].name
	}
	return l
}

func (s *taskStorageStruct) register(name string, f func(), count int, interval time.Duration) {
	s.Lock()
	defer s.Unlock()
	task := backgroundTask{name: name, f: f, workers: int64(count), interval: interval}
	for i := range s.tasks {
		if s.tasks[i].name == task.name {
			log.Printf("%s duplicated task %v", logPrefixVenafiScheduler, name)
			return
		}
	}
	s.tasks = append(s.tasks, &task)
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

func (s *taskStorageStruct) init() {
	if s.inited {
		panic(logPrefixVenafiScheduler + " twice inited loop")
	}
	s.inited = true
	go s.loop()
}

func (s *taskStorageStruct) loop() {
	for {
		s.RLock()
		for i := range s.tasks {
			currentTask := s.tasks[i]
			if currentTask.currentWorkers >= currentTask.workers {
				continue
			}
			if time.Since(currentTask.lastRun) < currentTask.interval {
				continue
			}
			atomic.AddInt64(&currentTask.currentWorkers, 1)
			go func(counter *int64) {
				defer func(counter *int64) {
					r := recover()
					if r != nil {
						log.Printf("%s job %s failed. recover: %v\n", logPrefixVenafiScheduler, currentTask.name, r)
						//todo: better log
					}
					atomic.AddInt64(counter, -1)
				}(counter)
				currentTask.f()
			}(&currentTask.currentWorkers)
			currentTask.lastRun = time.Now()
		}
		s.RUnlock()
		time.Sleep(time.Second)
	}
}
