package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

type backgroundTask struct {
	name string
	f func((storage logical.Storage, conf *logical.BackendConfig)
	threads int
	timeout time.Duration
}

type taskStorageStruct struct {
	tasks []backgroundTask
}

func (s *taskStorageStruct) Register(task backgroundTask) error {
	for i := range s.tasks {
		if s.tasks[i].name == task.name {
			return fmt.Errorf("duplicated task")
		}
	}
	s.tasks = append(s.tasks, task)
	return nil
}

func (s *taskStorageStruct) Del(taskName string) {}

var typeStorage taskStorageStruct

func (b *backend) scheduler(storage logical.Storage, conf *logical.BackendConfig) {
	type runnedTask struct {
		endTime time.Time
		task *backgroundTask
		cancel context.CancelFunc
	}
	var runnedTasks []runnedTask
	for {
		currentTime := time.Now()
		for i := range runnedTasks {
			if runnedTasks[i].endTime.Before(currentTime) {
				runnedTasks[i].cancel()
			}
		}
		time.Sleep(time.Second)
	}
}
