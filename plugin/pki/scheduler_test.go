package pki

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func Test_scheduler_register(t *testing.T) {
	s := taskStorageStruct{}
	f1 := func() { fmt.Println("a") }
	f2 := func() { fmt.Println("b") }
	s.register("a", f1, 1, time.Second)
	if len(s.tasks) != 1 {
		t.Fatal("should be one task")
	}
	s.register("b", f2, 4, time.Minute)
	if len(s.tasks) != 2 {
		t.Fatal("should be two tasks")
	}
	s.register("c", f1, 1, time.Second)
	if len(s.tasks) != 3 {
		t.Fatal("should be three tasks")
	}
	s.register("a", f1, 5, time.Hour)
	if len(s.tasks) != 3 {
		t.Fatal("should be three tasks")
	}
	for i, n := range []string{"a", "b", "c"} {
		if s.tasks[i].name != n {
			t.Fatalf("name should be %v", n)
		}
	}
	for i, n := range []int64{1, 4, 1} {
		if s.tasks[i].workers != n {
			t.Fatalf("workers should be %v", n)
		}
	}
}

func Test_scheduler_del(t *testing.T) {
	s := taskStorageStruct{}
	f1 := func() { fmt.Println("a") }
	s.del("0")
	if len(s.tasks) != 0 {
		t.Fatal("should be zero tasks")
	}
	s.register("1", f1, 1, time.Second)
	s.del("0")
	if len(s.tasks) != 1 {
		t.Fatal("should be one task")
	}
	s.del("1")
	if len(s.tasks) != 0 {
		t.Fatal("should be zero tasks")
	}
	s.register("2", f1, 1, time.Second)
	s.register("3", f1, 1, time.Second)
	s.register("4", f1, 1, time.Second)
	s.register("5", f1, 1, time.Second)
	s.register("6", f1, 1, time.Second)
	s.del("2")
	s.del("4")
	s.del("6")
	if len(s.tasks) != 2 {
		t.Fatal("should be two tasks")
	}
	if s.tasks[0].name != "3" || s.tasks[1].name != "5" {
		t.Fatal("incorrect tasks was deleted")
	}
}

func Test_scheduler_concurency(t *testing.T) {
	t.Skip("Skip until fixing issue https://github.com/Venafi/vault-pki-monitor-venafi/issues/48")
	s := taskStorageStruct{}
	const threads = 100
	const iterations = 1000
	s.init()
	var globalCounter int64
	for i := 0; i < threads; i++ {
		go func(i int) {
			for j := 0; j < iterations; j++ {
				if j%10 == 0 {
					s.del(fmt.Sprintf("task-%v-%v", i, j-1))
				}
				s.register(fmt.Sprintf("task-%v-%v", i, j), func() {
					atomic.AddInt64(&globalCounter, 1)
				}, 1, time.Hour)
			}

		}(i)
	}
	time.Sleep(time.Minute * 2)
	tasksCount := threads*iterations*9/10 + threads
	if len(s.tasks) != tasksCount {
		t.Fatalf("tasks count should be %v but it is %v", tasksCount, len(s.tasks))
	}
	if globalCounter < int64(tasksCount) || globalCounter > threads*iterations {
		t.Fatalf("something wrong with incrementer value: %v. should be between %v and %v", globalCounter, tasksCount, threads*iterations)
	}
}

func Test_scheduler_running(t *testing.T) {
	s := taskStorageStruct{}
	const iterations = 1000
	var globalCounter int64
	s.init()
	for i := 0; i < iterations; i++ {
		s.register(fmt.Sprintf("task-%v", i), func() {
			atomic.AddInt64(&globalCounter, 1)
		}, 1, time.Second*10)
	}
	time.Sleep(time.Second * 28)
	if globalCounter != iterations*3 {
		t.Fatalf("global counter should be %v but it is %v", iterations*3, globalCounter)
	}
}
