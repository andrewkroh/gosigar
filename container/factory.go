package container

import (
	"sync"

	"github.com/pkg/errors"
)

// ContainerTool identifies the container tool associated with the process.
type ContainerToolType int

const (
	ContainerToolUnknown ContainerToolType = iota
	ContainerToolDocker
)

func (tool ContainerToolType) String() string {
	switch tool {
	case ContainerToolDocker:
		return "docker"
	default:
		return "unknown"
	}
}

type ContainerTool interface {
	GetContainerData(id string) (*Data, error)

	CanHandleContainer(cgroupPath string) (id string, handles bool)
}

type Data struct {
	Image  string
	ID     string
	Name   string
	Labels map[string]string
	Tool   ContainerToolType
}

type ContainerToolFactory struct {
	factories map[ContainerToolType]ContainerTool
	sync      sync.RWMutex
}

func NewContainerToolFactory() *ContainerToolFactory {
	return &ContainerToolFactory{
		factories: map[ContainerToolType]ContainerTool{},
	}
}

func (f *ContainerToolFactory) RegisterContainerTool(typ ContainerToolType, tool ContainerTool) {
	f.sync.Lock()
	defer f.sync.Unlock()
	f.factories[typ] = tool
}

func (f *ContainerToolFactory) ContainerTool(cgroupPath string) (string, ContainerTool, error) {
	f.sync.RLock()
	defer f.sync.RUnlock()

	for _, tool := range f.factories {
		id, canHandle := tool.CanHandleContainer(cgroupPath)
		if !canHandle {
			continue
		}

		return id, tool, nil
	}

	return "", nil, errors.New("no container tool found")
}
