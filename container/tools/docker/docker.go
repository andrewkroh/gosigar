package docker

import (
	"regexp"

	"github.com/Sirupsen/logrus"
	"github.com/elastic/gosigar/container"
	"github.com/fsouza/go-dockerclient"
	"github.com/pkg/errors"
)

var log = logrus.WithField("package", "gosigar.containers.tools.docker")

const (
	defaultEndpoint = "unix:///var/run/docker.sock"
)

var (
	dockerIDRegex = regexp.MustCompile(`([0-9a-z]{64})`)
)

type Config struct {
	Endpoint string
}

func Register(factory *container.ContainerToolFactory, config Config) error {
	tool, err := newContainerTool(config.Endpoint)
	if err != nil {
		return err
	}

	factory.RegisterContainerTool(container.ContainerToolDocker, tool)
	return nil
}

type containerTool struct {
	client *docker.Client
}

func newContainerTool(endpoint string) (container.ContainerTool, error) {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	client, err := docker.NewClient(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create docker client for endpoint=%v", endpoint)
	}

	env, err := client.Version()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get docker version")
	}

	version := env.Get("Version")
	log.WithField("docker-version", version).Info("initialized new docker client")

	return &containerTool{client: client}, nil
}

func (d *containerTool) GetContainerData(id string) (*container.Data, error) {
	c, err := d.client.InspectContainer(id)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to inspect container=%v", id)
	}

	return &container.Data{
		ID:     id,
		Name:   c.Name,
		Image:  c.Image,
		Labels: c.Config.Labels,
		Tool:   container.ContainerToolDocker,
	}, nil
}

func (d *containerTool) CanHandleContainer(cgroupPath string) (string, bool) {
	matches := dockerIDRegex.FindStringSubmatch(cgroupPath)
	if len(matches) != 2 {
		return "", false
	}

	return matches[1], true
}
