package scheme

import (
	"fmt"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/stereoscope/pkg/image"
)

// Scheme represents the optional prefixed string at the beginning of a user request (e.g. "docker:").
type Scheme string

type sourceDetector func(string) (image.Source, string, error)

const (
	// UnknownScheme is the default scheme
	UnknownScheme Scheme = "UnknownScheme"
	// DirectoryScheme indicates the source being cataloged is a directory on the root filesystem
	DirectoryScheme Scheme = "DirectoryScheme"
	// ContainerImageScheme indicates the source being cataloged is a container image
	ContainerImageScheme Scheme = "ContainerImageScheme"
	// FileScheme indicates the source being cataloged is a single file
	FileScheme Scheme = "FileScheme"
)

var AllSchemes = []Scheme{
	DirectoryScheme,
	ContainerImageScheme,
	FileScheme,
}

// Input is an object that captures the detected user input regarding source location, scheme, and provider type.
// It acts as a struct input for some source constructors.
type Input struct {
	UserInput   string
	Scheme      Scheme
	ImageSource image.Source
	Location    string
	Platform    string
	Name        string
}

// Parse generates a source Input that can be used as an argument to generate a new source
// from specific providers including a registry, with an explicit name.
func Parse(userInput string, platform, name, defaultImageSource string) (*Input, error) {
	fs := afero.NewOsFs()
	scheme, source, location, err := detect(fs, image.DetectSource, userInput)
	if err != nil {
		return nil, err
	}

	if source == image.UnknownSource {
		// only run for these two scheme
		// only check on packages command, attest we automatically try to pull from userInput
		switch scheme {
		case ContainerImageScheme, UnknownScheme:
			scheme = ContainerImageScheme
			location = userInput
			if defaultImageSource != "" {
				source = parseDefaultImageSource(defaultImageSource)
			} else {
				source = image.DetermineDefaultImagePullSource(userInput)
			}
		default:
		}
	}

	if scheme != ContainerImageScheme && platform != "" {
		return nil, fmt.Errorf("cannot specify a platform for a non-image source")
	}

	// collect user input for downstream consumption
	return &Input{
		UserInput:   userInput,
		Scheme:      scheme,
		ImageSource: source,
		Location:    location,
		Platform:    platform,
		Name:        name,
	}, nil
}

func detect(fs afero.Fs, imageDetector sourceDetector, userInput string) (Scheme, image.Source, string, error) {
	switch {
	case strings.HasPrefix(userInput, "dir:"):
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return DirectoryScheme, image.UnknownSource, dirLocation, nil

	case strings.HasPrefix(userInput, "file:"):
		fileLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "file:"))
		if err != nil {
			return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return FileScheme, image.UnknownSource, fileLocation, nil
	}

	// try the most specific sources first and move out towards more generic sources.

	// first: let's try the image detector, which has more scheme parsing internal to stereoscope
	source, imageSpec, err := imageDetector(userInput)
	if err == nil && source != image.UnknownSource {
		return ContainerImageScheme, source, imageSpec, nil
	}

	// next: let's try more generic sources (dir, file, etc.)
	location, err := homedir.Expand(userInput)
	if err != nil {
		return UnknownScheme, image.UnknownSource, "", fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fileMeta, err := fs.Stat(location)
	if err != nil {
		return UnknownScheme, source, "", nil
	}

	if fileMeta.IsDir() {
		return DirectoryScheme, source, location, nil
	}

	return FileScheme, source, location, nil
}

func parseDefaultImageSource(defaultImageSource string) image.Source {
	switch defaultImageSource {
	case "registry":
		return image.OciRegistrySource
	case "docker":
		return image.DockerDaemonSource
	case "podman":
		return image.PodmanDaemonSource
	default:
		return image.UnknownSource
	}
}
