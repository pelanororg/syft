package scheme

import (
	"fmt"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

// NewSource produces a Source based on userInput like dir: or image:tag
func NewSource(in Input, registryOptions *image.RegistryOptions, exclusions []string) (source.Source, error) {
	var err error
	var src source.Source

	switch in.Scheme {
	case FileScheme:
		src, err = source.NewFromFile(
			source.FileConfig{
				Path: in.Location,
				Exclude: source.ExcludeConfig{
					Paths: exclusions,
				},
				Name: in.Name,
			},
		)
	case DirectoryScheme:
		src, err = source.NewFromDirectory(
			source.DirectoryConfig{
				Path:    in.Location,
				Base:    in.Location,
				Exclude: source.ExcludeConfig{},
				Name:    in.Name,
			},
		)
	case ContainerImageScheme:
		var platform *image.Platform
		if in.Platform != "" {
			platform, err = image.NewPlatform(in.Platform)
			if err != nil {
				return nil, fmt.Errorf("unable to parse platform: %w", err)
			}
		}
		src, err = source.NewFromImage(
			source.StereoscopeImageConfig{
				Reference:       in.Location,
				From:            in.ImageSource,
				Platform:        platform,
				RegistryOptions: registryOptions,
				Exclude: source.ExcludeConfig{
					Paths: exclusions,
				},
				Name: in.Name,
			},
		)
	default:
		err = fmt.Errorf("unable to process input for scanning: %q", in.UserInput)
	}

	return src, err
}
