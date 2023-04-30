package spdxhelpers

import (
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/scheme"
)

func DocumentName(srcMetadata source.Metadata) string {
	if srcMetadata.Name != "" {
		return srcMetadata.Name
	}

	switch srcMetadata.Scheme {
	case scheme.ContainerImageScheme:
		return srcMetadata.ImageMetadata.UserInput
	case scheme.DirectoryScheme, scheme.FileScheme:
		return srcMetadata.Path
	default:
		return "unknown"
	}
}
