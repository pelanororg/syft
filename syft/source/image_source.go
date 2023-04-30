package source

import (
	"context"
	"fmt"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/opencontainers/go-digest"
	"strings"
)

var (
	_ Source           = (*StereoscopeImageSource)(nil)
	_ ImageInterpreter = (*StereoscopeImageSource)(nil)
)

type StereoscopeImageConfig struct {
	Reference       string
	From            image.Source
	Platform        *image.Platform
	RegistryOptions *image.RegistryOptions // TODO: takes platform? as string?
	Exclude         ExcludeConfig
	Name            string // ? can this be done differently?
}

type StereoscopeImageSource struct {
	id       artifact.ID
	config   StereoscopeImageConfig
	image    *image.Image
	metadata ImageMetadata
}

func NewFromImage(cfg StereoscopeImageConfig) (Source, error) {
	ctx := context.TODO()

	var opts []stereoscope.Option
	if cfg.RegistryOptions != nil {
		opts = append(opts, stereoscope.WithRegistryOptions(*cfg.RegistryOptions))
	}

	if cfg.Platform != nil {
		opts = append(opts, stereoscope.WithPlatform(cfg.Platform.String()))
	}

	img, err := stereoscope.GetImageFromSource(ctx, cfg.Reference, cfg.From, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to load image: %w", err)
	}

	metadata := imageMetadataFromStereoscopeImage(img, cfg.Reference)

	return &StereoscopeImageSource{
		id:       artifactIDFromStereoscopeImage(metadata),
		config:   cfg,
		image:    img,
		metadata: metadata,
	}, nil
}

func (s StereoscopeImageSource) ID() artifact.ID {
	return s.id
}

func (s StereoscopeImageSource) Metadata() ImageMetadata {
	return s.metadata
}

func (s StereoscopeImageSource) Describe() Description {
	return Description{
		ID:       string(s.id),
		Name:     s.config.Reference,
		Metadata: s.Metadata(),
	}
}

func (s StereoscopeImageSource) FileResolver(scope Scope) (FileResolver, error) {
	var resolver FileResolver
	var err error

	switch scope {
	case SquashedScope:
		resolver, err = newImageSquashResolver(s.image)
	case AllLayersScope:
		resolver, err = newAllLayersResolver(s.image)
	default:
		return nil, fmt.Errorf("bad image scope provided: %+v", scope)
	}

	if err != nil {
		return nil, err
	}

	// image tree contains all paths, so we filter out the excluded entries afterward
	if len(s.config.Exclude.Paths) > 0 {
		resolver = NewExcludingResolver(resolver, getImageExclusionFunction(s.config.Exclude.Paths))
	}

	return resolver, nil
}

func (s StereoscopeImageSource) Close() error {
	if s.image == nil {
		return nil
	}
	return s.image.Cleanup()
}

func imageMetadataFromStereoscopeImage(img *image.Image, reference string) ImageMetadata {

	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	layers := make([]LayerMetadata, len(img.Layers))
	for _, l := range img.Layers {
		layers = append(layers,
			LayerMetadata{
				MediaType: string(l.Metadata.MediaType),
				Digest:    l.Metadata.Digest,
				Size:      l.Metadata.Size,
			},
		)
	}

	return ImageMetadata{
		ID:             img.Metadata.ID,
		UserInput:      reference,
		ManifestDigest: img.Metadata.ManifestDigest,
		Size:           img.Metadata.Size,
		MediaType:      string(img.Metadata.MediaType),
		Tags:           tags,
		Layers:         layers,
		RawConfig:      img.Metadata.RawConfig,
		RawManifest:    img.Metadata.RawManifest,
		RepoDigests:    img.Metadata.RepoDigests,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
		OS:             img.Metadata.OS,
	}
}

func artifactIDFromStereoscopeImage(metadata ImageMetadata) artifact.ID {
	var input string

	manifestDigest := digest.FromBytes(metadata.RawManifest).String()
	if manifestDigest != "" {
		input = manifestDigest
	} else {
		// calculate chain ID for image sources where manifestDigest is not available
		// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
		input = calculateChainID(metadata.Layers)
		if input == "" {
			// TODO what happens here if image has no layers?
			// is this case possible?
			input = digest.FromString(metadata.UserInput).String()
		}

	}

	return artifact.ID(strings.TrimPrefix(input, "sha256:"))
}

func calculateChainID(lm []LayerMetadata) string {
	if len(lm) < 1 {
		return ""
	}

	// DiffID(L0) = digest of layer 0
	// https://github.com/anchore/stereoscope/blob/1b1b744a919964f38d14e1416fb3f25221b761ce/pkg/image/layer_metadata.go#L19-L32
	chainID := lm[0].Digest
	id := chain(chainID, lm[1:])

	return id
}

func chain(chainID string, layers []LayerMetadata) string {
	if len(layers) < 1 {
		return chainID
	}

	chainID = digest.FromString(layers[0].Digest + " " + chainID).String()
	return chain(chainID, layers[1:])
}

func getImageExclusionFunction(exclusions []string) func(string) bool {
	if len(exclusions) == 0 {
		return nil
	}
	// add subpath exclusions
	for _, exclusion := range exclusions {
		exclusions = append(exclusions, exclusion+"/**")
	}
	return func(path string) bool {
		for _, exclusion := range exclusions {
			matches, err := doublestar.Match(exclusion, path)
			if err != nil {
				return false
			}
			if matches {
				return true
			}
		}
		return false
	}
}
