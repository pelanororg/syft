/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"github.com/anchore/syft/syft/artifact"
	"io"
	"strings"
)

type Source interface {
	artifact.Identifiable
	FileResolver(Scope) (FileResolver, error)
	Describe() Description
	io.Closer
}

//// Input is an object that captures the detected user input regarding source location, scheme, and provider type.
//// It acts as a struct input for some source constructors.
//type Input struct {
//	UserInput   string
//	Scheme      Scheme
//	ImageSource image.Source
//	Location    string
//	Platform    string
//	Name        string
//}
//
//// ParseInput generates a source Input that can be used as an argument to generate a new source
//// from specific providers including a registry.
//func ParseInput(userInput string, platform string) (*Input, error) {
//	return ParseInputWithName(userInput, platform, "", "")
//}
//
//// ParseInputWithName generates a source Input that can be used as an argument to generate a new source
//// from specific providers including a registry, with an explicit name.
//func ParseInputWithName(userInput string, platform, name, defaultImageSource string) (*Input, error) {
//	fs := afero.NewOsFs()
//	scheme, source, location, err := DetectScheme(fs, image.DetectSource, userInput)
//	if err != nil {
//		return nil, err
//	}
//
//	if source == image.UnknownSource {
//		// only run for these two scheme
//		// only check on packages command, attest we automatically try to pull from userInput
//		switch scheme {
//		case ImageScheme, UnknownScheme:
//			scheme = ImageScheme
//			location = userInput
//			if defaultImageSource != "" {
//				source = parseDefaultImageSource(defaultImageSource)
//			} else {
//				imagePullSource := image.DetermineDefaultImagePullSource(userInput)
//				source = imagePullSource
//			}
//			if location == "" {
//				location = userInput
//			}
//		default:
//		}
//	}
//
//	if scheme != ImageScheme && platform != "" {
//		return nil, fmt.Errorf("cannot specify a platform for a non-image source")
//	}
//
//	// collect user input for downstream consumption
//	return &Input{
//		UserInput:   userInput,
//		Scheme:      scheme,
//		ImageSource: source,
//		Location:    location,
//		Platform:    platform,
//		Name:        name,
//	}, nil
//}
//
//func parseDefaultImageSource(defaultImageSource string) image.Source {
//	switch defaultImageSource {
//	case "registry":
//		return image.OciRegistrySource
//	case "docker":
//		return image.DockerDaemonSource
//	case "podman":
//		return image.PodmanDaemonSource
//	default:
//		return image.UnknownSource
//	}
//}
//
//type sourceDetector func(string) (image.Source, string, error)

//func NewFromRegistry(in Input, registryOptions *image.RegistryOptions, exclusions []string) (*Source, func(), error) {
//	source, cleanupFn, err := generateImageSource(in, registryOptions)
//	if source != nil {
//		source.Exclusions = exclusions
//	}
//	return source, cleanupFn, err
//}
//
//// New produces a Source based on userInput like dir: or image:tag
//func New(in Input, registryOptions *image.RegistryOptions, exclusions []string) (*Source, func(), error) {
//	var err error
//	fs := afero.NewOsFs()
//	var source *Source
//	cleanupFn := func() {}
//
//	switch in.Scheme {
//	case FileScheme:
//		source, cleanupFn, err = generateFileSource(fs, in)
//	case DirectoryScheme:
//		source, cleanupFn, err = generateDirectorySource(fs, in)
//	case ImageScheme:
//		source, cleanupFn, err = generateImageSource(in, registryOptions)
//	default:
//		err = fmt.Errorf("unable to process input for scanning: %q", in.UserInput)
//	}
//
//	if err == nil {
//		source.Exclusions = exclusions
//	}
//
//	return source, cleanupFn, err
//}

//func generateImageSource(in Input, registryOptions *image.RegistryOptions) (*Source, func(), error) {
//	img, cleanup, err := getImageWithRetryStrategy(in, registryOptions)
//	if err != nil || img == nil {
//		return nil, cleanup, fmt.Errorf("could not fetch image %q: %w", in.Location, err)
//	}
//
//	s, err := NewFromImageWithName(img, in.Location, in.Name)
//	if err != nil {
//		return nil, cleanup, fmt.Errorf("could not populate source with image: %w", err)
//	}
//
//	return &s, cleanup, nil
//}

func parseScheme(userInput string) string {
	parts := strings.SplitN(userInput, ":", 2)
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

//func generateDirectorySource(fs afero.Fs, in Input) (*Source, func(), error) {
//	fileMeta, err := fs.Stat(in.Location)
//	if err != nil {
//		return nil, func() {}, fmt.Errorf("unable to stat dir=%q: %w", in.Location, err)
//	}
//
//	if !fileMeta.IsDir() {
//		return nil, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", in.Location, err)
//	}
//
//	s, err := NewFromDirectoryWithName(in.Location, in.Name)
//	if err != nil {
//		return nil, func() {}, fmt.Errorf("could not populate source from path=%q: %w", in.Location, err)
//	}
//
//	return &s, func() {}, nil
//}

//func generateFileSource(fs afero.Fs, in Input) (*Source, func(), error) {
//	fileMeta, err := fs.Stat(in.Location)
//	if err != nil {
//		return nil, func() {}, fmt.Errorf("unable to stat dir=%q: %w", in.Location, err)
//	}
//
//	if fileMeta.IsDir() {
//		return nil, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", in.Location, err)
//	}
//
//	s, cleanupFn := NewFromFileWithName(in.Location, in.Name)
//
//	return &s, cleanupFn, nil
//}

//// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
//func NewFromDirectory(path string) (Source, error) {
//	return NewFromDirectoryWithName(path, "")
//}
//
//// NewFromDirectory creates a new source object tailored to catalog a given filesystem directory recursively.
//func NewFromDirectoryRoot(path string) (Source, error) {
//	return NewFromDirectoryRootWithName(path, "")
//}
//
//// NewFromDirectoryWithName creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
//func NewFromDirectoryWithName(path string, name string) (Source, error) {
//	s := Source{
//		mutex: &sync.Mutex{},
//		Metadata: Metadata{
//			Name:   name,
//			Scheme: DirectoryScheme,
//			Path:   path,
//		},
//		path: path,
//	}
//	s.SetID()
//	return s, nil
//}
//
//// NewFromDirectoryRootWithName creates a new source object tailored to catalog a given filesystem directory recursively, with an explicitly provided name.
//func NewFromDirectoryRootWithName(path string, name string) (Source, error) {
//	s := Source{
//		mutex: &sync.Mutex{},
//		Metadata: Metadata{
//			Name:   name,
//			Scheme: DirectoryScheme,
//			Path:   path,
//			Base:   path,
//		},
//		path: path,
//		base: path,
//	}
//	s.SetID()
//	return s, nil
//}

//// NewFromFile creates a new source object tailored to catalog a file.
//func NewFromFile(path string) (Source, func()) {
//	return NewFromFileWithName(path, "")
//}
//
//// NewFromFileWithName creates a new source object tailored to catalog a file, with an explicitly provided name.
//func NewFromFileWithName(path string, name string) (Source, func()) {
//	analysisPath, cleanupFn := fileAnalysisPath(path)
//
//	s := Source{
//		mutex: &sync.Mutex{},
//		Metadata: Metadata{
//			Name:   name,
//			Scheme: FileScheme,
//			Path:   path,
//		},
//		path: analysisPath,
//	}
//
//	s.SetID()
//	return s, cleanupFn
//}

//
//// NewFromImage creates a new source object tailored to catalog a given container image, relative to the
//// option given (e.g. all-layers, squashed, etc)
//func NewFromImage(img *image.Image, userImageStr string) (Source, error) {
//	return NewFromImageWithName(img, userImageStr, "")
//}
//
//// NewFromImageWithName creates a new source object tailored to catalog a given container image, relative to the
//// option given (e.g. all-layers, squashed, etc), with an explicit name.
//func NewFromImageWithName(img *image.Image, userImageStr string, name string) (Source, error) {
//	if img == nil {
//		return Source{}, fmt.Errorf("no image given")
//	}
//
//	s := Source{
//		Image: img,
//		Metadata: Metadata{
//			Name:          name,
//			Scheme:        ImageScheme,
//			metadata: NewImageMetadata(img, userImageStr),
//		},
//	}
//	s.SetID()
//	return s, nil
//}

//func (s *Source) ID() artifact.ID {
//	if s.id == "" {
//		s.SetID()
//	}
//	return s.id
//}
//
//func (s *Source) SetID() {
//	var d string
//	switch s.Metadata.Scheme {
//	case DirectoryScheme:
//		d = digest.FromString(s.Metadata.Path).String()
//	case FileScheme:
//		// attempt to use the digest of the contents of the file as the ID
//		file, err := os.Open(s.Metadata.Path)
//		if err != nil {
//			d = digest.FromString(s.Metadata.Path).String()
//			break
//		}
//		defer file.Close()
//		di, err := digest.FromReader(file)
//		if err != nil {
//			d = digest.FromString(s.Metadata.Path).String()
//			break
//		}
//		d = di.String()
//	case ImageScheme:
//		manifestDigest := digest.FromBytes(s.Metadata.ImageMetadata.RawManifest).String()
//		if manifestDigest != "" {
//			d = manifestDigest
//			break
//		}
//
//		// calcuate chain ID for image sources where manifestDigest is not available
//		// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
//		d = calculateChainID(s.Metadata.ImageMetadata.Layers)
//		if d == "" {
//			// TODO what happens here if image has no layers?
//			// Is this case possible
//			d = digest.FromString(s.Metadata.ImageMetadata.UserInput).String()
//		}
//	default: // for UnknownScheme we hash the struct
//		id, _ := artifact.IDByHash(s)
//		d = string(id)
//	}
//
//	s.id = artifact.ID(strings.TrimPrefix(d, "sha256:"))
//	s.Metadata.ID = strings.TrimPrefix(d, "sha256:")
//}
//
//func (s *Source) FileResolver(scope Scope) (FileResolver, error) {
//	switch s.Metadata.Scheme {
//	case DirectoryScheme, FileScheme:
//		s.mutex.Lock()
//		defer s.mutex.Unlock()
//		if s.directoryResolver == nil {
//			exclusionFunctions, err := getDirectoryExclusionFunctions(s.path, s.Exclusions)
//			if err != nil {
//				return nil, err
//			}
//			resolver, err := newDirectoryResolver(s.path, s.base, exclusionFunctions...)
//			if err != nil {
//				return nil, fmt.Errorf("unable to create directory resolver: %w", err)
//			}
//			s.directoryResolver = resolver
//		}
//		return s.directoryResolver, nil
//	case ImageScheme:
//		var resolver FileResolver
//		var err error
//		switch scope {
//		case SquashedScope:
//			resolver, err = newImageSquashResolver(s.Image)
//		case AllLayersScope:
//			resolver, err = newAllLayersResolver(s.Image)
//		default:
//			return nil, fmt.Errorf("bad image scope provided: %+v", scope)
//		}
//		if err != nil {
//			return nil, err
//		}
//		// image tree contains all paths, so we filter out the excluded entries afterwards
//		if len(s.Exclusions) > 0 {
//			resolver = NewExcludingResolver(resolver, getImageExclusionFunction(s.Exclusions))
//		}
//		return resolver, nil
//	}
//	return nil, fmt.Errorf("unable to determine FilePathResolver with current scheme=%q", s.Metadata.Scheme)
//}
