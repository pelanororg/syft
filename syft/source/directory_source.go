package source

import (
	"fmt"
	"github.com/anchore/syft/syft/artifact"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/opencontainers/go-digest"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	_ Source          = (*DirectorySource)(nil)
	_ PathInterpreter = (*DirectorySource)(nil)
)

type DirectoryConfig struct {
	Path    string
	Base    string
	Exclude ExcludeConfig
	Name    string // ? can this be done differently?
}

// TODO: add fs.FS support
type DirectorySource struct {
	id       artifact.ID
	config   DirectoryConfig
	resolver *directoryResolver
	mutex    *sync.Mutex

	// implements PathInterpreter
}

func NewFromDirectory(cfg DirectoryConfig) (Source, error) {
	fi, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if !fi.IsDir() {
		return nil, fmt.Errorf("given path is not a directory (path=%q): %w", cfg.Path, err)
	}

	return &DirectorySource{
		id:     artifact.ID(strings.TrimPrefix(digest.FromString(cfg.Path).String(), "sha256:")),
		config: cfg,
		mutex:  &sync.Mutex{},
	}, nil
}

func (s DirectorySource) ID() artifact.ID {
	return s.id
}

func (s DirectorySource) Metadata() PathMetadata {
	return PathMetadata{
		Path: s.config.Path,
		Base: s.config.Base,
	}
}

func (s DirectorySource) Describe() Description {
	return Description{
		ID:       string(s.id),
		Name:     s.config.Path,
		Metadata: s.Metadata(),
	}
}

func (s *DirectorySource) FileResolver(scope Scope) (FileResolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		exclusionFunctions, err := getDirectoryExclusionFunctions(s.config.Path, s.config.Exclude.Paths)
		if err != nil {
			return nil, err
		}

		resolver, err := newDirectoryResolver(s.config.Path, s.config.Base, exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}

		s.resolver = resolver
	}

	return s.resolver, nil
}

func (s *DirectorySource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.resolver = nil
	return nil
}

func getDirectoryExclusionFunctions(root string, exclusions []string) ([]pathIndexVisitor, error) {
	if len(exclusions) == 0 {
		return nil, nil
	}

	// this is what directoryResolver.indexTree is doing to get the absolute path:
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// this handles Windows file paths by converting them to C:/something/else format
	root = filepath.ToSlash(root)

	if !strings.HasSuffix(root, "/") {
		root += "/"
	}

	var errors []string
	for idx, exclusion := range exclusions {
		// check exclusions for supported paths, these are all relative to the "scan root"
		if strings.HasPrefix(exclusion, "./") || strings.HasPrefix(exclusion, "*/") || strings.HasPrefix(exclusion, "**/") {
			exclusion = strings.TrimPrefix(exclusion, "./")
			exclusions[idx] = root + exclusion
		} else {
			errors = append(errors, exclusion)
		}
	}

	if errors != nil {
		return nil, fmt.Errorf("invalid exclusion pattern(s): '%s' (must start with one of: './', '*/', or '**/')", strings.Join(errors, "', '"))
	}

	return []pathIndexVisitor{
		func(path string, info os.FileInfo, _ error) error {
			for _, exclusion := range exclusions {
				// this is required to handle Windows filepaths
				path = filepath.ToSlash(path)
				matches, err := doublestar.Match(exclusion, path)
				if err != nil {
					return nil
				}
				if matches {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return errSkipPath
				}
			}
			return nil
		},
	}, nil
}
