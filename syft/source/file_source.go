package source

import (
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/mholt/archiver/v3"
	"github.com/opencontainers/go-digest"
	"os"
	"strings"
	"sync"
)

var (
	_ Source          = (*FileSource)(nil)
	_ PathInterpreter = (*FileSource)(nil)
)

type FileConfig struct {
	Path    string
	Exclude ExcludeConfig
	Name    string // ? can this be done differently?
	// base??
}

// TODO: add fs.FS support
type FileSource struct {
	id           artifact.ID
	config       FileConfig
	resolver     *directoryResolver
	mutex        *sync.Mutex
	closer       func() error
	analysisPath string
}

func NewFromFile(cfg FileConfig) (Source, error) {
	fileMeta, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("given path is a directory (path=%q): %w", cfg.Path, err)
	}

	analysisPath, cleanupFn := fileAnalysisPath(cfg.Path)

	return &FileSource{
		id:           artifact.ID(strings.TrimPrefix(digestOfFileContents(cfg.Path), "sha256:")),
		config:       FileConfig{},
		mutex:        &sync.Mutex{},
		closer:       cleanupFn,
		analysisPath: analysisPath,
	}, nil
}

func (s FileSource) ID() artifact.ID {
	return s.id
}

func (s FileSource) Metadata() PathMetadata {
	return PathMetadata{
		Path: s.config.Path,
		Base: "",
	}
}

func (s FileSource) Describe() Description {
	return Description{
		ID:       string(s.id),
		Name:     s.config.Path,
		Metadata: s.Metadata(),
	}
}

func (s FileSource) FileResolver(scope Scope) (FileResolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		exclusionFunctions, err := getDirectoryExclusionFunctions(s.analysisPath, s.config.Exclude.Paths)
		if err != nil {
			return nil, err
		}

		resolver, err := newDirectoryResolver(s.analysisPath, "", exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}

		s.resolver = resolver
	}

	return s.resolver, nil
}

func (s FileSource) Close() error {
	if s.closer == nil {
		return nil
	}
	s.resolver = nil
	return s.closer()
}

// fileAnalysisPath returns the path given, or in the case the path is an archive, the location where the archive
// contents have been made available. A cleanup function is provided for any temp files created (if any).
func fileAnalysisPath(path string) (string, func() error) {
	var analysisPath = path
	var cleanupFn = func() error { return nil }

	// if the given file is an archive (as indicated by the file extension and not MIME type) then unarchive it and
	// use the contents as the source. Note: this does NOT recursively unarchive contents, only the given path is
	// unarchived.
	envelopedUnarchiver, err := archiver.ByExtension(path)
	if unarchiver, ok := envelopedUnarchiver.(archiver.Unarchiver); err == nil && ok {
		if tar, ok := unarchiver.(*archiver.Tar); ok {
			// when tar files are extracted, if there are multiple entries at the same
			// location, the last entry wins
			// NOTE: this currently does not display any messages if an overwrite happens
			tar.OverwriteExisting = true
		}
		unarchivedPath, tmpCleanup, err := unarchiveToTmp(path, unarchiver)
		if err != nil {
			log.Warnf("file could not be unarchived: %+v", err)
		} else {
			log.Debugf("source path is an archive")
			analysisPath = unarchivedPath
		}
		if tmpCleanup != nil {
			cleanupFn = tmpCleanup
		}
	}

	return analysisPath, cleanupFn
}

func digestOfFileContents(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return digest.FromString(path).String()
	}
	defer file.Close()
	di, err := digest.FromReader(file)
	if err != nil {
		return digest.FromString(path).String()
	}
	return di.String()
}

func unarchiveToTmp(path string, unarchiver archiver.Unarchiver) (string, func() error, error) {
	tempDir, err := os.MkdirTemp("", "syft-archive-contents-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
	}

	cleanupFn := func() error {
		return os.RemoveAll(tempDir)
	}

	return tempDir, cleanupFn, unarchiver.Unarchive(path, tempDir) // TODO: does not work, use v4 for io.FS support
}
