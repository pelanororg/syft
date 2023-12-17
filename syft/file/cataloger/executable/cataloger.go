package executable

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
	"io"
)

// TODO: this was copied from syft/pkg/internal, we should share this
type unionReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}

type CatalogerConfig struct {
	MIMETypes []string `json:"mimeTypes" yaml:"mimeTypes" mapstructure:"mimeTypes"`
	Globs     []string `json:"globs" yaml:"globs" mapstructure:"globs"`
}

type Cataloger struct {
	config CatalogerConfig
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		MIMETypes: internal.ExecutableMIMETypeSet.List(),
		Globs:     nil,
	}
}

func NewCataloger(cfg CatalogerConfig) *Cataloger {
	return &Cataloger{
		config: cfg,
	}
}

func (i *Cataloger) Catalog(resolver file.Resolver) (map[file.Coordinates]file.Executable, error) {
	locs, err := resolver.FilesByMIMEType(i.config.MIMETypes...)
	if err != nil {
		return nil, fmt.Errorf("unable to get file locations for binaries: %w", err)
	}

	locs, err = filterByGlobs(locs, i.config.Globs)
	if err != nil {
		return nil, err
	}

	results := make(map[file.Coordinates]file.Executable)
	for _, loc := range locs {
		reader, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			// TODO: known-unknowns
			log.WithFields("error", err).Warnf("unable to get file contents for %q", loc.RealPath)
			continue
		}
		exec, err := processExecutable(loc, reader.(unionReader))
		if err != nil {
			log.WithFields("error", err).Warnf("unable to process executable %q", loc.RealPath)
		}
		if exec != nil {
			results[loc.Coordinates] = *exec
		}
	}
	return results, nil
}

func filterByGlobs(locs []file.Location, globs []string) ([]file.Location, error) {
	if len(globs) == 0 {
		return locs, nil
	}
	var filteredLocs []file.Location
	for _, loc := range locs {

		matches, err := locationMatchesGlob(loc, globs)
		if err != nil {
			return nil, err
		}
		if matches {
			filteredLocs = append(filteredLocs, loc)
		}

	}
	return filteredLocs, nil
}

func locationMatchesGlob(loc file.Location, globs []string) (bool, error) {
	for _, glob := range globs {
		for _, path := range []string{loc.RealPath, loc.AccessPath} {
			if path == "" {
				continue
			}
			matches, err := doublestar.Match(glob, path)
			if err != nil {
				return false, fmt.Errorf("unable to match glob %q to path %q: %w", glob, path, err)
			}
			if matches {
				return true, nil
			}
		}
	}
	return false, nil
}

func processExecutable(loc file.Location, reader unionReader) (*file.Executable, error) {
	data := file.Executable{}

	// determine the executable format

	format, err := findExecutableFormat(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to determine executable kind: %w", err)
	}

	if format == "" {
		log.Debugf("unable to determine executable format for %q", loc.RealPath)
		return nil, nil
	}

	data.Format = format

	securityFeatures, err := findSecurityFeatures(format, reader)
	if err != nil {
		log.WithFields("error", err).Warnf("unable to determine security features for %q", loc.RealPath)
		return nil, nil
	}

	data.SecurityFeatures = securityFeatures

	return &data, nil
}

func findExecutableFormat(reader unionReader) (file.ExecutableFormat, error) {
	// read the first sector of the file
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		return "", fmt.Errorf("unable to read first sector of file: %w", err)
	}
	if n < 512 {
		return "", fmt.Errorf("unable to read enough bytes to determine executable format")
	}

	switch {
	case isMacho(buf):
		return file.MachO, nil
	case isPE(buf):
		return file.PE, nil
	case isELF(buf):
		return file.ELF, nil
	}

	return "", nil
}

func isMacho(by []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	if classOrMachOFat(by) && by[7] < 20 {
		return true
	}

	if len(by) < 4 {
		return false
	}

	be := binary.BigEndian.Uint32(by)
	le := binary.LittleEndian.Uint32(by)

	return be == macho.Magic32 ||
		le == macho.Magic32 ||
		be == macho.Magic64 ||
		le == macho.Magic64
}

// Java bytecode and Mach-O binaries share the same magic number.
// More info here https://github.com/threatstack/libmagic/blob/master/magic/Magdir/cafebabe
func classOrMachOFat(in []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	// There should be at least 8 bytes for both of them because the only way to
	// quickly distinguish them is by comparing byte at position 7
	if len(in) < 8 {
		return false
	}

	return bytes.HasPrefix(in, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

func isPE(by []byte) bool {
	return bytes.HasPrefix(by, []byte("MZ"))
}

func isELF(by []byte) bool {
	return bytes.HasPrefix(by, []byte(elf.ELFMAG))
}

func findSecurityFeatures(format file.ExecutableFormat, reader unionReader) (*file.ELFSecurityFeatures, error) {
	switch format {
	case file.ELF:
		return findELFSecurityFeatures(reader)
		//case file.PE:
		//	return findPESecurityFeatures(reader)
		//case file.MachO:
		//	return findMachOSecurityFeatures(reader)
	}
	return nil, fmt.Errorf("unsupported executable format: %q", format)
}
