package nix

import (
	"fmt"
	"regexp"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	catalogerName = "nix-store-cataloger"
	nixStoreGlob  = "**/nix/store/*"
)

var (
	numericPattern = regexp.MustCompile(`\d`)
	// attempts to find the right-most example of something that appears to be a version (semver or otherwise)
	// example input: h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin
	// example output:
	//  version: "-2.34-210"
	//  major: "2"
	//  minor: "34"
	//  patch: "210"
	// (there are other capture groups, but they can be ignored)
	rightMostVersionIshPattern = regexp.MustCompile(`-(?P<version>(?P<major>[0-9][a-zA-Z0-9]*)(\.(?P<minor>[0-9][a-zA-Z0-9]*))?(\.(?P<patch>0|[1-9][a-zA-Z0-9]*)){0,3}(?:-(?P<prerelease>\d*[.a-zA-Z-][.0-9a-zA-Z-]*)*)?(?:\+(?P<metadata>[.0-9a-zA-Z-]+(?:\.[.0-9a-zA-Z-]+)*))?)`)
)

type Cataloger struct{}

func NewStoreCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	// we want to search for only directories, which isn't possible via the stereoscope API, so we need to apply the glob manually on all returned paths
	var pkgs []pkg.Package
	for storeLocation := range resolver.AllLocations() {
		matches, err := doublestar.Match(nixStoreGlob, storeLocation.RealPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match nix store path: %w", err)
		}
		if !matches {
			continue
		}

		storePath := parseNixStorePath(storeLocation.RealPath)

		if storePath == nil || !storePath.isValidPackage() {
			continue
		}

		pkgs = append(pkgs, newNixStorePackage(*storePath, storeLocation))
	}
	return pkgs, nil, nil
}
