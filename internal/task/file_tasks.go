package task

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/filedigest"
	"github.com/anchore/syft/syft/file/cataloger/filemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func NewFileDigestCatalogerTask(selection file.Selection, hashers ...crypto.Hash) Task {
	if selection == file.NoFilesSelection || len(hashers) == 0 {
		return nil
	}

	digestsCataloger := filedigest.NewCataloger(hashers)

	fn := func(resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		var coordinates []file.Coordinates

		accessor.ReadFromSBOM(func(sbom *sbom.SBOM) {
			if selection == file.OwnedFilesSelection {
				for _, r := range sbom.Relationships {
					// TODO: double check this logic
					if r.Type != artifact.ContainsRelationship {
						continue
					}
					if _, ok := r.From.(pkg.Package); !ok {
						continue
					}
					if c, ok := r.To.(file.Coordinates); ok {
						coordinates = append(coordinates, c)
					}
				}
			}
		})

		result, err := digestsCataloger.Catalog(resolver, coordinates...)
		if err != nil {
			return fmt.Errorf("unable to catalog file digests: %w", err)
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileDigests = result
		})

		return nil
	}

	return NewTask("file-digest-cataloger", fn)
}

func NewFileMetadataCatalogerTask(selection file.Selection) Task {
	if selection == file.NoFilesSelection {
		return nil
	}

	metadataCataloger := filemetadata.NewCataloger()

	fn := func(resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		var coordinates []file.Coordinates

		accessor.ReadFromSBOM(func(sbom *sbom.SBOM) {
			if selection == file.OwnedFilesSelection {
				for _, r := range sbom.Relationships {
					if r.Type != artifact.ContainsRelationship {
						continue
					}
					if _, ok := r.From.(pkg.Package); !ok {
						continue
					}
					if c, ok := r.To.(file.Coordinates); ok {
						coordinates = append(coordinates, c)
					}
				}
			}
		})

		result, err := metadataCataloger.Catalog(resolver, coordinates...)
		if err != nil {
			return err
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileMetadata = result
		})

		return nil
	}

	return NewTask("file-metadata-cataloger", fn)
}