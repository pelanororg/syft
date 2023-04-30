package source

type ExcludeConfig struct {
	Paths []string
}

type ImageInterpreter interface {
	Metadata() ImageMetadata
}

type PathInterpreter interface {
	Metadata() PathMetadata
}

type PathMetadata struct {
	Path string
	Base string
}
