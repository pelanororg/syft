package main

import "C"
import (
	_ "modernc.org/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli"
	"github.com/anchore/syft/cmd/syft/internal"
)

// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "syft"

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = internal.NotProvided
	buildDate      = internal.NotProvided
	gitCommit      = internal.NotProvided
	gitDescription = internal.NotProvided
)

//export syft_main
func syft_main() {
	app := cli.Application(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()
}

func main() {

}
