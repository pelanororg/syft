package portage

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
)

// the licenses files seems to conform to a custom format that is common to gentoo packages.
// see more details:
//  - https://www.gentoo.org/glep/glep-0023.html#id9
//  - https://devmanual.gentoo.org/general-concepts/licenses/index.html
//
// in short, the format is:
//
//   mandatory-license
//      || ( choosable-licence1 chooseable-license-2 )
//      useflag? ( optional-component-license )
//
//   "License names may contain [a-zA-Z0-9] (english alphanumeric characters), _ (underscore), - (hyphen), .
//   (dot) and + (plus sign). They must not begin with a hyphen, a dot or a plus sign."
//
// this does not conform to SPDX license expressions, which would be a great enhancement in the future.

func extractLicenses(reader io.Reader) []string {
	findings := internal.NewStringSet()
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		token := scanner.Text()
		if !strings.ContainsAny(token, "()|?") {
			findings.Add(token)
		}
	}
	licenses := findings.ToSlice()
	sort.Strings(licenses)

	return licenses
}
