package portage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// you can get a good sense of test fixtures with:
//   docker run --rm -it gentoo/stage3 bash -c 'find var/db/pkg/ | grep LICENSE | xargs cat'

func Test_extractLicenses(t *testing.T) {

	tests := []struct {
		name    string
		license string
		want    []string
	}{
		{
			name:    "empty",
			license: "",
			want:    []string{},
		},
		{
			name:    "single",
			license: "GPL-2",
			want:    []string{"GPL-2"},
		},
		{
			name:    "multiple",
			license: "GPL-2 GPL-3 ", // note the extra space
			want:    []string{"GPL-2", "GPL-3"},
		},
		// the following cases are NOT valid interpretations, but capture the behavior today.
		// when we follow up later with SPDX license expressions, this can be fixed then.
		{
			name:    "license choices",
			license: "|| ( GPL-2 GPL-3 )",
			// should allow for expression of "NONE OR (GPL-2 OR GPL-3)" or "GPL-2 OR GPL-3",
			// I'm not certain which is correct (NONE isn't allowed, right?)
			want: []string{"GPL-2", "GPL-3"},
		},
		{
			name:    "license choices with use flag",
			license: "LGPL-2.1+ tools? ( GPL-2+ )",
			want:    []string{"GPL-2+", "LGPL-2.1+"}, // should allow for expression of "LGPL-2.1+ OR (LGPL-2.1+ AND GPL-2+)"
		},
		{
			name:    "license choices with unknown suffix",
			license: "GPL-3+ LGPL-3+ || ( GPL-3+ libgcc libstdc++ gcc-runtime-library-exception-3.1 ) FDL-1.3+",
			want: []string{
				"FDL-1.3+", // is it right to include this? what does this represent since a useflag was not specified?
				"GPL-3+",
				"LGPL-3+",
				"gcc-runtime-library-exception-3.1",
				"libgcc",
				"libstdc++",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, extractLicenses(strings.NewReader(tt.license)), "extractLicenses(%v)", tt.license)
		})
	}
}
