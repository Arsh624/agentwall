// Package attacks holds the scripted attack and benign scenarios the attack suite replays.
package attacks

import "embed"

//go:embed *.json
var FS embed.FS
