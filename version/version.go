package version

import "fmt"

var (
	Version    = "0.0.1"
	GitVersion = ""
	BuildDate  = "2022-01-01 15:00:00"
)

func Info() string {
	return fmt.Sprintf("version: %s.%s (built at %s)", Version, GitVersion, BuildDate)
}
