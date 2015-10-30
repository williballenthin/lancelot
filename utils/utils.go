package utils

import "github.com/codegangsta/cli"
import "errors"
import "log"
import "fmt"

var RequiredFlagNotProvidedError = errors.New("Required flag not provided.")

func CheckRequiredArgs(c *cli.Context, requiredFlags []cli.StringFlag) error {
	for _, flag := range requiredFlags {
		if c.GlobalString(flag.Name) != "" {
			continue
		}
		if c.String(flag.Name) != "" {
			continue
		}
		log.Printf(fmt.Sprintf("Error: '%s' value required", flag.Name))
		return RequiredFlagNotProvidedError
	}
	return nil
}
