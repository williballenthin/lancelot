package main

import (
	"errors"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/williballenthin/Lancelot/utils/hexdump"
	"io/ioutil"
	"log"
	"os"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to dump",
}

var verboseFlag = cli.BoolFlag{
	Name:  "verbose",
	Usage: "print debugging output",
}

var RequiredFlagNotProvidedError = errors.New("Required flag not provided.")

func checkRequiredArgs(c *cli.Context, requiredFlags []cli.StringFlag) error {
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

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func doit(inputFile string) error {
	f, e := os.Open(inputFile)
	if e != nil {
		return e
	}
	defer f.Close()

	b, e := ioutil.ReadAll(f)
	if e != nil {
		return e
	}

	e = hexdump.Dump(b, os.Stdout)
	if e != nil {
		return e
	}

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "crystal-tiger-hexdump"
	app.Usage = "hexdump binary data."
	app.Flags = []cli.Flag{inputFlag, verboseFlag}
	app.Action = func(c *cli.Context) {
		if checkRequiredArgs(c, []cli.StringFlag{inputFlag}) != nil {
			return
		}
		check(doit(c.String("input_file")))
	}
	app.Run(os.Args)
}
