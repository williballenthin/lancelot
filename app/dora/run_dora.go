package main

import (
	"debug/pe"
	"fmt"
	"github.com/codegangsta/cli"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	"github.com/williballenthin/Lancelot/utils"
	W "github.com/williballenthin/Lancelot/workspace"
	"github.com/williballenthin/Lancelot/workspace/dora"
	"log"
	"os"
	"strconv"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to explore",
}

var fvaFlag = cli.StringFlag{
	Name:  "fva",
	Usage: "address of function to explore (hex)",
}

var verboseFlag = cli.BoolFlag{
	Name:  "verbose",
	Usage: "print debugging output",
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func doit(path string, fva W.VA) error {
	f, e := pe.Open(path)
	check(e)

	ws, e := W.New(W.ARCH_X86, W.MODE_32)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	d, e := dora.New(ws)
	check(e)

	e = d.ExploreFunction(fva)
	check(e)

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "run_dora"
	app.Usage = "Invoke dora the explora."
	app.Flags = []cli.Flag{inputFlag, fvaFlag}
	app.Action = func(c *cli.Context) {
		if utils.CheckRequiredArgs(c, []cli.StringFlag{inputFlag, fvaFlag}) != nil {
			return
		}

		inputFile := c.String("input_file")
		if !utils.DoesPathExist(inputFile) {
			log.Printf("Error: file %s must exist", inputFile)
			return
		}

		iva, e := strconv.ParseUint(c.String("fva"), 0x10, 64)
		check(e)
		fva := W.VA(iva)
		check(doit(inputFile, fva))
	}
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
