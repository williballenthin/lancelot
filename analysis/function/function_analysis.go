package function_analysis

import (
	"github.com/williballenthin/Lancelot/artifacts"
)

type FunctionAnalysis interface {
	AnalyzeFunction(f *artifacts.Function) error

	// currently:
	//   name - 25
	//   direct call - 50
	//   stack delta - 50  (must be before emulation)
	Priority() uint
}
