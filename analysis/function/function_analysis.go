package function_analysis

import (
	"github.com/williballenthin/Lancelot/artifacts"
)

type FunctionAnalysis interface {
	AnalyzeFunction(f *artifacts.Function) error
}
