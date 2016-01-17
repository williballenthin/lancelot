package file_analysis

type FileAnalysis interface {
	AnalyzeAll() error

	// currently:
	//  entry point - 50
	//  prologue - 75
	Priority() uint

	Close() error
}
