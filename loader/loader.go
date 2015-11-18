package loader

import "github.com/williballenthin/Lancelot/workspace"

type Loader interface {
	Load(ws *workspace.Workspace) (*workspace.LoadedModule, error)
}
