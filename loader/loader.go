package loader

import "github.com/williballenthin/CrystalTiger/workspace"

type Loader interface {
	Load(ws *workspace.Workspace) (*workspace.LoadedModule, error)
}
