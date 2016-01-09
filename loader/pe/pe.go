package pe

import (
	"bufio"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"github.com/Sirupsen/logrus"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/workspace"
	"strings"
	"unicode/utf16"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func roundUp(i uint64, base uint64) uint64 {
	if i%base == 0x0 {
		return i
	} else {
		return i + base - (i % base)
	}
}

func roundUpToPage(i uint64) uint64 {
	return roundUp(i, AS.PAGE_SIZE)
}

type PELoader struct {
	name string
	file *pe.File
}

func New(name string, file *pe.File) (*PELoader, error) {
	// TODO: detect bitness
	return &PELoader{name: name, file: file}, nil
}

type ImageImportDirectory struct {
	rvaOriginalThunkTable uint32
	TimeDateStamp         uint32
	ForwarderChain        uint32
	rvaModuleName         uint32
	rvaThunkTable         uint32
}

func (loader *PELoader) loadPESection(
	ws *workspace.Workspace,
	mod *workspace.LoadedModule,
	section *pe.Section) error {

	h := section.SectionHeader

	logrus.Infof("section: %s", section.SectionHeader.Name)
	logrus.Infof("  virtual address: 0x%x", section.SectionHeader.VirtualAddress)
	logrus.Infof("  virtual size: 0x%x", section.SectionHeader.VirtualSize)
	logrus.Infof("  file offset: 0x%x", section.SectionHeader.Offset)
	logrus.Infof("  file size: 0x%x", section.SectionHeader.Size)

	rvaSecStart := AS.RVA(h.VirtualAddress)
	secStart := mod.VA(rvaSecStart)
	secLength := roundUpToPage(uint64(h.VirtualSize))
	e := ws.MemMap(secStart, secLength, fmt.Sprintf("%s/%s", mod.Name, section.SectionHeader.Name))
	check(e)

	d, e := section.Data()
	check(e)

	e = mod.MemWrite(ws, rvaSecStart, d)
	check(e)

	// TODO: apply permissions

	return nil
}

type ImageImportByName struct {
	Hint uint16
	Name string
}

type Flag64 uint64
type Flags64 uint64

var FLAG_IMPORT_BY_ORDINAL Flag64 = 1 << 31

func (i Flags64) isSet(j Flag64) bool {
	return uint64(i)&uint64(j) > 0
}

func (loader *PELoader) resolveThunkTable(
	ws *workspace.Workspace,
	mod *workspace.LoadedModule,
	moduleName string,
	rvaTable AS.RVA) error {

	var offset AS.RVA = rvaTable
	for {
		rvaImport, e := mod.MemReadRva(ws, offset)
		check(e)

		if rvaImport == 0x0 {
			break
		}

		if Flags64(rvaImport).isSet(FLAG_IMPORT_BY_ORDINAL) {
			logrus.Infof("  import by ordinal: %03x", uint64(rvaImport)&uint64(0x7FFFFFFF))
			// TODO: replace thunk with handler
			// notes:
			//    32: PUSH 0xAABBCCDD --> 68 DD CC BB AA
			//        JMP  0xAABBCCDD --> E9 D9 CC BB AA  ugh, relative jump. do a push/ret instead.
			//        RET             --> C3
			//
			mod.Imports[offset] = workspace.LinkedSymbol{
				ModuleName: moduleName,
				SymbolName: fmt.Sprintf("ordinal-%x", uint64(rvaImport)&uint64(0x7FFFFFFF)),
			}
		} else {
			d, e := mod.MemRead(ws, rvaImport, 0x100)
			check(e)

			p := bytes.NewBuffer(d)
			var importByName ImageImportByName
			binary.Read(p, binary.LittleEndian, &importByName.Hint)

			importByName.Name, e = readAscii(d[2:])
			check(e)

			logrus.Infof("  import by name: %s@%s", importByName.Name, rvaImport)
			// TODO: replace thunk with handler
			mod.Imports[offset] = workspace.LinkedSymbol{
				ModuleName: moduleName,
				SymbolName: importByName.Name,
			}
		}

		offset += 4
	}
	return nil
}

func (loader *PELoader) resolveImports(
	ws *workspace.Workspace,
	mod *workspace.LoadedModule,
	dataDirectory [16]pe.DataDirectory) error {

	// since we always map at ImageBase, we don't need to apply (32bit) relocs
	// TODO: check 64bit reloc types

	importDirectory := dataDirectory[1]
	importRva := AS.RVA(importDirectory.VirtualAddress)
	importSize := importDirectory.Size

	logrus.Infof("import rva: %s", importRva)
	logrus.Infof("import size: 0x%x", importSize)

	d, e := mod.MemRead(ws, AS.RVA(importDirectory.VirtualAddress), uint64(importDirectory.Size))
	check(e)

	p := bytes.NewBuffer(d)
	for {
		var dir ImageImportDirectory
		binary.Read(p, binary.LittleEndian, &dir.rvaOriginalThunkTable)
		logrus.Infof("rva import lookup table: 0x%x", dir.rvaOriginalThunkTable)
		if dir.rvaOriginalThunkTable == 0 {
			break
		}
		binary.Read(p, binary.LittleEndian, &dir.TimeDateStamp)
		logrus.Infof("time date stamp: 0x%x", dir.TimeDateStamp)

		binary.Read(p, binary.LittleEndian, &dir.ForwarderChain)
		logrus.Infof("forwarder chain: 0x%x", dir.ForwarderChain)

		binary.Read(p, binary.LittleEndian, &dir.rvaModuleName)

		moduleNameBuf, e := mod.MemRead(ws, AS.RVA(dir.rvaModuleName), 0x100)
		check(e)
		moduleName, e := readAscii(moduleNameBuf)
		check(e)

		logrus.Infof("module name: %s", string(moduleName))

		binary.Read(p, binary.LittleEndian, &dir.rvaThunkTable)
		loader.resolveThunkTable(ws, mod, moduleName, AS.RVA(dir.rvaThunkTable))
	}

	return nil
}

type ImageExportDirectory struct {
	Characteristics          uint32
	TimeDateStamp            uint32
	MajorVersion             uint16
	MinorVersion             uint16
	rvaName                  uint32
	Base                     uint32
	NumberOfFunctions        uint32
	NumberOfNames            uint32
	rvaAddressOfFunctions    uint32
	rvaAddressOfNames        uint32
	rvaAddressOfNameOrdinals uint32
}

func (loader *PELoader) resolveExports(
	ws *workspace.Workspace,
	mod *workspace.LoadedModule,
	dataDirectory [16]pe.DataDirectory) error {
	exportDirectory := dataDirectory[0]
	exportRva := AS.RVA(exportDirectory.VirtualAddress)
	exportSize := exportDirectory.Size

	logrus.Infof("export rva: %s", exportRva)
	logrus.Infof("export size: 0x%x", exportSize)

	d, e := mod.MemRead(ws, AS.RVA(exportDirectory.VirtualAddress), uint64(exportDirectory.Size))
	check(e)

	p := bytes.NewBuffer(d)
	var dir ImageExportDirectory

	binary.Read(p, binary.LittleEndian, &dir.Characteristics)
	binary.Read(p, binary.LittleEndian, &dir.TimeDateStamp)
	binary.Read(p, binary.LittleEndian, &dir.MajorVersion)
	binary.Read(p, binary.LittleEndian, &dir.MinorVersion)
	binary.Read(p, binary.LittleEndian, &dir.rvaName)
	binary.Read(p, binary.LittleEndian, &dir.Base)
	binary.Read(p, binary.LittleEndian, &dir.NumberOfFunctions)
	binary.Read(p, binary.LittleEndian, &dir.NumberOfNames)
	binary.Read(p, binary.LittleEndian, &dir.rvaAddressOfFunctions)
	binary.Read(p, binary.LittleEndian, &dir.rvaAddressOfNames)
	binary.Read(p, binary.LittleEndian, &dir.rvaAddressOfNameOrdinals)

	if dir.rvaAddressOfFunctions == 0 {
		panic("address of functions is NULL")
	}

	exportModuleNameBuf, e := mod.MemRead(ws, AS.RVA(dir.rvaName), 0x100)
	check(e)
	exportModuleName, e := readAscii(exportModuleNameBuf)
	logrus.Infof("export name: %s", string(exportModuleName))
	check(e)

	logrus.Infof("time date stamp: 0x%x", dir.TimeDateStamp)

	// note closure over dir, mod, ws
	readFunctionRva := func(i uint32) (AS.RVA, error) {
		if i > dir.NumberOfFunctions {
			panic("function index too large")
		}
		// sizeof(RVA) is always 4 bytes, even on x64
		return mod.MemReadRva(ws, AS.RVA(dir.rvaAddressOfFunctions+4*i))
	}

	// isForwardedExport returns true when the provided RVA falls within the
	//  export directory table, which is used to signify that an export is
	//  fowarded to another module.
	// implementation: note closure over loader
	isForwardedExport := func(rvaFn AS.RVA) bool {
		if uint32(rvaFn) < exportDirectory.VirtualAddress {
			return false
		}
		if uint32(rvaFn) >= exportDirectory.VirtualAddress+exportDirectory.Size {
			return false
		}
		return true
	}

	// implementation: node closure over mod, ws
	readForwardedSymbol := func(rvaFn AS.RVA) (workspace.LinkedSymbol, error) {
		var forwardedSymbol workspace.LinkedSymbol
		forwardedNameBuf, e := mod.MemRead(ws, AS.RVA(rvaFn), 0x100)
		check(e)
		forwardedName, e := readAscii(forwardedNameBuf)
		check(e)

		i := strings.LastIndex(forwardedName, ".")
		if i == -1 {
			panic("expected to find a '.' in the module name")
		}
		if i >= len(forwardedName) {
			panic("module name ends in period")
		}

		forwardedSymbol.ModuleName = forwardedName[:i]
		forwardedSymbol.SymbolName = forwardedName[i+1:]
		return forwardedSymbol, nil
	}

	// resolve exports by ordinals first
	for i := uint32(0); i < dir.NumberOfFunctions; i++ {
		ordinal := uint16(i + dir.Base)
		rvaFn, e := readFunctionRva(i)
		check(e)

		isForwarded := isForwardedExport(rvaFn)

		sym := workspace.ExportedSymbol{
			RVA:         rvaFn,
			IsForwarded: isForwarded,
		}

		if isForwarded {
			fsym, e := readForwardedSymbol(rvaFn)
			check(e)
			sym.ForwardedSymbol = fsym
		}
		mod.ExportsByOrdinal[ordinal] = sym

		if isForwarded {
			logrus.Infof(" export: (ordinal) %x: %s -> %s.%s",
				ordinal, rvaFn, sym.ForwardedSymbol.ModuleName, sym.ForwardedSymbol.SymbolName)
		} else {
			logrus.Infof(" export: (ordinal) %x: %s", ordinal, rvaFn)
		}
	}

	// resolve exports by name
	for i := uint32(0); i < dir.NumberOfNames; i++ {
		// sizeof(RVA) is always 4 bytes, even on x64
		rvaName, e := mod.MemReadRva(ws, AS.RVA(dir.rvaAddressOfNames+4*i))
		check(e)
		// sizeof(ordinal) is always 2 bytes
		nameOrdinal, e := mod.MemReadShort(ws, AS.RVA(dir.rvaAddressOfNameOrdinals+2*i))
		check(e)
		rvaFn, e := readFunctionRva(uint32(nameOrdinal))
		check(e)

		nameBuf, e := mod.MemRead(ws, AS.RVA(rvaName), 0x100)
		check(e)
		name, e := readAscii(nameBuf)
		check(e)

		isForwarded := isForwardedExport(rvaFn)

		sym := workspace.ExportedSymbol{
			RVA:         rvaFn,
			IsForwarded: isForwarded,
		}

		if isForwarded {
			fsym, e := readForwardedSymbol(rvaFn)
			check(e)
			sym.ForwardedSymbol = fsym
		}
		mod.ExportsByName[name] = sym

		if isForwarded {
			logrus.Infof(" export: %s: %s -> %s.%s",
				name, rvaFn, sym.ForwardedSymbol.ModuleName, sym.ForwardedSymbol.SymbolName)
		} else {
			logrus.Infof(" export: %s: %s", name, rvaFn)
		}
	}

	return nil
}

func (loader *PELoader) Load(ws *workspace.Workspace) (*workspace.LoadedModule, error) {
	var imageBase AS.VA
	var addressOfEntryPoint AS.RVA
	var dataDirectory [16]pe.DataDirectory

	if optionalHeader, ok := loader.file.OptionalHeader.(*pe.OptionalHeader32); ok {
		imageBase = AS.VA(optionalHeader.ImageBase)
		addressOfEntryPoint = AS.RVA(optionalHeader.AddressOfEntryPoint)
		dataDirectory = optionalHeader.DataDirectory
	} else {
		return nil, workspace.InvalidModeError
	}

	mod := &workspace.LoadedModule{
		Name:             loader.name,
		BaseAddress:      imageBase,
		EntryPoint:       addressOfEntryPoint.VA(imageBase),
		Imports:          map[AS.RVA]workspace.LinkedSymbol{},
		ExportsByName:    map[string]workspace.ExportedSymbol{},
		ExportsByOrdinal: map[uint16]workspace.ExportedSymbol{},
	}

	for _, section := range loader.file.Sections {
		e := loader.loadPESection(ws, mod, section)
		check(e)
	}

	e := loader.resolveImports(ws, mod, dataDirectory)
	check(e)

	e = loader.resolveExports(ws, mod, dataDirectory)
	check(e)

	e = ws.AddLoadedModule(mod)
	check(e)

	return mod, nil
}

func readAscii(buf []byte) (string, error) {
	br := bufio.NewReader(bytes.NewReader(buf))
	bytez, e := br.ReadBytes(byte(0x00))
	check(e)
	bytez = bytes.TrimSuffix(bytez, []byte{0x00})
	return string(bytez), nil
}

func readUtf16le(buf []byte) ([]rune, error) {
	start := 0
	end := 0

	for i := 0; i < len(buf)/2; i++ {
		if !(buf[i*2] == 0 && buf[i*2+1] == 0) {
			end = i * 2
			break
		}
	}

	numChars := (end - start) / 2
	d := make([]uint16, numChars)
	for i := 0; i < numChars; i++ {
		d[i] = uint16(buf[i*2]) | (uint16(buf[i*2+1]) << 8)
	}
	return utf16.Decode(d), nil
}
