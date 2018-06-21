// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"bytes"
	"cmd/link/internal/sym"
	"encoding/binary"
	"strings"
)

/* Derived from AIX include files and
 * cmd/link/internal/pe.go => PE and Xcoff are based on Coff files
 *
 * XCOFF 64 bits only
 */

/*
 * Total amount of space to reserve at the start of the file
 * for FileHeader, Auxiliary Header , and Section Headers.
 * May waste some.
 * Based on 24 (fhdr) + 120 (ahdr) + 23(max sections number)*72 ( scnhdr)
 */
const (
	XCOFFHDRRESERVE = FILHSZ_64 + AOUTHSZ_EXEC64 + SCNHSZ_64*23
)

const (
	XCOFFSECTALIGN int64 = 32 // base on dump -o
	XCOFFFILEALIGN int64 = 32 // temporary value based on PE. TODO: find xcoff equivalent
	XCOFFBASE            = 0x100000000
)

/*
 * Headers Structures
 */

// File Header
type XcoffFileHdr64 struct {
	Fmagic   uint16 // Target machine
	Fnscns   uint16 // Number of sections
	Ftimedat int32  // Time and date of file creation
	Fsymptr  uint64 // Byte offset to symbol table start
	Fopthdr  uint16 // Number of bytes in optional header
	Fflags   uint16 // Flags
	Fnsyms   int32  // Number of entries in symbol table
}

const (
	U802TOCMAGIC = 0737 // AIX 32-bit XCOFF
	U64_TOCMAGIC = 0767 // AIX 64-bit XCOFF
)

// Flags that describe the type of the object file.
const (
	F_RELFLG    = 0x0001
	F_EXEC      = 0x0002
	F_LNNO      = 0x0004
	F_FDPR_PROF = 0x0010
	F_FDPR_OPTI = 0x0020
	F_DSA       = 0x0040
	F_VARPG     = 0x0100
	F_DYNLOAD   = 0x1000
	F_SHROBJ    = 0x2000
	F_LOADONLY  = 0x4000
)

// Auxiliary Header
type XcoffAoutHdr64 struct {
	Omagic      int16    // Flags - Ignored If Vstamp Is 1
	Ovstamp     int16    // Version
	Odebugger   uint32   // Reserved For Debugger
	Otextstart  uint64   // Virtual Address Of Text
	Odatastart  uint64   // Virtual Address Of Data
	Otoc        uint64   // Toc Address
	Osnentry    int16    // Section Number For Entry Point
	Osntext     int16    // Section Number For Text
	Osndata     int16    // Section Number For Data
	Osntoc      int16    // Section Number For Toc
	Osnloader   int16    // Section Number For Loader
	Osnbss      int16    // Section Number For Bss
	Oalgntext   int16    // Max Text Alignment
	Oalgndata   int16    // Max Data Alignment
	Omodtype    [2]byte  // Module Type Field
	Ocpuflag    uint8    // Bit Flags - Cputypes Of Objects
	Ocputype    uint8    // Reserved for CPU type
	Otextpsize  uint8    // Requested text page size
	Odatapsize  uint8    // Requested data page size
	Ostackpsize uint8    // Requested stack page size
	Oflags      uint8    // Flags And TLS Alignment
	Otsize      uint64   // Text Size In Bytes
	Odsize      uint64   // Data Size In Bytes
	Obsize      uint64   // Bss Size In Bytes
	Oentry      uint64   // Entry Point Address
	Omaxstack   uint64   // Max Stack Size Allowed
	Omaxdata    uint64   // Max Data Size Allowed
	Osntdata    int16    // Section Number For Tdata Section
	Osntbss     int16    // Section Number For Tbss Section
	Ox64flags   uint16   // Additional Flags For 64-Bit Objects
	Oresv3a     int16    // Reserved
	Oresv3      [2]int32 // Reserved

}

// Section Header
type XcoffScnHdr64 struct {
	Sname    [8]byte // Section Name
	Spaddr   uint64  // Physical Address
	Svaddr   uint64  // Virtual Address
	Ssize    uint64  // Section Size
	Sscnptr  uint64  // File Offset To Raw Data
	Srelptr  uint64  // File Offset To Relocation
	Slnnoptr uint64  // File Offset To Line Numbers
	Snreloc  uint32  // Number Of Relocation Entries
	Snlnno   uint32  // Number Of Line Number Entries
	Sflags   uint32  // flags
}

// Flags defining the section type.
const (
	STYP_DWARF  = 0x0010
	STYP_TEXT   = 0x0020
	STYP_DATA   = 0x0040
	STYP_BSS    = 0x0080
	STYP_EXCEPT = 0x0100
	STYP_INFO   = 0x0200
	STYP_TDATA  = 0x0400
	STYP_TBSS   = 0x0800
	STYP_LOADER = 0x1000
	STYP_DEBUG  = 0x2000
	STYP_TYPCHK = 0x4000
	STYP_OVRFLO = 0x8000
)
const (
	SSUBTYP_DWINFO  = 0x10000 // DWARF info section
	SSUBTYP_DWLINE  = 0x20000 // DWARF line-number section
	SSUBTYP_DWPBNMS = 0x30000 // DWARF public names section
	SSUBTYP_DWPBTYP = 0x40000 // DWARF public types section
	SSUBTYP_DWARNGE = 0x50000 // DWARF aranges section
	SSUBTYP_DWABREV = 0x60000 // DWARF abbreviation section
	SSUBTYP_DWSTR   = 0x70000 // DWARF strings section
	SSUBTYP_DWRNGES = 0x80000 // DWARF ranges section
	SSUBTYP_DWLOC   = 0x90000 // DWARF location lists section
	SSUBTYP_DWFRAME = 0xA0000 // DWARF frames section
	SSUBTYP_DWMAC   = 0xB0000 // DWARF macros section
)

// Headers size
const (
	FILHSZ_32      = 20
	FILHSZ_64      = 24
	AOUTHSZ_EXEC32 = 72
	AOUTHSZ_EXEC64 = 120
	SCNHSZ_32      = 40
	SCNHSZ_64      = 72
	LDHDRSZ_32     = 32
	LDHDRSZ_64     = 56
	LDSYMSZ_64     = 24
)

/*
 * Symbol table Structures
 */

// Symbol Table Entry
type XcoffSymEnt64 struct {
	Nvalue  uint64 // Symbol value
	Noffset uint32 // Offset of the name in string table or .debug section
	Nscnum  int16  // Section number of symbol
	Ntype   uint16 // Basic and derived type specification
	Nsclass uint8  // Storage class of symbol
	Nnumaux int8   // Number of auxiliary entries
}

const SYMESZ = 18

const (
	// Nscnum
	N_DEBUG = -2
	N_ABS   = -1
	N_UNDEF = 0

	//Ntype
	SYM_V_INTERNAL  = 0x1000
	SYM_V_HIDDEN    = 0x2000
	SYM_V_PROTECTED = 0x3000
	SYM_V_EXPORTED  = 0x4000
	SYM_TYPE_FUNC   = 0x0020 // is function
)

// Storage Class.
const (
	C_NULL    = 0   // Symbol table entry marked for deletion
	C_EXT     = 2   // External symbol
	C_STAT    = 3   // Static symbol
	C_BLOCK   = 100 // Beginning or end of inner block
	C_FCN     = 101 // Beginning or end of function
	C_FILE    = 103 // Source file name and compiler information
	C_HIDEXT  = 107 // Unnamed external symbol
	C_BINCL   = 108 // Beginning of include file
	C_EINCL   = 109 // End of include file
	C_WEAKEXT = 111 // Weak external symbol
	C_DWARF   = 112 // DWARF symbol
	C_GSYM    = 128 // Global variable
	C_LSYM    = 129 // Automatic variable allocated on stack
	C_PSYM    = 130 // Argument to subroutine allocated on stack
	C_RSYM    = 131 // Register variable
	C_RPSYM   = 132 // Argument to function or procedure stored in register
	C_STSYM   = 133 // Statically allocated symbol
	C_BCOMM   = 135 // Beginning of common block
	C_ECOML   = 136 // Local member of common block
	C_ECOMM   = 137 // End of common block
	C_DECL    = 140 // Declaration of object
	C_ENTRY   = 141 // Alternate entry
	C_FUN     = 142 // Function or procedure
	C_BSTAT   = 143 // Beginning of static block
	C_ESTAT   = 144 // End of static block
	C_GTLS    = 145 // Global thread-local variable
	C_STTLS   = 146 // Static thread-local variable
)

// File Auxiliary Entry
type XcoffAuxFile64 struct {
	Xfname   [8]byte // Name or offset inside string table
	Xftype   uint8   // Source file string type
	Xauxtype uint8   // Type of auxiliary entry
}

// Function Auxiliary Entry
type XcoffAuxFcn64 struct {
	Xlnnoptr uint64 // File pointer to line number
	Xfsize   uint32 // Size of function in bytes
	Xendndx  uint32 // Symbol table index of next entry
	Xpad     uint8  // Unused
	Xauxtype uint8  // Type of auxiliary entry
}

// csect Auxiliary Entry.
type XcoffAuxCSect64 struct {
	Xscnlenlo uint32 // Lower 4 bytes of length or symbol table index
	Xparmhash uint32 // Offset of parameter type-check string
	Xsnhash   uint16 // .typchk section number
	Xsmtyp    uint8  // Symbol alignment and type
	Xsmclas   uint8  // Storage-mapping class
	Xscnlenhi uint32 // Upper 4 bytes of length or symbol table index
	Xpad      uint8  // Unused
	Xauxtype  uint8  // Type of auxiliary entry
}

// Auxiliary type
const (
	_AUX_EXCEPT = 255
	_AUX_FCN    = 254
	_AUX_SYM    = 253
	_AUX_FILE   = 252
	_AUX_CSECT  = 251
	_AUX_SECT   = 250
)

// Xftype field
const (
	XFT_FN = 0   // Source File Name
	XFT_CT = 1   // Compile Time Stamp
	XFT_CV = 2   // Compiler Version Number
	XFT_CD = 128 // Compiler Defined Information/

)

// Symbol type field.
const (
	XTY_ER  = 0    // External reference
	XTY_SD  = 1    // Section definition
	XTY_LD  = 2    // Label definition
	XTY_CM  = 3    // Common csect definition
	XTY_WK  = 0x8  // Weak symbol
	XTY_EXP = 0x10 // Exported symbol
	XTY_ENT = 0x20 // Entry point symbol
	XTY_IMP = 0x40 // Imported symbol
)

// Storage-mapping class.
const (
	XMC_PR     = 0  // Program code
	XMC_RO     = 1  // Read-only constant
	XMC_DB     = 2  // Debug dictionary table
	XMC_TC     = 3  // TOC entry
	XMC_UA     = 4  // Unclassified
	XMC_RW     = 5  // Read/Write data
	XMC_GL     = 6  // Global linkage
	XMC_XO     = 7  // Extended operation
	XMC_SV     = 8  // 32-bit supervisor call descriptor
	XMC_BS     = 9  // BSS class
	XMC_DS     = 10 // Function descriptor
	XMC_UC     = 11 // Unnamed FORTRAN common
	XMC_TC0    = 15 // TOC anchor
	XMC_TD     = 16 // Scalar data entry in the TOC
	XMC_SV64   = 17 // 64-bit supervisor call descriptor
	XMC_SV3264 = 18 // Supervisor call descriptor for both 32-bit and 64-bit
	XMC_TL     = 20 // Read/Write thread-local data
	XMC_UL     = 21 // Read/Write thread-local data (.tbss)
	XMC_TE     = 22 // TOC entry
)

/*
 * Loader Structures
 */

type XcoffLdHdr64 struct {
	Lversion int32  // Loader section version number
	Lnsyms   int32  // Number of symbol table entries
	Lnreloc  int32  // Number of relocation table entries
	Listlen  uint32 // Length of import file ID string table
	Lnimpid  int32  // Number of import file IDs
	Lstlen   uint32 // Length of string table
	Limpoff  uint64 // Offset to start of import file IDs
	Lstoff   uint64 // Offset to start of string table
	Lsymoff  uint64 // Offset to start of symbol table
	Lrldoff  uint64 // Offset to start of relocation entries
}

// Loader Symbol
type XcoffLdSym64 struct {
	Lvalue  uint64 // Address field
	Loffset uint32 // Byte offset into string table of symbol name
	Lscnum  int16  // Section number containing symbol
	Lsmtype int8   // Symbol type, export, import flags
	Lsmclas int8   // Symbol storage class
	Lifile  int32  // Import file ID; ordinal of import file IDs
	Lparm   uint32 // Parameter type-check field
}

type XcoffLdImportFile64 struct {
	Limpidpath string
	Limpidbase string
	Limpidmem  string
}

type XcoffLdRel64 struct {
	Lvaddr  uint64 // Address Field
	Lrtype  uint16 // Relocation Type
	Lrsecnm int16  // Section Number being relocated
	Lsymndx uint32 // Loader-Section symbol table index
}

type XcoffLdStr64 struct {
	size uint16
	name string
}

// xcoffFile is used to build COFF file.
type xcoffFile struct {
	xfhdr        XcoffFileHdr64
	xahdr        XcoffAoutHdr64
	sections     []*XcoffScnHdr64
	stringTable  xcoffStringTable
	textSect     *XcoffScnHdr64
	dataSect     *XcoffScnHdr64
	bssSect      *XcoffScnHdr64
	loaderSect   *XcoffScnHdr64
	symtabOffset int64           // offset to the start of symbol table
	symbolCount  int             // number of symbol table records written
	dynLibraries map[string]int  // Dynamic libraries in .loader section. The integer represents its import file number ( - 1 )
	dynSymbols   []*sym.Symbol   // Dynamic symbols in .loader section
	loaderReloc  []*XcoffLdRel64 // Reloc that must be made inside loader
}

// Those values will latter be computed in XcoffInit
var (
	XCOFFFILEHDR int
	XCOFFSECTHDR int
)

// Var used by Xcoff Generation algorithms
var (
	xfile      xcoffFile
	loaderOff  uint64
	loaderSize uint64
)

// xcoffStringTable is a COFF string table.
type xcoffStringTable struct {
	strings    []string
	stringsLen int
}

// size resturns size of string table t.
func (t *xcoffStringTable) size() int {
	// string table starts with 4-byte length at the beginning
	return t.stringsLen + 4
}

// add adds string str to string table t.
func (t *xcoffStringTable) add(str string) int {
	off := t.size()
	t.strings = append(t.strings, str)
	t.stringsLen += len(str) + 1 // each string will have 0 appended to it
	return off
}

// write writes string table t into the output file.
func (t *xcoffStringTable) write(out *OutBuf) {
	out.Write32(uint32(t.size()))
	for _, s := range t.strings {
		out.WriteString(s)
		out.Write8(0)
	}
}

// write writes COFF section sect into the output file.
func (sect *XcoffScnHdr64) write(ctxt *Link) {
	binary.Write(ctxt.Out, binary.BigEndian, sect)
	ctxt.Out.Write32(0) // Add 4 empty bytes at the end to match alignment
}

// addSection adds section to the COFF file f.
func (f *xcoffFile) addSection(s *sym.Section) *XcoffScnHdr64 {
	sect := &XcoffScnHdr64{
		Spaddr:  s.Vaddr,
		Svaddr:  s.Vaddr,
		Ssize:   s.Length,
		Sscnptr: s.Seg.Fileoff + s.Vaddr - s.Seg.Vaddr,
	}
	copy(sect.Sname[:], s.Name) // copy string to [8]byte ( pb if len(name) > 8 )
	f.sections = append(f.sections, sect)
	return sect
}
func (f *xcoffFile) addLoaderSection(size uint64, off uint64) *XcoffScnHdr64 {
	sect := &XcoffScnHdr64{
		Ssize:   size,
		Sscnptr: off,
		Sflags:  STYP_LOADER,
	}
	copy(sect.Sname[:], ".loader") // copy string to [8]byte ( pb if len(name) > 8
	f.xahdr.Osnloader = int16(len(f.sections) + 1)
	f.sections = append(f.sections, sect)
	f.loaderSect = sect
	return sect
}

// addDwarfSection adds a dwarf section to the COFF file f.
// This function is similar to addSection, but Dwarf section names
// must be modified to conventional names and they are various subtypes
func (f *xcoffFile) addDwarfSection(s *sym.Section) *XcoffScnHdr64 {
	sect := &XcoffScnHdr64{
		// Spaddr:  s.Vaddr,
		// Svaddr:  s.Vaddr,
		Ssize:   s.Length,
		Sscnptr: s.Seg.Fileoff + s.Vaddr - s.Seg.Vaddr,
		Sflags:  STYP_DWARF,
	}
	newName, subtype := xcoffGetDwarfSubtype(s.Name)
	copy(sect.Sname[:], newName)
	sect.Sflags |= subtype
	f.sections = append(f.sections, sect)
	return sect
}

// Return the xcoff name of the section and its subtype const
func xcoffGetDwarfSubtype(str string) (string, uint32) {
	switch str {
	default:
		Exitf("Unknown Dwarf section name for xcoff: %s\n", str)
	case ".debug_abbrev":
		return ".dwabrev", SSUBTYP_DWABREV
	case ".debug_info":
		return ".dwinfo", SSUBTYP_DWINFO
	case ".debug_frame":
		return ".dwframe", SSUBTYP_DWFRAME
	case ".debug_line":
		return ".dwline", SSUBTYP_DWLINE
	case ".debug_loc":
		return ".dwloc", SSUBTYP_DWLOC
	case ".debug_pubnames":
		return ".dwpbnms", SSUBTYP_DWPBNMS
	case ".debug_pubtypes":
		return ".dwpbtyp", SSUBTYP_DWPBTYP
	case ".debug_ranges":
		return ".dwrnge", SSUBTYP_DWRNGES
	}
	// never used
	return "", 0
}

// Setup already known header information
func Xcoffinit(ctxt *Link) {
	ctxt.IsAix = true
	xfile.dynLibraries = make(map[string]int)
	XCOFFFILEHDR = int(Rnd(XCOFFHDRRESERVE, XCOFFSECTALIGN))
	XCOFFSECTHDR = int(Rnd(int64(XCOFFFILEHDR), XCOFFSECTALIGN))

	HEADR = int32(XCOFFFILEHDR)
	if *FlagTextAddr != -1 {
		ctxt.Logf("-T not available on AIX. Set default -T = 0x%x\n", XCOFFBASE+int64(XCOFFSECTHDR))
	}
	*FlagTextAddr = XCOFFBASE + int64(XCOFFSECTHDR)
	*FlagDataAddr = 0
	if *FlagRound != -1 {
		ctxt.Logf("-R not implemented. Setup to default -R = 0x%x\n", XCOFFSECTALIGN)
	}
	*FlagRound = int(XCOFFSECTALIGN)

}

/*
 * SYMBOL TABLE
 */

// type records C_FILE information needed for genasmsym in Xcoff
type xcoffSymSrcFile struct {
	name       string
	fileSymNb  int // Symbol number of this C_FILE
	csectSymNb int // Symbol number for the current .csect
}

var (
	currDwscnoff   = make(map[string]uint64) // Needed to create C_DWARF symbols
	currSymSrcFile xcoffSymSrcFile
)

// Write a symbol or an auxiliary symbol entry on ctxt.out
func (f *xcoffFile) writeSymbol(out *OutBuf, byteOrder binary.ByteOrder, sym interface{}) {
	binary.Write(out, byteOrder, sym)
	f.symbolCount++
}

/*
* Write symbols needed when a new file appared :
* a C_FILE with one auxiliary entry for its name
* C_DWARF symbols to provide debug information
* C_HIDEXT which will be a csect containing all (?) of its functions
* It needs several parameters to create .csect symbols such as its entry point and its section number ( always 1 ? )
 */
func (f *xcoffFile) writeSymbolNewFile(ctxt *Link, name string, firstEntry uint64, extnum int16) {
	/* C_FILE */
	s := &XcoffSymEnt64{
		Noffset: uint32(f.stringTable.add(".file")),
		Nsclass: C_FILE,
		Nscnum:  N_DEBUG,
		Ntype:   0, // Go isn't inside predefined language. Maybe add Cpu stuff ?
		Nnumaux: 1,
	}
	f.writeSymbol(ctxt.Out, ctxt.Arch.ByteOrder, s)

	// Auxiliary not needed but helps symbol table comprehension
	// Manual cause easier
	ctxt.Out.Write32(0)
	ctxt.Out.Write32(uint32(f.stringTable.add(name)))
	ctxt.Out.Write32(0) // 6 bytes empty
	ctxt.Out.Write16(0)
	ctxt.Out.Write8(XFT_FN)
	ctxt.Out.Write16(0) // 2 bytes empty
	ctxt.Out.Write8(_AUX_FILE)
	f.symbolCount++

	/* Dwarf */
	for _, sect := range Segdwarf.Sections {
		// Find size for this pkg corresponding dwarf compilation unit
		dwsize := getDwsectSize(sect.Name, name)
		// .debug_abbrev is commun and not found with the previous function
		if sect.Name == ".debug_abbrev" {
			s := ctxt.Syms.Lookup(sect.Name, 0)
			dwsize = uint64(s.Size)
		}

		// ctxt.Logf("%s %s offset 0x%x\n", name, sect.Name, dwsize)

		// get xcoff name
		name, _ := xcoffGetDwarfSubtype(sect.Name)
		s := &XcoffSymEnt64{
			Nvalue:  currDwscnoff[sect.Name],
			Noffset: uint32(f.stringTable.add(name)),
			Nsclass: C_DWARF,
			Nscnum:  sect.Extnum,
			Nnumaux: 1,
		}
		f.writeSymbol(ctxt.Out, ctxt.Arch.ByteOrder, s)

		// update section offset if not in abbrev section
		if sect.Name != ".debug_abbrev" {
			currDwscnoff[sect.Name] += dwsize
		}

		// Auxiliary dwarf section
		ctxt.Out.Write64(dwsize) // section length
		ctxt.Out.Write64(0)      // nreloc
		ctxt.Out.Write8(0)       // pad
		ctxt.Out.Write8(_AUX_SECT)
		f.symbolCount++
	}

	/* .csect */
	// Check if extnum is in text.
	// This is temporary and only here to check if this algorithm is correct
	if extnum != 1 {
		Exitf("Xcoff symtab: A new file was detected with its first symbol not in .text\n")
	}

	currSymSrcFile.csectSymNb = f.symbolCount

	// No offset because no name
	s = &XcoffSymEnt64{
		Nvalue:  firstEntry,
		Nscnum:  extnum,
		Nsclass: C_HIDEXT,
		Ntype:   0, // check visibility ?
		Nnumaux: 1,
	}
	f.writeSymbol(ctxt.Out, ctxt.Arch.ByteOrder, s)

	aux := &XcoffAuxCSect64{
		// Xsclen ???
		Xsmclas:  XMC_PR,
		Xsmtyp:   XTY_SD | 5<<3, // align = 5. Might need fix ?
		Xauxtype: _AUX_CSECT,
	}
	f.writeSymbol(ctxt.Out, ctxt.Arch.ByteOrder, aux)

}

// Update Svalue of a C_FILE symbol
// If it is the last one, this Svalue must be -1
func (f *xcoffFile) updateCFileSvalue(ctxt *Link, last bool) {
	// first file
	if currSymSrcFile.fileSymNb == 0 {
		return
	}

	prevOff := f.symtabOffset + int64(currSymSrcFile.fileSymNb*18)
	currOff := ctxt.Out.Offset()

	ctxt.Out.SeekSet(prevOff)
	if last {
		ctxt.Out.Write64(0xFFFFFFFFFFFFFFFF)
	} else {
		ctxt.Out.Write64(uint64(f.symbolCount))
	}
	ctxt.Out.SeekSet(currOff)

}

// Write symbol representing a .text function.
// Split symbol table with C_FILE corresponding to pkg and not source file
func (f *xcoffFile) writeSymbolFunc(ctxt *Link, x *sym.Symbol) []interface{} {
	// New Xcoff symbols
	syms := []interface{}{}

	// Check if new file
	if x.File == "" { // Undefined global symbol
		// If this happens, the algo must be redone !
		if currSymSrcFile.name != "" {
			Exitf("Undefined global symbol found inside another file \n")
		}
	} else {
		// File changed must generated C_FILE, C_DWARF, etc
		if currSymSrcFile.name != x.File {
			// update previous file Svalue
			xfile.updateCFileSvalue(ctxt, false)
			currSymSrcFile.name = x.File
			currSymSrcFile.fileSymNb = f.symbolCount
			f.writeSymbolNewFile(ctxt, x.File, uint64(x.Value), x.Sect.Extnum)
		}
	}

	s := &XcoffSymEnt64{
		Nsclass: C_EXT,
		Noffset: uint32(xfile.stringTable.add(x.Name)),
		Nvalue:  uint64(x.Value),
		Nscnum:  x.Sect.Extnum,
		Ntype:   SYM_TYPE_FUNC,
		Nnumaux: 2,
	}
	syms = append(syms, s)

	// create auxiliary entry
	a2 := &XcoffAuxFcn64{
		Xfsize:   uint32(x.Size),
		Xlnnoptr: 0,                             // TODO
		Xendndx:  uint32(xfile.symbolCount + 3), // this symbol + 2 aux entries
		Xauxtype: _AUX_FCN,
	}
	syms = append(syms, a2)

	a4 := &XcoffAuxCSect64{
		Xscnlenlo: uint32(currSymSrcFile.csectSymNb & 0x00FF),
		Xscnlenhi: uint32(currSymSrcFile.csectSymNb >> 8),
		Xsmclas:   XMC_PR, // Program Code ?
		Xsmtyp:    XTY_LD, // label definition ( based on C )
		Xauxtype:  _AUX_CSECT,
	}
	syms = append(syms, a4)
	return syms
}

// put function used by genasmsym to write symbol table
// TODO: visibility ( cf STB_GLOBAL and STB_LOCAL in elf )
func putaixsym(ctxt *Link, x *sym.Symbol, str string, t SymbolType, addr int64, go_ *sym.Symbol) {
	// ctxt.Logf("%s: %c\n", str, t)

	// All xcoff symbols generated by this GO symbols
	// Can be symbol entry or auxiliary entry
	syms := []interface{}{}

	switch t {
	default:
		return

		/*
		 * This Type seems to be only for functions which are defined inside .text.
		 * In Xcoff, those functions can be in two storage classes
		 * C_EXT : if it's a external symbol
		 * ??? :  if it's a local symbol ( TODO )
		 */
	case TextSym:
		// Function within a file
		if x.FuncInfo != nil {
			syms = xfile.writeSymbolFunc(ctxt, x) // No need to append yet
		} else {
			// TODO: runtime.text and runtime.etext
			s := &XcoffSymEnt64{
				Nsclass: C_EXT,
				Noffset: uint32(xfile.stringTable.add(str)),
				Nvalue:  uint64(x.Value),
				Nscnum:  x.Sect.Extnum,
				Ntype:   SYM_TYPE_FUNC,
				Nnumaux: 0,
			}
			syms = append(syms, s)
		}

	case DataSym, BSSSym:
		// Only object ???
		s := &XcoffSymEnt64{
			Nsclass: C_HIDEXT,
			Noffset: uint32(xfile.stringTable.add(str)),
			Nvalue:  uint64(x.Value),
			Nscnum:  x.Sect.Extnum,
			//Nnumaux: 1,
		}
		syms = append(syms, s)

		// TODO: linked with toc.
		// a4 := &XcoffAuxCSect64{
		// 	Xsmtyp:   XTY_SC | 5<<3, // align = 5. Might need to be changed
		// 	Xauxtype: _AUX_CSECT,
		// }

	}
	for _, s := range syms {
		xfile.writeSymbol(ctxt.Out, ctxt.Arch.ByteOrder, s)
	}
}

// Generate xcoff Symbol table and xcoff String table
func Asmaixsym(ctxt *Link) {
	// write symbol table
	xfile.symtabOffset = ctxt.Out.Offset()
	genasmsym(ctxt, putaixsym)

	// update last file Svalue
	xfile.updateCFileSvalue(ctxt, true)

	// write string table
	xfile.stringTable.write(ctxt.Out)
}

// Add a new imported symbol and a new library if needed
func (f *xcoffFile) adddynimpsym(ctxt *Link, s *sym.Symbol) {
	// Check that library name is given
	// Pattern is already checked when compiling
	if s.Dynimplib == "" {
		Errorf(s, "imported symbol must have a given library")
	}

	for _, sf := range f.dynSymbols {
		if sf == s {
			return
		}
	}
	f.dynSymbols = append(f.dynSymbols, s)
	s.Type = sym.SXCOFFTOC
	// Function descriptor value
	s.AddUint64(ctxt.Arch, 0)

	if _, ok := f.dynLibraries[s.Dynimplib]; !ok {
		f.dynLibraries[s.Dynimplib] = len(f.dynLibraries)
	}
}

// Add a relocation to .loader relocation section
func (f *xcoffFile) addloaderreloc(ctxt *Link, s *sym.Symbol, r *sym.Reloc) {
	// Currently only TOC is relocated this way
	ldr := &XcoffLdRel64{
		Lvaddr:  uint64(s.Value + int64(r.Off)),
		Lrtype:  0x3F00,
		Lrsecnm: s.Sect.Extnum,
		Lsymndx: 1,
	}
	f.loaderReloc = append(f.loaderReloc, ldr)

}

func (ctxt *Link) doxcoff() {
	/* TOC */
	toc := ctxt.Syms.Lookup("TOC", 0)
	toc.Type = sym.SXCOFFTOC
	toc.Attr |= sym.AttrReachable

	// // TOC address is 2nd doubleword in entrypoing function descriptor
	// ep := ctxt.Syms.ROLookup(*flagEntrySymbol, 0)
	// ep.SetAddr(ctxt.Arch, 8, toc)

}

/*
 * Loader section
 * Currently, this section is created from scratch when assembling xcoff file
 * but it might be better to create a data symbol for this.
 */

// Create loader section and returns its size
func Loaderblk(ctxt *Link, off uint64) uint64 {
	xfile.writeLdrScn(ctxt, off)
	return loaderSize
}

func (f *xcoffFile) writeLdrScn(ctxt *Link, globalOff uint64) {
	var symtab []*XcoffLdSym64
	var strtab []*XcoffLdStr64
	var importtab []*XcoffLdImportFile64
	var reloctab []*XcoffLdRel64
	var dynimpreloc []*XcoffLdRel64

	/* As the string table is updated in any of the loader subsection,
	 * its length must be computed at the same time
	 */
	stlen := uint32(0)

	// Loader Header
	hdr := &XcoffLdHdr64{
		Lversion: 2,
		Lsymoff:  LDHDRSZ_64,
	}

	/* Symbol table */
	// Entry point symbol
	ep := ctxt.Syms.ROLookup(*flagEntrySymbol, 0)
	if !ep.Attr.Reachable() {
		Exitf("Wrong entry point.\n")
	}
	lds := &XcoffLdSym64{
		Lvalue:  uint64(ep.Value),
		Loffset: uint32(stlen + 2), // +2 because its must the first byte of the symbol not its size field
		Lscnum:  ep.Sect.Extnum,
		Lsmtype: XTY_ENT | XTY_SD,
		Lsmclas: XMC_DS,
		Lifile:  0,
		Lparm:   0,
	}
	ldstr := &XcoffLdStr64{
		size: uint16(len(ep.String()) + 1), // + null terminator
		name: ep.String(),
	}
	stlen += uint32(2 + ldstr.size) // 2 = sizeof ldstr.size
	symtab = append(symtab, lds)
	strtab = append(strtab, ldstr)

	nbldsym := int32(4)
	// dynamic import

	for _, s := range f.dynSymbols {
		lds = &XcoffLdSym64{
			Loffset: uint32(stlen + 2),
			Lsmtype: XTY_IMP,
			Lsmclas: XMC_DS,
			Lifile:  int32(f.dynLibraries[s.Dynimplib] + 1),
		}
		ldstr := &XcoffLdStr64{
			size: uint16(len(s.Extname) + 1), // + null terminator
			name: s.Extname,
		}
		stlen += uint32(2 + ldstr.size) // 2 = sizeof ldstr.size
		symtab = append(symtab, lds)
		strtab = append(strtab, ldstr)

		// Create relocation entry at the same moment to get symndx
		ldr := &XcoffLdRel64{
			Lvaddr:  uint64(s.Value),
			Lrtype:  0x3F00,
			Lrsecnm: s.Sect.Extnum,
			Lsymndx: uint32(nbldsym),
		}
		dynimpreloc = append(dynimpreloc, ldr)
		nbldsym++

	}

	hdr.Lnsyms = int32(len(symtab))
	hdr.Lrldoff = hdr.Lsymoff + uint64(24*hdr.Lnsyms) // 24 = sizeof one symbol
	off := hdr.Lrldoff                                // current offset is the same of reloc offset

	/* Reloc */
	ldr := &XcoffLdRel64{
		Lvaddr:  uint64(ep.Value),
		Lrtype:  0x3F00,
		Lrsecnm: ep.Sect.Extnum,
		Lsymndx: 0,
	}
	off += 16
	reloctab = append(reloctab, ldr)

	off += uint64(16 * len(f.loaderReloc))
	reloctab = append(reloctab, (f.loaderReloc)...)

	off += uint64(16 * len(dynimpreloc))
	reloctab = append(reloctab, dynimpreloc...)

	hdr.Lnreloc = int32(len(reloctab))
	hdr.Limpoff = off

	/* Import */
	// Default import: /usr/lib:/lib
	ldimpf := &XcoffLdImportFile64{
		Limpidpath: "/usr/lib:/lib",
	}
	off += uint64(len(ldimpf.Limpidpath) + len(ldimpf.Limpidbase) + len(ldimpf.Limpidmem) + 3) // + null delimiter
	importtab = append(importtab, ldimpf)

	// The map created by adddynimpsym associates the name to a number
	// This number represents the librairie index (- 1)  in this import files section
	// Therefore, they must be sorted before being put inside the section
	libsOrdered := make([]string, len(f.dynLibraries))
	for key, val := range f.dynLibraries {
		if libsOrdered[val] != "" {
			continue
		}
		libsOrdered[val] = key
	}

	for _, lib := range libsOrdered {
		// lib string is defined base.a/mem.o
		n := strings.Split(lib, "/")
		ldimpf = &XcoffLdImportFile64{
			Limpidpath: "",
			Limpidbase: n[0],
			Limpidmem:  n[1],
		}
		off += uint64(len(ldimpf.Limpidpath) + len(ldimpf.Limpidbase) + len(ldimpf.Limpidmem) + 3) // + null delimiter
		importtab = append(importtab, ldimpf)
	}

	hdr.Lnimpid = int32(len(importtab))
	hdr.Listlen = uint32(off - hdr.Limpoff)
	hdr.Lstoff = off
	hdr.Lstlen = stlen

	/* Writing */
	ctxt.Out.SeekSet(int64(globalOff))
	binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, hdr)

	for _, s := range symtab {
		binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, s)

	}
	for _, r := range reloctab {
		binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, r)
	}
	for _, f := range importtab {
		ctxt.Out.WriteString(f.Limpidpath)
		ctxt.Out.Write8(0)
		ctxt.Out.WriteString(f.Limpidbase)
		ctxt.Out.Write8(0)
		ctxt.Out.WriteString(f.Limpidmem)
		ctxt.Out.Write8(0)
	}
	for _, s := range strtab {
		ctxt.Out.Write16(s.size)
		ctxt.Out.WriteString(s.name)
		ctxt.Out.Write8(0) // null terminator
	}

	loaderOff = globalOff
	loaderSize = off + uint64(stlen)
	ctxt.Out.Flush()

	/* again for printing */
	if !*flagA {
		return
	}

	ctxt.Logf("\n.loader section")
	// write in buf
	var buf bytes.Buffer

	binary.Write(&buf, ctxt.Arch.ByteOrder, hdr)
	for _, s := range symtab {
		binary.Write(&buf, ctxt.Arch.ByteOrder, s)

	}
	for _, f := range importtab {
		buf.WriteString(f.Limpidpath)
		buf.WriteByte(0)
		buf.WriteString(f.Limpidbase)
		buf.WriteByte(0)
		buf.WriteString(f.Limpidmem)
		buf.WriteByte(0)
	}
	for _, s := range strtab {
		binary.Write(&buf, ctxt.Arch.ByteOrder, s.size)
		buf.WriteString(s.name)
		buf.WriteByte(0) // null terminator
	}

	// Log buffer
	ctxt.Logf("\n\t%.8x|", globalOff)
	for i, b := range buf.Bytes() {
		if i > 0 && i%16 == 0 {
			ctxt.Logf("\n\t%.8x|", uint64(globalOff)+uint64(i))
		}
		ctxt.Logf(" %.2x", b)
	}
	ctxt.Logf("\n")

}

/*
 * xcoff assembling and writing file
 */

func (f *xcoffFile) writeFileHeader(ctxt *Link) {
	// File header
	f.xfhdr.Fmagic = U64_TOCMAGIC
	f.xfhdr.Fnscns = uint16(len(f.sections))
	f.xfhdr.Ftimedat = 0

	// FlagS !
	if !*FlagS {
		f.xfhdr.Fsymptr = uint64(f.symtabOffset)
		f.xfhdr.Fnsyms = int32(f.symbolCount)
	}

	if ctxt.BuildMode == BuildModeExe {
		f.xfhdr.Fopthdr = AOUTHSZ_EXEC64
		f.xfhdr.Fflags = F_EXEC

		// auxiliary header
		f.xahdr.Ovstamp = 1 // based on dump -o
		f.xahdr.Omagic = 0x10b
		copy(f.xahdr.Omodtype[:], "1L") // copy string to [8]byte ( pb if len(name) > 8
		f.xahdr.Oentry = uint64(Entryvalue(ctxt))
		f.xahdr.Otoc = uint64(ctxt.Syms.ROLookup("TOC", 0).Value)

		// Based on dump -o
		f.xahdr.Oalgntext = 0x5
		f.xahdr.Oalgndata = 0x5

		binary.Write(ctxt.Out, binary.BigEndian, &f.xfhdr)
		binary.Write(ctxt.Out, binary.BigEndian, &f.xahdr)
	} else {
		f.xfhdr.Fopthdr = 0
		binary.Write(ctxt.Out, binary.BigEndian, &f.xfhdr)
	}

}

func xcoffwrite(ctxt *Link) {
	ctxt.Out.SeekSet(0)

	xfile.writeFileHeader(ctxt)

	for _, sect := range xfile.sections {
		sect.write(ctxt)
	}
}

// Generate xcoff assembly file
func Asmbxcoff(ctxt *Link) {
	//initial offset for sections
	if ctxt.BuildMode == BuildModeExe {
		// search entry section number
		eaddr := uint64(Entryvalue(ctxt))
		for _, sect := range append(Segtext.Sections, Segdata.Sections...) {
			if eaddr-sect.Vaddr <= sect.Length {
				xfile.xahdr.Osnentry = int16(sect.Extnum)
			}
		}

		// search toc section number TODO

		// check
		if xfile.xahdr.Osnentry == 0 {
			Exitf("Internal Error:  Section number for entry point (addr = 0x%x) not found.\n", eaddr)
		}

	}

	// add text sections
	for _, sect := range Segtext.Sections {
		// ctxt.Logf(".text: %s \n", sect.Name)
		s := xfile.addSection(sect)
		s.Sflags = STYP_TEXT

		// use sect.Name because of convertion inside scnhdr
		if sect.Name == ".text" {
			xfile.xahdr.Otextstart = s.Spaddr
			xfile.xahdr.Otsize = s.Ssize
			xfile.xahdr.Osntext = sect.Extnum
		}
	}

	// add data sections
	var (
		snoptrdata,
		sdata,
		sbss,
		snoptrbss *sym.Section
	)
	for _, sect := range Segdata.Sections {
		if sect.Name == ".noptrdata" {
			snoptrdata = sect
		}
		if sect.Name == ".noptrbss" {
			snoptrbss = sect
		}
		if sect.Name == ".data" {
			sdata = sect
		}
		if sect.Name == ".bss" {
			sbss = sect
		}
	}

	// Merge .noptrdata inside .data
	sdata.Length += snoptrdata.Length
	sdata.Vaddr = snoptrdata.Vaddr
	s := xfile.addSection(sdata)
	s.Sflags = STYP_DATA
	xfile.xahdr.Odatastart = s.Spaddr
	xfile.xahdr.Odsize = s.Ssize
	xfile.xahdr.Osndata = sdata.Extnum

	// Merge .noptrbss inside .bss
	sbss.Length += snoptrbss.Length
	s = xfile.addSection(sbss)
	s.Sflags = STYP_BSS
	xfile.xahdr.Obsize = s.Ssize
	xfile.xahdr.Osnbss = sbss.Extnum
	s.Sscnptr = 0

	// add dwarf section
	for _, sect := range Segdwarf.Sections {
		xfile.addDwarfSection(sect)
	}

	// Loader section must be add at the end because of sect.Extnum
	// in others sections
	xfile.addLoaderSection(loaderSize, loaderOff)

	xcoffwrite(ctxt)

}
