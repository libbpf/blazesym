package blazesym_test

import (
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	blazesym "github.com/libbpf/blazesym/go"
)

func isSelfStripped() bool {
	f, err := os.Open(os.Args[0])
	if err != nil {
		panic(err)
	}

	e, err := elf.NewFile(f)
	if err != nil {
		panic(err)
	}

	for _, section := range e.Sections {
		if section.Name == ".debug_line" {
			return false
		}
	}

	return true
}

func TestSymbolizeProcess(t *testing.T) {
	if isSelfStripped() {
		t.Skip("test binary is stripped, skipping")
		return
	}

	symbolizer, err := blazesym.NewSymbolizer()
	if err != nil {
		t.Fatal(err)
	}

	addr := reflect.ValueOf(TestSymbolizeProcess).Pointer()

	syms, err := symbolizer.SymbolizeProcessAbsAddrs(
		[]uint64{uint64(addr)},
		uint32(os.Getpid()),
		blazesym.ProcessSourceWithDebugSyms(true),
		blazesym.ProcessSourceWithoutMapFiles(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if syms[0].Name != "github.com/libbpf/blazesym/go_test.TestSymbolizeProcess" {
		t.Errorf("unexpected name: %v", syms[0].Name)
	}
}

func TestSymbolizeElfStripped(t *testing.T) {
	symbolizer, err := blazesym.NewSymbolizer()
	if err != nil {
		t.Fatal(err)
	}

	syms, err := symbolizer.SymbolizeElfVirtOffsets([]uint64{uint64(0x2000200)}, "../data/test-stable-addrs-stripped.bin")
	if err != nil {
		t.Fatal(err)
	}

	if syms[0].Reason != blazesym.SymbolizeReasonMissingSyms {
		t.Errorf("expected SymbolizeReasonMissingSyms, got %v", syms[0].Reason)
	}
}

type symbolizeClosure func(*blazesym.Symbolizer, []uint64) ([]blazesym.Sym, error)

func testElfDwarfGsymSource(t *testing.T, symbolize symbolizeClosure, hasCodeInfo bool) {
	symbolizer, err := blazesym.NewSymbolizer()
	if err != nil {
		t.Fatal(err)
	}

	syms, err := symbolize(symbolizer, []uint64{0x2000200})
	if err != nil {
		t.Fatal(err)
	}

	if syms[0].Reason != blazesym.SymbolizeReasonSuccess {
		t.Errorf("expected symbolication to succeed, got reason %d", syms[0].Reason)
	}

	if syms[0].Name != "factorial" {
		t.Errorf("expected name factorial, got %q", syms[0].Name)
	}

	if syms[0].Addr != 0x2000200 {
		t.Errorf("expected addr 0x2000200, got 0x%x", syms[0].Addr)
	}

	if syms[0].Offset != 0 {
		t.Errorf("expected offset 0, got %d", syms[0].Offset)
	}

	if hasCodeInfo {
		if syms[0].CodeInfo == nil {
			t.Error("expected code info to be present")
		} else {
			if syms[0].CodeInfo.Dir == "" {
				t.Errorf("expected non-empty dir, got %q", syms[0].CodeInfo.Dir)
			}

			if syms[0].CodeInfo.File != "test-stable-addrs.c" {
				t.Errorf("expected file to be test-stable-addrs.c, got %q", syms[0].CodeInfo.File)
			}

			if syms[0].CodeInfo.Line != 10 {
				t.Errorf("expected line to be 10, got %d", syms[0].CodeInfo.Line)
			}
		}
	} else {
		if syms[0].CodeInfo != nil {
			t.Errorf("expected no code info, got %#v", syms[0].CodeInfo)
		}
	}

	if syms[0].Size == 0 {
		t.Error("expected non-zero size, got zero")
	}

	offsetAddrs := make([]uint64, syms[0].Size-1)
	for offset := range syms[0].Size - 1 {
		offsetAddrs[offset] = uint64(0x2000200 + offset + 1)
	}

	syms, err = symbolize(symbolizer, offsetAddrs)
	if err != nil {
		t.Error(err)
	}

	if len(syms) != len(offsetAddrs) {
		t.Errorf("got %d syms for %d addrs", len(syms), len(offsetAddrs))
	}

	for i := range syms {
		if syms[i].Name != "factorial" {
			t.Errorf("expected name factorial, got %q", syms[i].Name)
		}

		if syms[i].Addr != 0x2000200 {
			t.Errorf("expected addr 0x2000200, got 0x%x", syms[i].Addr)
		}

		if syms[i].Offset != uint64(i+1) {
			t.Errorf("expected offset %d, got %d", i+1, syms[i].Offset)
		}

		if hasCodeInfo {
			if syms[i].CodeInfo == nil {
				t.Error("expected code info to be present")
			} else {
				if syms[i].CodeInfo.Dir == "" {
					t.Errorf("expected non-empty dir, got %q", syms[i].CodeInfo.Dir)
				}

				if syms[i].CodeInfo.File != "test-stable-addrs.c" {
					t.Errorf("expected file to be test-stable-addrs.c, got %q", syms[i].CodeInfo.File)
				}

				if syms[i].CodeInfo.Line == 0 {
					t.Error("expected line to non-zero")
				}
			}
		} else {
			if syms[i].CodeInfo != nil {
				t.Errorf("expected no code info, got %#v", syms[i].CodeInfo)
			}
		}
	}
}

func TestSymbolizeElfDwarfGsym(t *testing.T) {
	elfSymbolize := func(path string) symbolizeClosure {
		return func(symbolizer *blazesym.Symbolizer, addrs []uint64) ([]blazesym.Sym, error) {
			return symbolizer.SymbolizeElfVirtOffsets(addrs, path, blazesym.ElfSourceWithDebugSyms(true))
		}
	}

	for _, file := range []string{
		"test-stable-addrs-no-dwarf.bin",
		"test-stable-addrs-stripped-with-link-to-elf-only.bin",
		"test-stable-addrs-32-no-dwarf.bin",
	} {
		t.Run(file, func(t *testing.T) {
			testElfDwarfGsymSource(t, elfSymbolize(filepath.Join("../data", file)), false)
		})
	}

	for _, file := range []string{
		"test-stable-addrs-stripped-elf-with-dwarf.bin",
		"test-stable-addrs-lto.bin",
		"test-stable-addrs-compressed-debug-zlib.bin",
	} {
		t.Run(file, func(t *testing.T) {
			testElfDwarfGsymSource(t, elfSymbolize(filepath.Join("../data", file)), true)
		})
	}

	gsymFileSymbolize := func(path string) symbolizeClosure {
		return func(symbolizer *blazesym.Symbolizer, addrs []uint64) ([]blazesym.Sym, error) {
			return symbolizer.SymbolizeGsymFileVirtOffsets(addrs, path)
		}
	}

	gsymDataSymbolize := func(data []byte) symbolizeClosure {
		return func(symbolizer *blazesym.Symbolizer, addrs []uint64) ([]blazesym.Sym, error) {
			return symbolizer.SymbolizeGsymDataVirtOffsets(addrs, data)
		}
	}

	gsymFilePath := "test-stable-addrs.gsym"
	t.Run(gsymFilePath, func(t *testing.T) {
		path := filepath.Join("../data", gsymFilePath)

		testElfDwarfGsymSource(t, gsymFileSymbolize(path), true)

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("error reading %q: %v", path, err)
		}

		testElfDwarfGsymSource(t, gsymDataSymbolize(data), true)
	})
}

func copyFile(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}

	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer d.Close()

	_, err = io.Copy(d, s)
	if err != nil {
		return err
	}

	return nil
}

func TestConfigurableDebugDirs(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "*")
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "test-stable-addrs-stripped-with-link.bin")

	err = copyFile(dst, filepath.Join("../data", "test-stable-addrs-stripped-with-link.bin"))
	if err != nil {
		t.Fatal(err)
	}

	symbolizer, err := blazesym.NewSymbolizer(blazesym.SymbolizerWithDebugDirs([]string{}))
	if err != nil {
		t.Fatal(err)
	}

	syms, err := symbolizer.SymbolizeElfVirtOffsets([]uint64{0x2000200}, dst, blazesym.ElfSourceWithDebugSyms(true))
	if err != nil {
		t.Fatal(err)
	}

	if syms[0].Name != "" {
		t.Errorf("expected symbol to be not resolved, got %q", syms[0].Name)
	}

	if syms[0].Reason != blazesym.SymbolizeReasonMissingSyms {
		t.Errorf("expected reason to be SymbolizeReasonMissingSyms, got %v", syms[0].Reason)
	}

	debugDir1, err := os.MkdirTemp(os.TempDir(), "*")
	if err != nil {
		t.Fatal(err)
	}

	debugDir2, err := os.MkdirTemp(os.TempDir(), "*")
	if err != nil {
		t.Fatal(err)
	}

	debugDst := filepath.Join(debugDir2, "test-stable-addrs-dwarf-only.dbg")

	err = copyFile(debugDst, filepath.Join("../data", "test-stable-addrs-dwarf-only.dbg"))
	if err != nil {
		t.Fatal(err)
	}

	symbolizer, err = blazesym.NewSymbolizer(blazesym.SymbolizerWithDebugDirs([]string{debugDir1, debugDir2}))
	if err != nil {
		t.Fatal(err)
	}

	syms, err = symbolizer.SymbolizeElfVirtOffsets([]uint64{0x2000200}, dst, blazesym.ElfSourceWithDebugSyms(true))
	if err != nil {
		t.Fatal(err)
	}

	if syms[0].Name != "factorial" {
		t.Errorf("expected symbol to resolve to factorial, got %q", syms[0].Name)
	}

	if syms[0].Module != dst {
		t.Errorf("expected module to be %q, got %q", dst, syms[0].Module)
	}
}
