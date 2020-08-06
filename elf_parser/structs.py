from ctypes import *
from .constants import *

class ELF32FileHeader(Structure):
    _fields_ = [
        ("e_indent", c_char * EI_NINDENT),
        ("e_type", c_uint16),
        ("e_machine", c_uint16),
        ("e_version", c_uint32),
        ("e_entry", c_uint32),
        ("e_phoff", c_uint32),
        ("e_shoff", c_uint32),
        ("e_flags", c_uint32),
        ("e_ehsize", c_uint16),
        ("e_phentsize", c_uint16),
        ("e_phnum", c_uint16),
        ("e_shentsize", c_uint16),
        ("e_shnum", c_uint16),
        ("e_shstrndx", c_uint16),
    ]

class ELF32SectionHeader(Structure):
    _fields_ = [
        ("sh_name", c_uint32),
        ("sh_type", c_uint32),
        ("sh_flags", c_uint32),
        ("sh_addr", c_uint32),
        ("sh_offset", c_uint32),
        ("sh_size", c_uint32),
        ("sh_link", c_uint32),
        ("sh_info", c_uint32),
        ("sh_addralign", c_uint32),
        ("sh_entsize", c_uint32),
    ]

class ELF32ProgramHeader(Structure):
    _fields_ = [
        ("p_type", c_uint32),
        ("p_offset", c_uint32),
        ("p_vaddr", c_uint32),
        ("p_paddr", c_uint32),
        ("p_filesz", c_uint32),
        ("p_memsz", c_uint32),
        ("p_flags", c_uint32),
        ("p_align", c_uint32),
    ]

class ELF32SymbolHeader(Structure):
    _fields_ = [
        ("st_name", c_uint32),
        ("st_value", c_uint32),
        ("st_size", c_uint32),
        ("st_info", c_uint8),
        ("st_other", c_uint8),
        ("st_shndx", c_uint16),
    ]

class ELF32DynUnion(Union):
    _fields_ = [
        ("d_val", c_uint32),
        ("d_ptr", c_uint32),
    ]

class ELF32DynSymbolHeader(Structure):
    _fields_ = [
        ("d_tag", c_uint32),
        ("d_un", ELF32DynUnion),
    ]

class ELF64FileHeader(Structure):
    _fields_ = [
        ("e_indent", c_char * EI_NINDENT),
        ("e_type", c_uint16),
        ("e_machine", c_uint16),
        ("e_version", c_uint32),
        ("e_entry", c_uint64),
        ("e_phoff", c_uint64),
        ("e_shoff", c_uint64),
        ("e_flags", c_uint32),
        ("e_ehsize", c_uint16),
        ("e_phentsize", c_uint16),
        ("e_phnum", c_uint16),
        ("e_shentsize", c_uint16),
        ("e_shnum", c_uint16),
        ("e_shstrndx", c_uint16),
    ]

class ELF64SectionHeader(Structure):
    _fields_ = [
        ("sh_name", c_uint32),
        ("sh_type", c_uint32),
        ("sh_flags", c_uint64),
        ("sh_addr", c_uint64),
        ("sh_offset", c_uint64),
        ("sh_size", c_uint64),
        ("sh_link", c_uint32),
        ("sh_info", c_uint32),
        ("sh_addralign", c_uint64),
        ("sh_entsize", c_uint64),
    ]

class ELF64ProgramHeader(Structure):
    _fields_ = [
        ("p_type", c_uint32),
        ("p_offset", c_uint32),
        ("p_vaddr", c_uint64),
        ("p_paddr", c_uint64),
        ("p_filesz", c_uint64),
        ("p_flags", c_uint64),
        ("p_memsz", c_uint64),
        ("p_align", c_uint64),
    ]

class ELF64SymbolHeader(Structure):
    _fields_ = [
        ("st_name", c_uint32),
        ("st_info", c_char),
        ("st_other", c_char),
        ("st_shndx", c_uint16),
        ("st_value", c_uint64),
        ("st_size", c_uint64),
    ]

class ELF64DynUnion(Union):
    _fields_ = [
        ("d_val", c_uint64),
        ("d_ptr", c_uint64),
    ]

class ELF64DynSymbolHeader(Structure):
    _fields_ = [
        ("d_tag", c_int64),
        ("d_un", ELF64DynUnion),
    ]
