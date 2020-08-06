from .constants import *
from .structs import *
from .section import Section
from .symbol import Symbol
from .segment import Segment
from .dynamic import Dynamic
import io

class ELF:
    def __init__(self, filename):
        with open(filename, 'rb') as f:
            self.stream = io.BytesIO(f.read())
        # check magic number
        self._check_magic_number()
        # check 32bit or 64bit
        self._check_arch()
        # check endian
        self._check_endian() 
        self.sections  = []
        self.symbols = []
        self.segments = []
        self.dynamics = []
        # load
        self._init_structs()
        self._load_elf_header()
        self._load_segments()
        self._load_sections()
        self._load_symbols()
        self._load_dynamic()

    def _check_magic_number(self):
        self.stream.seek(0)
        mag = self.stream.read(4)
        if mag != b'\x7fELF':
            raise Exception('not ELF')

    def _check_arch(self):
        self.stream.seek(4)
        bits = int.from_bytes(self.stream.read(1), "little")
        if bits == ELFCLASS32:
            self.bits = 32
        elif bits == ELFCLASS64:
            self.bits = 64
        else:
            raise Exception('Does not support!')

    def _check_endian(self):
        self.stream.seek(5)
        endian = int.from_bytes(self.stream.read(1), "little")
        if endian == ELFDATA2LSB:
            self.endian = "little"
        elif endian == ELFDATA2MSB:
            self.endian = "bit"
        else:
            raise Exception('error')

    def _init_structs(self):
        if self.bits == 32:
            self.ehdr_struct = ELF32FileHeader
            self.shdr_struct = ELF32SectionHeader
            self.phdr_struct = ELF32ProgramHeader
            self.symhdr_struct = ELF32SymbolHeader
            self.dynhdr_struct = ELF32DynSymbolHeader
        else:
            self.ehdr_struct = ELF64FileHeader
            self.shdr_struct = ELF64SectionHeader
            self.phdr_struct = ELF64ProgramHeader
            self.symhdr_struct = ELF64SymbolHeader
            self.dynhdr_struct = ELF64DynSymbolHeader

    def _load_elf_header(self):
        self.stream.seek(0)
        self.elf_header = self.ehdr_struct()
        self.stream.readinto(self.elf_header)
        self.machine = [k for k, v in E_MACHINE.items() if v == self.elf_header.e_machine][0]

    def _load_segments(self):
        self.stream.seek(self.elf_header.e_phoff)
        for idx in range(self.elf_header.e_phnum):
            ph = self.phdr_struct()
            self.stream.readinto(ph)
            segment = Segment(ph)
            self.segments.append(segment)

    def _load_sections(self):
        shdr_size = self.elf_header.e_shentsize
        shoff = self.elf_header.e_shoff
        # load shstr section
        sh = self.shdr_struct()
        self.stream.seek(shoff + self.elf_header.e_shstrndx * shdr_size)
        self.stream.readinto(sh)
        # load shstr table
        self.stream.seek(sh.sh_offset)
        shstr_table = self.stream.read(sh.sh_size)
        # load sections
        for idx in range(self.elf_header.e_shnum):
            # load header
            sh = self.shdr_struct()
            self.stream.seek(shoff + idx * shdr_size)
            self.stream.readinto(sh)
            # load data
            self.stream.seek(sh.sh_offset)
            data = self.stream.read(sh.sh_size)
            # section name
            name_pos = sh.sh_name
            section_name = shstr_table[name_pos:shstr_table.find(b'\x00', name_pos)].decode()

            section = Section(sh, section_name, data)
            self.sections.append(section)

    def _load_symbols(self):
        symtab = self.get_section_by_name('.symtab')
        strtab = self.get_section_by_name('.strtab')
        # symbol table is not exist
        if symtab is None or strtab is None:
            return
        str_table = strtab.data
        stream = io.BytesIO(symtab.data)
        symhdr_size = symtab.entsize
        for idx in range(symtab.size // symhdr_size):
            symh = self.symhdr_struct()
            stream.seek(idx * symhdr_size)
            stream.readinto(symh)

            name_pos = symh.st_name
            symbol_name = str_table[name_pos:str_table.find(b'\x00', name_pos)].decode()
            symbol = Symbol(symh, symbol_name)
            self.symbols.append(symbol)

    def _load_dynamic(self):
        dynstr = self.get_section_by_name('.dynstr')
        dynsym = self.get_section_by_name('.dynsym')
        dynamic = self.get_section_by_name('.dynamic')
        # load dynamic link data
        dynstr_table = dynstr.data
        stream = io.BytesIO(dynamic.data)
        for idx in range(dynamic.size // dynamic.entsize):
            dh = self.dynhdr_struct()
            stream.readinto(dh)
            self.dynamics.append(Dynamic(dh))
        # load dynamic symbols
        stream = io.BytesIO(dynsym.data)
        for idx in range(dynsym.size // dynsym.entsize):
            symh = self.symhdr_struct()
            stream.readinto(symh)
            name_pos = dsymh.st_name
            sym_name = dynstr_table[name_pos:dynstr_table.find(b'\x00', name_pos)].decode()
            symbol = Symbol(symh, sym_name)
            self.symbols.append(symbol)

    def search(self, target: bytes):
        rslt = []
        for section in self.sections:
            pos = section.data.find(target)
            while pos != -1:
                rslt.append(pos + section.addr)
                pos = section.data.find(target, pos + 1)
        return iter(rslt)

    def bss(self):
        return self.get_section_by_name('.bss')

    @property
    def execstack(self):
        stack_seg = self.get_segment_by_type("PT_GNU_STACK")
        return stack_seg.is_executable

    @property
    def relro(self):
        if self.get_segment_by_type("PT_GNU_RELRO") is None:
            return NO_RELRO
        dyn_flags = self.get_dynamic_by_tag("DT_FLAGS")
        if dyn_flags is not None and dyn_flags.value & DF_BIND_NOW:
            return FULL_RELRO
        return PARTICAL_RELRO

    @property
    def pie(self):
        return self.elf_header.e_type == ELF_TYPE["ET_DYN"]

    @property
    def ssp(self):
        for symbol in self.symbols:
            if "__stack_chk_fail" in symbol.name:
                return True
        return False

    def get_section_by_name(self, section_name):
        for section in self.sections:
            if section.name == section_name:
                return section
        return None

    def get_symbol_by_name(self, symbol_name):
        for symbol in self.symbols:
            if symbol.name == symbol_name:
                return symbol
        return None

    def get_dynamic_by_tag(self, dyn_tag):
        for dynamic in self.dynamics:
            if dynamic.tag == DT_TAG[dyn_tag]:
                return dynamic
        return None

    def get_segment_by_type(self, segment_type):
        for segment in self.segments:
            if segment.type == PHDR_TYPE[segment_type]:
                return segment
        return None

    @property
    def arch(self):
        if self.machine in E_ARCHITECHTURES:
            return E_ARCHITECHTURES[self.machine]
        return "Unknown"
