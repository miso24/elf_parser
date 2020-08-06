from elf_parser import ELF
from elf_parser import NO_RELRO, PARTICAL_RELRO, FULL_RELRO
import os
import sys

def red(text):
    return f"\x1b[31m{text}\x1b[0m"

def green(text):
    return f"\x1b[32m{text}\x1b[0m"

def orange(text):
    return f"\x1b[33m{text}\x1b[0m"

def relro(elf):
    if elf.relro == NO_RELRO:
        return red("No RELRO")
    elif elf.relro == PARTICAL_RELRO:
        return orange("Partical RELRO")
    else:
        return green("Full RELRO")

def ssp(elf):
    if elf.ssp:
        return green("Canary found")
    else:
        return red("Canary not found")

def nxbit(elf):
    if elf.execstack:
        return red("NX disabled")
    else:
        return green("NX enabled")

def pie(elf):
    if elf.pie:
        return green("PIE enabled")
    else:
        return red("PIE disabled")

def main(filename):
    elf = ELF(filename)
    print(f"[*] {os.path.abspath(filename)}")
    outputs = {
        "Arch": '-'.join([elf.arch, str(elf.bits), elf.endian]),
        "RELRO": relro(elf),
        "Stack": ssp(elf),
        "NX": nxbit(elf),
        "PIE": pie(elf)
    }
    for key, value in outputs.items():
        print(" " * 4 + f"{key}:".ljust(10) + value)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python checksec.py <ELF>")
        exit()
    main(sys.argv[1])
