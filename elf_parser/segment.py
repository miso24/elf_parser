from .constants import *

class Segment:
    def __init__(self, header):
        self.header = header

    def __getattr__(self, name):
        return getattr(self.header, f"p_{name}")

    @property
    def is_readable(self):
        return self.flags & PR_R != 0

    @property
    def is_writable(self):
        return self.flags & PR_W != 0

    @property
    def is_executable(self):
        return self.flags & PR_X != 0
