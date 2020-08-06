class Dynamic:
    def __init__(self, header):
        self.tag = header.d_tag
        self.union = header.d_un

    @property
    def value(self):
        return self.union.d_val

    @property
    def addr(self):
        return self.union.d_ptr
