class Symbol:
    def __init__(self, header, symbol_name):
        self.name = symbol_name
        self.header = header

    def __getattr__(self, name):
        return getattr(self.header, f"st_{name}")
