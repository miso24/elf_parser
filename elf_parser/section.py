class Section:
    def __init__(self, header, section_name, data):
        self.name = section_name
        self.data = data
        self.header = header

    def __getattr__(self, name):
        return getattr(self.header, f"sh_{name}")
