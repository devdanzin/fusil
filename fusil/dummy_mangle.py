from fusil.mangle import MangleAgent

class DummyMangle(MangleAgent):
    def mangleData(self, data, file_index):
        return data

