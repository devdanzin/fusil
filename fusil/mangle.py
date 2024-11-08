from array import array
from random import choice, randint

from fusil.mangle_agent import MangleAgent
from fusil.mangle_op import MAX_INCR, SPECIAL_VALUES
from fusil.six.moves import range as xrange
from fusil.tools import minmax


class MangleConfig:
    def __init__(self, min_op=1, max_op=100, operations=None):
        """
        Number of operations: min_op..max_op
        Operations: list of function names (eg. ["replace", "bit"])
        """
        self.min_op = min_op
        self.max_op = max_op
        self.max_insert_bytes = 4
        self.max_delete_bytes = 4
        self.max_incr = MAX_INCR
        self.first_offset = 0
        self.change_size = False
        if operations:
            self.operations = operations
        else:
            self.operations = None

class Mangle:
    def __init__(self, config, data):
        self.config = config
        self.data = data

    def generateByte(self):
        return randint(0, 255)

    def offset(self, last=1):
        first = self.config.first_offset
        last = len(self.data)-last
        if last < first:
            raise ValueError(
                "Invalid first_offset value (first=%s > last=%s)"
                % (first, last))
        return randint(first, last)

    def mangle_replace(self):
        self.data[self.offset()] = self.generateByte()

    def mangle_bit(self):
        offset = self.offset()
        bit = randint(0, 7)
        if randint(0, 1) == 1:
            value = self.data[offset] | (1 << bit)
        else:
            value = self.data[offset] & (~(1 << bit) & 0xFF)
        self.data[offset] = value

    def mangle_special_value(self):
        text = choice(SPECIAL_VALUES)
        offset = self.offset(len(text))
        self.data[offset:offset+len(text)] = array("B", text)

    def mangle_increment(self):
        incr = randint(1, self.config.max_incr)
        if randint(0, 1) == 1:
            incr = -incr
        offset = self.offset()
        self.data[offset] = minmax(0, self.data[offset] + incr, 255)

    def mangle_insert_bytes(self):
        offset = self.offset()
        count = randint(1, self.config.max_insert_bytes)
        for index in xrange(count):
            self.data.insert(offset, self.generateByte())

    def mangle_delete_bytes(self):
        offset = self.offset(2)
        count = randint(1, self.config.max_delete_bytes)
        count = min(count, len(self.data)-offset)
        del self.data[offset:offset+count]

    def run(self):
        """
        Mangle data and return number of applied operations
        """

        operation_names = self.config.operations
        if not operation_names:
            operation_names = ["replace", "bit", "special_value"]
            if self.config.change_size:
                operation_names.extend(("insert_bytes", "delete_bytes"))

        operations = []
        for name in operation_names:
            operation = getattr(self, "mangle_" + name)
            operations.append(operation)

        if self.config.max_op <= 0:
            return 0
        count = randint(self.config.min_op, self.config.max_op)
        for index in xrange(count):
            operation = choice(operations)
            operation()
        return count

class MangleFile(MangleAgent):
    """
    Inject errors in a valid file ("mutate" or "mangle" a file) to
    create new files. Use the config attribute (a MangleConfig
    instance) to configure the mutation parameters.
    """
    def __init__(self, project, source, nb_file=1):
        MangleAgent.__init__(self, project, source, nb_file)
        self.config = MangleConfig()

    def mangleData(self, data, file_index):
        # Mangle bytes
        count = Mangle(self.config, data).run()
        self.info("Mangle operation: %s" % count)
        return data

