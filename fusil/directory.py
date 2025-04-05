import grp
import pwd
from os import chmod, chown, mkdir, scandir, umask
from os.path import basename
from os.path import exists as path_exists
from os.path import join as path_join
from shutil import rmtree
from sys import getfilesystemencoding

from fusil.six import text_type


class Directory:
    def __init__(self, directory):
        self.directory = directory
        # Filenames generated by uniqueFilename() method
        self.files = set()

    def ignore(self, filename):
        try:
            self.files.remove(filename)
        except KeyError:
            pass

    def mkdir(self):
        old_umask = umask(0)
        mkdir(self.directory, 0o777)
        try:
            uid = pwd.getpwnam("fusil").pw_uid
            gid = grp.getgrnam("fusil").gr_gid
            chown(self.directory, uid, gid)
        except Exception as e:
            print(e)
        umask(old_umask)

    def isEmpty(self, ignore_generated=False):
        try:
            for entry in scandir(self.directory):
                if entry.name in ('.', '..'):
                    continue
                if entry.name in self.files and ignore_generated:
                    continue
                return False
            return True
        except OSError as e:
            print(e)
            return False


    def rmtree(self):
        filename = self.directory
        if isinstance(filename, text_type):
            # Convert to byte strings because rmtree() doesn't support mixing
            # byte and unicode strings
            charset = getfilesystemencoding()
            filename = filename.encode(charset)
        rmtree(filename, onerror=self.rmtree_error)

    def rmtree_error(self, operation, argument, stack):
        # Try to change file permission (allow write) and retry
        try:
            chmod(argument, 0o777)
        except OSError:
            pass
        operation(argument)

    def uniqueFilename(self, name,
    count=None, count_format="%d", save=True):
        # Test with no count suffix
        name = basename(name)
        if not name:
            raise ValueError("Empty filename")
        if count is None and not self._exists(name):
            if save:
                self.files.add(name)
            return path_join(self.directory, name)

        # Create filename pattern: "archive.tar.gz" => "archive-%04u.tar.gz"
        name_pattern = name.split(".", 1)
        if count is None:
            count = 2
        count_format = "-" + count_format
        if 1 < len(name_pattern):
            name_pattern = name_pattern[0] + count_format + '.' + name_pattern[1]
        else:
            name_pattern = name_pattern[0] + count_format

        # Try names and increment count at each step
        while True:
            name = name_pattern % count
            if not self._exists(name):
                if save:
                    self.files.add(name)
                return path_join(self.directory, name)
            count += 1

    def _exists(self, name):
        if name in self.files:
            return True
        filename = path_join(self.directory, name)
        return path_exists(filename)

