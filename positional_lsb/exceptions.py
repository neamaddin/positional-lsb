class LengthError(Exception):
    def __init__(self, length: int):
        message = f"Length must be {length} character"
        super().__init__(message)


class TooBigFileError(Exception):
    def __init__(self, max_file_size: int):
        message = f"File is too big. " \
                  f"The maximum file size is {max_file_size} bytes"
        super().__init__(message)


class NonSocketObjectError(Exception):
    """Argument must be an object of the built-in socket class"""
