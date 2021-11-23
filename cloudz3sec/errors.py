
from typing import Optional


class BaseCloudz3SecError(Exception):
    def __init__(self, message: Optional[str]) -> None:
        self.message = message


class InvalidCharacterError(BaseCloudz3SecError):
    """
    Raised when a character set of field name includes a reserved character.
    """
    pass


class InvalidValueError(BaseCloudz3SecError):
    """
    Raised when a value passed to an Re type is not allowed.
    """
    pass


class InvalidStringTupleStructure(BaseCloudz3SecError):
    """
    Raised when a StringTupleRe contstructor is passed an improperly formatted fields argument. 
    """
    pass


class MissingStringTupleData(BaseCloudz3SecError):
    """
    Raised when a StringTuple type does not have required data set.
    """
    pass

class InvalidStringTupleData(BaseCloudz3SecError):
    """
    Raised when a StringTupleRe set_data method is passed an improperly formatted key-word argument. 
    """
    pass


class MissingStringEnumData(BaseCloudz3SecError):
    """
    Raised when a StringEnum type does not have required data set.
    """
    pass