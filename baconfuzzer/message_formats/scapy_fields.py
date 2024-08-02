from scapy.fields import FieldListField
from scapy.volatile import RandField, RandNum, VolatileValue


class RandList(RandField):
    def __init__(
        self, volatile_obj: VolatileValue, size=None, min_size=1, max_size=128
    ):
        """
        Create a random list
        :param volatile_obj: The VolatileValue object in the list
        :param size: Optional size of the list. If None, size is a RandNum in range
        [min_size, max_size]
        :param min_size: Minimum size of list
        :param max_size: Maximum size of list
        """
        self.volatile_obj = volatile_obj
        if size is None:
            size = RandNum(min_size, max_size)
        self.size = size

    def __iter__(self):
        # This is a fix to keep show() from breaking
        yield self

    def _fix(self):
        return [self.volatile_obj] * int(self.size)


class CustomFieldListField(FieldListField):
    @classmethod
    def from_fieldlistfield(cls, field: FieldListField, owner=None):
        custom_field = CustomFieldListField(
            field.name,
            field.default,
            field.field,
            field.length_from,
            field.count_from,
        )
        if owner:
            custom_field.register_owner(owner)
        return custom_field

    def randval(self):
        return RandList(self.field.randval())
