from typing import List, Optional


class ConfigItem:
    def __init__(self, name: str, help_text=None, group=None):
        self.name = name
        self.help_text = help_text
        self.group = group

    def to_html(self) -> str:
        raise NotImplementedError()

    def from_form(self, form):
        raise NotImplementedError()


class DropDown(ConfigItem):
    """
    Configuration option that allows a single selection from a dropdown menu
    """

    def __init__(self, name: str, options: List[str], help_text=None, group=None):
        super().__init__(name, help_text, group)
        self.options = options
        self.options.sort()

    def to_html(self) -> str:
        payload = ""
        payload += BaconConfig.util_label(self.name, self.help_text)
        payload += f'<select name="{self.name}" class="form-select" id="{self.name}">'
        for option in self.options:
            payload += (
                f'<option name="{option}" data-group="{self.group}">{option}</option>'
            )
        payload += f"</select></br>"
        return payload

    def from_form(self, form) -> List[str]:
        return form.get(self.name, default=None)


class MultiSelect(ConfigItem):
    """
    Configuration option that allows multiple pre-defined options to be selected
    """

    def __init__(self, name: str, options: List[str], help_text=None, group=None):
        super().__init__(name, help_text, group)
        self.options = options

    def to_html(self) -> str:
        payload = ""
        payload += BaconConfig.util_label(self.name, self.help_text)
        for option in self.options:
            payload += f"""
                <input type="checkbox" name="{option}" id="{option}" data-group="{self.group}" class="form-check-input">
                <label for="{option}" class="form-check-label">{option}</label><br>
                """
        return payload

    def from_form(self, form) -> List[str]:
        selected_options = []
        for option in self.options:
            msg_check_value = form.get(option)
            if msg_check_value == "on":
                selected_options.append(option)
        return selected_options


class SingleSelect(ConfigItem):
    """
    Configuration option that allows a single pre-defined option to be selected
    """

    def __init__(self, name: str, options: List[str], help_text=None, group=None):
        super().__init__(name, help_text, group)
        self.options = options

    def to_html(self) -> str:
        payload = ""
        payload += BaconConfig.util_label(self.name, self.help_text)
        for option in self.options:
            payload += f"""
                <input type="radio" name="{self.name}" id="{option}" value="{option}" data-group="{self.group}" class="form-check-input">
                <label for="{option}" class="form-check-label">{option}</label><br>
                """
        return payload

    def from_form(self, form) -> str:
        return form.get(self.name)


class TextValue(ConfigItem):
    """
    Configuration option that accepts a string
    """

    def __init__(
        self, name: str, default=None, required=True, help_text=None, group=None
    ):
        super().__init__(name, help_text, group)
        self.default = default
        self.required = required

    def to_html(self) -> str:
        value = "" if self.default is None else f'value="{self.default}"'
        required = "required" if self.required else ""
        return f"""
            {BaconConfig.util_label(self.name, self.help_text)}
            <input type="text" name="{self.name}" id="{self.name}" {value} {required}" data-group="{self.group}" class="form-control">
        """

    def from_form(self, form) -> Optional[str]:
        value = form.get(self.name)
        if value == "":
            return None
        return value


class IntValue(ConfigItem):
    """
    Configuration option that accepts an integer
    """

    def __init__(
        self, name: str, default=None, required=True, help_text=None, group=None
    ):
        super().__init__(name, help_text, group)
        self.default = default
        self.required = required

    def to_html(self) -> str:
        value = "" if self.default is None else f'value="{self.default}"'
        required = "required" if self.required else ""
        return f"""
            {BaconConfig.util_label(self.name, self.help_text)}
            <input type="number" name="{self.name}" {value} {required} data-group="{self.group}" class="form-control">
        """

    def from_form(self, form) -> Optional[int]:
        value = form.get(self.name)
        if value == "":
            return None
        return int(value)


class FloatValue(ConfigItem):
    """
    Configuration option that accepts a float
    """

    def __init__(
        self, name: str, default=None, required=True, help_text=None, group=None
    ):
        super().__init__(name, help_text, group)
        self.default = default
        self.required = required

    def to_html(self) -> str:
        value = "" if self.default is None else f'value="{self.default}"'
        required = "required" if self.required else ""
        return f"""
            {BaconConfig.util_label(self.name, self.help_text)}
            <input type="number" name="{self.name}" step="0.01" {value} {required} data-group="{self.group}" class="form-control">
        """

    def from_form(self, form) -> Optional[float]:
        value = form.get(self.name)
        if value == "":
            return None
        return float(value)


class BaconConfig:
    def __init__(self, items: List[ConfigItem]):
        self.item_names = [item.name for item in items]
        if len(self.item_names) != len(set(self.item_names)):
            raise ValueError("Items cannot have the same name")
        self.items = items

    def to_html(self) -> str:
        return "<br>".join([item.to_html() for item in self.items])

    def parse_form(self, form) -> dict:
        return {item.name: item.from_form(form) for item in self.items}

    @staticmethod
    def util_label(name, help_text):
        if help_text:
            return f'<label for="{name}"><abbr title="{help_text}" class="initialism">{name}</abbr></label>'
        else:
            return f'<label for="{name}">{name}</label>'
