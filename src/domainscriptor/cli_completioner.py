import shlex
from prompt_toolkit.completion import Completer, Completion


class RuncommandCompleter(Completer):
    def __init__(self, adapter_params: dict[str, dict[str, list[str] | None]]):
        self.adapter_params = adapter_params

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor

        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()

        if not parts:
            return

        if parts[0] != "runcommand":
            return

        # runcommand <adapter>
        if len(parts) == 1 and not text.endswith(" "):
            prefix = parts[0]
            if "runcommand".startswith(prefix):
                yield Completion("runcommand", start_position=-len(prefix))
            return

        # Adapter vervollständigen
        if len(parts) == 1 and text.endswith(" "):
            for adapter in self.adapter_params:
                yield Completion(adapter, start_position=0)
            return

        if len(parts) == 2 and not text.endswith(" "):
            current = parts[-1]
            for adapter in self.adapter_params:
                if adapter.startswith(current):
                    yield Completion(adapter, start_position=-len(current))
            return

        adapter = parts[1]
        if adapter not in self.adapter_params:
            return

        param_defs = self.adapter_params[adapter]

        ends_with_space = text.endswith(" ")
        current = "" if ends_with_space else parts[-1]

        # Bereits verwendete Parameter sammeln
        used_params = set()
        for token in parts[2:]:
            if "=" in token:
                key, _ = token.split("=", 1)
                used_params.add(key)

        # Neues Argument anfangen
        if ends_with_space:
            for param in param_defs:
                if param not in used_params:
                    yield Completion(f"{param}=", start_position=0)
            return

        # Aktuelles Token ist key=value
        if "=" in current:
            key, value_prefix = current.split("=", 1)

            if key not in param_defs:
                return

            possible_values = param_defs[key]
            if possible_values:
                for value in possible_values:
                    if value.startswith(value_prefix):
                        yield Completion(value, start_position=-len(value_prefix))
            return

        # Parameternamen vervollständigen
        for param in param_defs:
            if param not in used_params and param.startswith(current):
                yield Completion(f"{param}=", start_position=-len(current))

class StopProcessCompleter(Completer):
    def __init__(self, get_process_names):
        self.get_process_names = get_process_names

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor

        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()

        if not parts or parts[0] != "stopprocess":
            return

        process_names = list(self.get_process_names())

        if len(parts) == 1:
            if text.endswith(" "):
                for name in process_names:
                    yield Completion(name, start_position=0)
            else:
                current = parts[0]
                if "stopprocess".startswith(current):
                    yield Completion("stopprocess", start_position=-len(current))
            return

        if len(parts) == 2:
            current = parts[1]
            for name in process_names:
                if name.startswith(current):
                    yield Completion(name, start_position=-len(current))



class MainCompleter(Completer):
    def __init__(self, base_completer, runcommand_completer,stopprocess_completer):
        self.base_completer = base_completer
        self.runcommand_completer = runcommand_completer
        self.stopprocess_completer = stopprocess_completer

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()

        if text.startswith("runcommand"):
            yield from self.runcommand_completer.get_completions(document, complete_event)
        elif text.startswith("stopprocess"):
            yield from self.stopprocess_completer.get_completions(document, complete_event)
        else:
            yield from self.base_completer.get_completions(document, complete_event)