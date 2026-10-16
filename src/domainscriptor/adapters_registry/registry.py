from typing import Dict, List, Type

import typer

from domainscriptor.adapters_registry.abstract_adapter import Adapter


class Adapter_Registry:
    def __init__(self):
        self._adapters: Dict[str, Type[Adapter]] = {}
        # Every adapter ever registered, with availability info (incl. disabled ones)
        self._all: Dict[str, dict] = {}

    def register(self, adapter_cls: type) -> type:
        name = adapter_cls.name.lower()
        available = True
        error = ""
        try:
            adapter_cls.can_run()
            self._adapters[name] = adapter_cls
        except RuntimeError as e:
            available = False
            error = str(e)
            typer.secho(
                f"⚠  {adapter_cls.executable} nicht verfügbar – Adapter deaktiviert: {e}",
                fg=typer.colors.YELLOW,
            )
        self._all[name] = {"cls": adapter_cls, "available": available, "error": error}
        return adapter_cls

    def create(self, name: str, **config):
        try:
            klass = self._adapters[name.lower()]
        except KeyError:
            raise ValueError(f"Unbekannter Adapter: {name}")
        return klass(**config)

    def list_names(self):
        return sorted(self._adapters.keys())

    def list_all(self) -> List[dict]:
        """All registered adapters (available and disabled), sorted by name."""
        return [self._all[name] for name in sorted(self._all.keys())]
