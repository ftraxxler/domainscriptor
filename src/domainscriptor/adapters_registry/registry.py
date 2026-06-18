from typing import Dict, List, Type

import typer

from domainscriptor.adapters_registry.abstract_adapter import Adapter


class Adapter_Registry:
    def __init__(self):
        self._adapters: Dict[str, Type[Adapter]] = {}

    def register(self, adapter_cls: type) -> type:
        name = adapter_cls.name.lower()
        try:
            adapter_cls.can_run()
            self._adapters[name] = adapter_cls
        except RuntimeError as e:
            typer.secho(f"⚠  {adapter_cls.executable} nicht verfügbar – Adapter deaktiviert: {e}", fg=typer.colors.YELLOW)
        return adapter_cls

    def create(self, name: str, **config):
        try:
            klass = self._adapters[name.lower()]
        except KeyError:
            raise ValueError(f"Unbekannter Adapter: {name}")
        return klass(**config)

    def list_names(self):
        return sorted(self._adapters.keys())
