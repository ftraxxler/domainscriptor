from typing import Dict, List, Type

from src.domainscriptor.adapters_registry.abstract_adapter import Adapter, AdapterError


class Adapter_Registry:
    def __init__(self):
        self._adapters: Dict[str, Type[Adapter]] = {}

    def register(self, adapter_cls: type) -> type:
        name = adapter_cls.name.lower()
        self._adapters[name] = adapter_cls
        adapter_cls.can_run()
        return adapter_cls

    def create(self, name: str, **config):
        try:
            klass = self._adapters[name.lower()]
        except KeyError:
            raise ValueError(f"Unbekannter Adapter: {name}")
        return klass(**config)

    def list_names(self):
        return sorted(self._adapters.keys())
