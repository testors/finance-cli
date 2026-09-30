"""Registered web jobs. Only these names are accepted by POST /jobs."""

_registry = None


def load():
    global _registry
    if _registry is None:
        from . import giro, hometax, hana, hana_queries, certificates
        items = {}
        for module in (giro, hometax, hana, hana_queries, certificates):
            for adapter in module.ADAPTERS:
                if adapter.name in items:
                    raise RuntimeError('duplicate_adapter')
                items[adapter.name] = adapter
        _registry = items
    return _registry


def get(name):
    return load().get(name) if isinstance(name, str) else None


def names():
    return sorted(load())
