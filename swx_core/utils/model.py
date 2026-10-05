"""
Model Loader
------------
This module dynamically loads (and reloads) all SQLAlchemy models
from both app models directory and swx_core.models to ensure
they are registered with `Base.metadata`.

Functions:
- `load_all_models()`: Dynamically loads all models and registers them with `Base.metadata`.
"""
import importlib
import pkgutil
import sys

from sqlmodel import SQLModel

from swx_core.config.discovery import discovery
from swx_core.middleware.logging_middleware import logger


def _attach_model_classes(parent_module, submodule) -> int:
    """Attach only SQLModel subclasses from a submodule to its parent package.

    Attaching every public attribute pollutes the package namespace with
    SQLAlchemy internals (``func``, column types, ``datetime`` re-exports)
    and risks name collisions between submodules.
    """
    attached = 0
    for attr in dir(submodule):
        if attr.startswith("_"):
            continue
        value = getattr(submodule, attr)
        if isinstance(value, type) and issubclass(value, SQLModel) and value is not SQLModel:
            setattr(parent_module, attr, value)
            attached += 1
    return attached


def load_all_models() -> SQLModel:
    """
    Dynamically loads all SQLAlchemy models from both app models and
    swx_core.models so that they register with `Base.metadata`.

    Returns:
        Base: The SQLAlchemy Base class with registered models.
    """
    importlib.invalidate_caches()

    modules_to_scan = ["swx_core.models"]

    # Add app models if app exists and has models directory
    if discovery.app_exists() and discovery.has_models():
        modules_to_scan.append(discovery.app_models_module)

    for module_name in modules_to_scan:
        try:
            if module_name == discovery.app_models_module and not discovery.app_models_path.exists():
                logger.warning("App models directory not found at %s. Skipping...", discovery.app_models_path)
                continue

            parent_module = sys.modules.get(module_name) or importlib.import_module(module_name)
            logger.debug("Imported parent module: %s", module_name)
        except ModuleNotFoundError:
            logger.warning("Module %s not found. Skipping...", module_name)
            continue

        if not hasattr(parent_module, "__path__"):
            continue

        for finder, name, is_pkg in pkgutil.walk_packages(
                parent_module.__path__, parent_module.__name__ + "."
        ):
            if is_pkg:
                continue

            submodule = sys.modules.get(name) or importlib.import_module(name)
            attached = _attach_model_classes(parent_module, submodule)
            logger.debug("Loaded %s (%d model classes attached)", name, attached)

    logger.debug("Models registered in metadata: %s", list(SQLModel.metadata.tables.keys()))
    return SQLModel