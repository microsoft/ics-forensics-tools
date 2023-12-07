import inspect
from typing import Generator, Type, TypeVar


T = TypeVar('T')


def class_subclasses(cls: Type[T]) -> Generator[Type[T], None, None]:
    """Returns all the (recursive) subclasses of a given class."""
    if not inspect.isclass(cls):
        raise TypeError(f"class_subclasses parameter not a valid class: {cls}")
    for clazz in cls.__subclasses__():
        if not hasattr(clazz, 'hidden') or not clazz.hidden:  # type: ignore
            yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value

def list_subclasses(interface, folder_path):
    subclasses = {}
    for cls in class_subclasses(interface):
        cls_name = cls.__module__ + "." + cls.__name__
        folder_name = cls.__module__.split('.')[2]
        if cls_name.startswith(folder_path):
            cls_name = cls_name.split('.')[-1]
            subclasses[f"{folder_name}.{cls_name}"] = cls
    return subclasses