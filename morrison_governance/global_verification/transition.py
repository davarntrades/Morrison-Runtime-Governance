"""Transition-model exceptions used for fail-closed verification."""


class TransitionModelError(RuntimeError):
    """Raised when deterministic environment semantics cannot be applied."""


class SerializationError(RuntimeError):
    """Raised when model or evidence values cannot be serialized."""

