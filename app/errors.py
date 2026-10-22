class ResourceNotFound(LookupError):
    """A requested record does not exist in the prepared dataset."""


class InvalidSearchInput(ValueError):
    """Search arguments are invalid before retrieval begins."""
