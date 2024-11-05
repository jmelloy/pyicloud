"""Util"""

from .bplist import BPListReader, BPListWriter
from .photos import parse_fields
from .password import (
    get_password,
    get_password_from_keyring,
    password_exists_in_keyring,
    store_password_in_keyring,
    delete_password_in_keyring,
)


def underscore_to_camelcase(word, initial_capital=False):
    """Transform a word to camelCase."""
    words = [x.capitalize() or "_" for x in word.split("_")]
    if not initial_capital:
        words[0] = words[0].lower()

    return "".join(words)
