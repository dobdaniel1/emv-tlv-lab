import json
from functools import cache
from importlib.resources import files


@cache
def data() -> dict:
    return json.loads(files(__package__).joinpath("emv.json").read_text())


def tag_name(tag: str) -> str:
    entry = data()["tags"].get(tag.upper())
    return entry["name"] if entry else "Unknown tag"


def tag_info(tag: str) -> dict:
    return data()["tags"].get(tag.upper(), {})
