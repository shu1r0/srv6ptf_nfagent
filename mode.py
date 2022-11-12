from enum import IntEnum, auto


class CollectMode(IntEnum):

    PACKET = auto()
    PACKET_ID = auto()


def str2mode(mode: str) -> CollectMode:
    for m in CollectMode:
        if mode.lower() == m.name.lower():
            return m
