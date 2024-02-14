"""
Pure Python implementation of QuickLZ decompression. A port of the C# version
available at: http://www.quicklz.com/QuickLZ.cs

Compression is not implemented at this time.

As a derivative of QuickLZ, the same license applies. This code can be used 
for free under the GPL 1, 2 or 3 license.

QuickLZ is copyright (C) 2006-2011 Lasse Mikkel Reinhold (lar@quicklz.com)
This port written 2022 by David Cannings (david@edeca.net)
"""


class QuickLZ:
    """
    Wrapper class for all QuickLZ methods, implemented in a similar manner to the official
    Java and C# versions.
    """

    QLZ_STREAMING_BUFFER = 0

    QLZ_MEMORY_SAFE = 0
    QLZ_VERSION_MAJOR = 1
    QLZ_VERSION_MINOR = 5
    QLZ_VERSION_REVISION = 0

    # Decrease QLZ_POINTERS_3 to increase compression speed of level 3. Do not
    # edit any other constants!
    HASH_VALUES = 4096
    MINOFFSET = 2
    UNCONDITIONAL_MATCHLEN = 6
    UNCOMPRESSED_END = 4
    CWORD_LEN = 4
    DEFAULT_HEADERLEN = 9
    QLZ_POINTERS_1 = 1
    QLZ_POINTERS_3 = 16

    @staticmethod
    def headerLen(source: bytes) -> int:
        """
        Returns the QuickLZ header length from a compressed buffer.
        """
        return 9 if ((source[0] & 2) == 2) else 3

    @staticmethod
    def sizeCompressed(source: bytes) -> int:
        """
        Returns the size required for compressed data from QuickLZ headers.
        """
        if QuickLZ.headerLen(source) == 9:
            return int.from_bytes(source[1:5], byteorder="little")
        else:
            return int.from_bytes(source[1:2], byteorder="little")

    @staticmethod
    def sizeDecompressed(source: bytes) -> int:
        """
        Returns the size required for decompressed data from QuickLZ headers.
        """
        if QuickLZ.headerLen(source) == 9:
            return int.from_bytes(source[5:9], byteorder="little")
        else:
            return int.from_bytes(source[2:3], byteorder="little")

    def compress(self, source: bytes, level: int):
        """
        Compress a buffer. Not implemented at this time.
        """
        raise NotImplementedError("Compression is not supported by this port")

    def decompress(self, source: bytes) -> bytearray:
        """
        Decompress a buffer, returning the resulting data.
        """

        if len(source) <= 3:
            raise ValueError("Input is too short to contain any QuickLZ header")

        src = QuickLZ.headerLen(source)
        if len(source) < src:
            raise ValueError(
                "Input is too short to contain a valid header for this data"
            )

        if len(source) < QuickLZ.sizeCompressed(source):
            raise ValueError("Input is too short to contain all compressed data")

        cword_val = 1
        size = QuickLZ.sizeDecompressed(source)
        dst = 0
        destination = bytearray(size)
        hashtable = [0] * 4096
        hash_counter = bytearray(4096)
        last_matchstart = (
            size - QuickLZ.UNCONDITIONAL_MATCHLEN - QuickLZ.UNCOMPRESSED_END - 1
        )
        last_hashed = -1
        fetch = 0

        level = (source[0] >> 2) & 0x3
        if level != 1 and level != 3:
            raise ValueError("This version only supports level 1 and 3")

        if source[0] & 1 != 1:
            start = QuickLZ.headerLen(source)
            return source[start : start + size]

        while True:
            if cword_val == 1:
                cword_val = int.from_bytes(source[src : src + 4], byteorder="little")
                src += 4

                if dst <= last_matchstart:
                    if level == 1:
                        fetch = int.from_bytes(
                            source[src : src + 3], byteorder="little"
                        )
                    else:
                        fetch = int.from_bytes(
                            source[src : src + 4], byteorder="little"
                        )

            if (cword_val & 1) == 1:
                cword_val = cword_val >> 1

                if level == 1:
                    hash = (fetch >> 4) & 0xFFF
                    offset2 = hashtable[hash]

                    if (fetch & 0xF) != 0:
                        matchlen = (fetch & 0xF) + 2
                        src += 2
                    else:
                        matchlen = source[src + 2]
                        src += 3
                else:
                    if (fetch & 3) == 0:
                        offset = (fetch & 0xFF) >> 2
                        matchlen = 3
                        src += 1

                    elif (fetch & 2) == 0:
                        offset = (fetch & 0xFFFF) >> 2
                        matchlen = 3
                        src += 2

                    elif (fetch & 1) == 0:
                        offset = (fetch & 0xFFFF) >> 6
                        matchlen = ((fetch >> 2) & 15) + 3
                        src += 2

                    elif (fetch & 127) != 3:
                        offset = (fetch >> 7) & 0x1FFFF
                        matchlen = ((fetch >> 2) & 0x1F) + 2
                        src += 3

                    else:
                        offset = fetch >> 15
                        matchlen = ((fetch >> 7) & 255) + 3
                        src += 4

                    offset2 = (dst - offset) & 0xFFFFFFFF

                destination[dst + 0] = destination[offset2 + 0]
                destination[dst + 1] = destination[offset2 + 1]
                destination[dst + 2] = destination[offset2 + 2]

                for i in range(3, matchlen):
                    destination[dst + i] = destination[offset2 + i]

                dst += matchlen

                if level == 1:
                    fetch = int.from_bytes(
                        destination[last_hashed + 1 : last_hashed + 4],
                        byteorder="little",
                    )

                    while last_hashed < dst - matchlen:
                        last_hashed += 1
                        hash = ((fetch >> 12) ^ fetch) & (QuickLZ.HASH_VALUES - 1)

                        hashtable[hash] = last_hashed
                        hash_counter[hash] = 1
                        fetch = fetch >> 8 & 0xFFFF | destination[last_hashed + 3] << 16

                    fetch = int.from_bytes(source[src : src + 3], byteorder="little")
                else:
                    fetch = int.from_bytes(source[src : src + 4], byteorder="little")

                last_hashed = dst - 1

            else:
                if dst <= last_matchstart:
                    destination[dst] = source[src]
                    dst += 1
                    src += 1
                    cword_val = cword_val >> 1

                    if level == 1:
                        while last_hashed < dst - 3:
                            last_hashed += 1
                            fetch2 = int.from_bytes(
                                destination[last_hashed : last_hashed + 3],
                                byteorder="little",
                            )
                            hash = ((fetch2 >> 12) ^ fetch2) & (QuickLZ.HASH_VALUES - 1)
                            hashtable[hash] = last_hashed
                            hash_counter[hash] = 1

                        fetch = fetch >> 8 & 0xFFFF | source[src + 2] << 16
                    else:
                        fetch = (
                            fetch >> 8 & 0xFFFF
                            | source[src + 2] << 16
                            | source[src + 3] << 24
                        )

                else:
                    while dst <= size - 1:
                        if cword_val == 1:
                            src += QuickLZ.CWORD_LEN
                            cword_val = 0x80000000

                        destination[dst] = source[src]
                        dst += 1
                        src += 1
                        cword_val = cword_val >> 1

                    return destination
