import zlib


def inflate(chunks):
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    for chunk in chunks:
        data = d.decompress(chunk)
        if data:
            yield data
