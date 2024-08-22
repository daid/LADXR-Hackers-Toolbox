
class Patch:
    def __init__(self, start, size):
        self.start = start
        self.size = size
        self.type = 0

    @property
    def end(self):
        return self.start + self.size


def findRLESequences(data, min_size=12):
    rle = []
    prev = None
    length = 0
    for idx, b in enumerate(data):
        if b == prev:
            length += 1
        else:
            if length >= min_size:
                rle.append((idx - length, length))
            prev = b
            length = 1
    if length >= min_size:
        rle.append((len(data) - length, length))
    return rle


# Sloppy IPS patch generator
def makePatch(old, new, patch):
    old = open(old, "rb").read()
    new = open(new, "rb").read()
    start = 0
    patches = []
    while start < len(new):
        if old[start] != new[start]:
            end = start
            while end < len(new) and old[end] != new[end]:
                end += 1
            size = end - start
            patches.append(Patch(start, size))
            start = end
        else:
            start += 1

    # Merge patches that are close enough to gether to save record space
    idx = 0
    while idx < len(patches) - 1:
        if patches[idx].end >= patches[idx+1].start - 4:
            size = patches[idx+1].end - patches[idx].start
            patches[idx] = Patch(patches[idx].start, size)
            patches.pop(idx+1)
        else:
            idx += 1

    patch = open(patch, "wb")
    patch.write(b"PATCH")
    for p in patches:
        patch.write(bytes([p.start >> 16, (p.start >> 8) & 0xFF, p.start & 0xFF]))
        patch.write(bytes([p.size >> 8, p.size & 0xFF]))
        patch.write(new[p.start:p.end])
    patch.write(b"EOF")
