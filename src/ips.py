

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
            patches.append((start, size))
            start = end
        else:
            start += 1

    # Merge patches that are close enough to gether to save record space
    idx = 0
    while idx < len(patches) - 1:
        if patches[idx][0] + patches[idx][1] >= patches[idx+1][0] - 4 and False:
            size = (patches[idx+1][0] + patches[idx+1][1]) - patches[idx][0]
            patches[idx] = (patches[idx][0], size)
            patches.pop(idx+1)
        else:
            idx += 1

    patch = open(patch, "wb")
    patch.write(b"PATCH")
    for start, size in patches:
        patch.write(bytes([start >> 16, (start >> 8) & 0xFF, start & 0xFF]))
        patch.write(bytes([size >> 8, size & 0xFF]))
        patch.write(new[start:start+size])
    patch.write(b"EOF")
