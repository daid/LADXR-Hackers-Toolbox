from items import *

_NAMES = {
    SWORD: "Sword",
    BOMB: "Bombs",
    POWER_BRACELET: "Power Bracelet",
    SHIELD: "Shield",
    BOW: "Bow",
    HOOKSHOT: "Hookshot",
    MAGIC_ROD: "Magic Rod",
    PEGASUS_BOOTS: "Pegasus Boots",
    OCARINA: "Ocarina",
    FEATHER: "Roc's Feather",
    SHOVEL: "Shovel",
    MAGIC_POWDER: "Magic Powder",
    BOOMERANG: "Boomerang",

    FLIPPERS: "Flippers",
    SLIME_KEY: "Slime key",
    TAIL_KEY: "Tail key",
    ANGLER_KEY: "Angler key",
    FACE_KEY: "Face key",
    BIRD_KEY: "Bird key",
    GOLD_LEAF: "Golden leaf",

    "RUPEE": "Rupee",
    "RUPEES": "Rupees",
    RUPEES_50: "50 Rupees",
    RUPEES_20: "20 Rupees",
    RUPEES_100: "100 Rupees",
    RUPEES_200: "200 Rupees",
    RUPEES_500: "500 Rupees",
    SEASHELL: "Secret Seashell",

    KEY: "Small Key",
    KEY1: "Key for Tail Cave",
    KEY2: "Key for Bottle Grotto",
    KEY3: "Key for Key Cavern",
    KEY4: "Key for Angler's Tunnel",
    KEY5: "Key for Catfish's Maw",
    KEY6: "Key for Face Shrine",
    KEY7: "Key for Eagle's Tower",
    KEY8: "Key for Turtle Rock",
    KEY9: "Key for Color Dungeon",

    MAP: "Dungeon Map",
    MAP1: "Map for Tail Cave",
    MAP2: "Map for Bottle Grotto",
    MAP3: "Map for Key Cavern",
    MAP4: "Map for Angler's Tunnel",
    MAP5: "Map for Catfish's Maw",
    MAP6: "Map for Face Shrine",
    MAP7: "Map for Eagle's Tower",
    MAP8: "Map for Turtle Rock",
    MAP9: "Map for Color Dungeon",

    COMPASS: "Dungeon Compass",
    COMPASS1: "Compass for Tail Cave",
    COMPASS2: "Compass for Bottle Grotto",
    COMPASS3: "Compass for Compass Cavern",
    COMPASS4: "Compass for Angler's Tunnel",
    COMPASS5: "Compass for Catfish's Maw",
    COMPASS6: "Compass for Face Shrine",
    COMPASS7: "Compass for Eagle's Tower",
    COMPASS8: "Compass for Turtle Rock",
    COMPASS9: "Compass for Color Dungeon",

    STONE_BEAK: "Stone Beak",
    STONE_BEAK1: "Stone Beak for Tail Cave",
    STONE_BEAK2: "Stone Beak for Bottle Grotto",
    STONE_BEAK3: "Stone Beak for Key Cavern",
    STONE_BEAK4: "Stone Beak for Angler's Tunnel",
    STONE_BEAK5: "Stone Beak for Catfish's Maw",
    STONE_BEAK6: "Stone Beak for Face Shrine",
    STONE_BEAK7: "Stone Beak for Eagle's Tower",
    STONE_BEAK8: "Stone Beak for Turtle Rock",
    STONE_BEAK9: "Stone Beak for Color Dungeon",

    NIGHTMARE_KEY: "Nightmare Key",
    NIGHTMARE_KEY1: "Nightmare Key for Tail Cave",
    NIGHTMARE_KEY2: "Nightmare Key for Bottle Grotto",
    NIGHTMARE_KEY3: "Nightmare Key for Key Cavern",
    NIGHTMARE_KEY4: "Nightmare Key for Angler's Tunnel",
    NIGHTMARE_KEY5: "Nightmare Key for Catfish's Maw",
    NIGHTMARE_KEY6: "Nightmare Key for Face Shrine",
    NIGHTMARE_KEY7: "Nightmare Key for Eagle's Tower",
    NIGHTMARE_KEY8: "Nightmare Key for Turtle Rock",
    NIGHTMARE_KEY9: "Nightmare Key for Color Dungeon",

    HEART_PIECE: "Piece of Heart",
    BOWWOW: "Bowwow",
    ARROWS_10: "10 Arrows",
    SINGLE_ARROW: "Single Arrow",
    MEDICINE: "Medicine",

    MAX_POWDER_UPGRADE: "Magic Powder upgrade",
    MAX_BOMBS_UPGRADE: "Bombs upgrade",
    MAX_ARROWS_UPGRADE: "Arrows upgrade",

    RED_TUNIC: "Red Tunic",
    BLUE_TUNIC: "Blue Tunic",

    HEART_CONTAINER: "Heart Container",
    BAD_HEART_CONTAINER: "Anti-Heart Container",

    TOADSTOOL: "Toadstool",

    SONG1: "Ballad of the Wind Fish",
    SONG2: "Manbo's Mambo",
    SONG3: "Frog's Song of Soul",

    INSTRUMENT1: "Full Moon Cello",
    INSTRUMENT2: "Conch Horn",
    INSTRUMENT3: "Sea Lily's Bell",
    INSTRUMENT4: "Surf Harp",
    INSTRUMENT5: "Wind Marimba",
    INSTRUMENT6: "Coral Triangle",
    INSTRUMENT7: "Organ of Evening Calm",
    INSTRUMENT8: "Thunder Drum",
}

TEXT_SYMBOLS = {
    b"<flower>": 0xd9,
    b"<footprint>": 0xda,
    b"<skull>": 0xdc,
    b"<link>": 0xdd,
    b"<marin>": 0xde,
    b"<tarin>": 0xdf,
    b"<yoshi>": 0xe0,
    b"<ribbon>": 0xe1,
    b"<dogfood>": 0xe2,
    b"<bananas>": 0xe3,
    b"<stick>": 0xe4,
    b"<honeycomb>": 0xe5,
    b"<pineapple>": 0xe6,
    b"<flower2>": 0xe7,
    b"<broom>": 0xe8,
    b"<fishhook>": 0xe9,
    b"<bra>": 0xea,
    b"<scale>": 0xeb,
    b"<glass>": 0xec,
    b"<letter>": 0xed,
    b"<dpad>": 0xee,
    b"<up>": 0xf0,
    b"<down>": 0xf1,
    b"<left>": 0xf2,
    b"<right>": 0xf3,
}


def setReplacementName(key, value):
    _NAMES[key] = value


def formatText(s, *, center=False, ask=None):
    s = s.format(**_NAMES)
    s = s.encode("ascii")
    s = s.replace(b"'", b"^")

    def padLine(line):
        return line + b' ' * (16 - len(line))
    if center:
        def padLine(line):
            padding = (16 - len(line))
            return b' ' * (padding // 2) + line + b' ' * (padding - padding // 2)

    result = b''
    for line in s.split(b'\n'):
        result_line = b''
        for word in line.split(b' '):
            if len(result_line) + 1 + len(word) > 16:
                result += padLine(result_line)
                result_line = b''
            elif result_line:
                result_line += b' '
            result_line += word
        if result_line:
            result += padLine(result_line)
    if ask is not None:
        ask = ask.encode("ascii")
        result = result.rstrip()
        while len(result) % 32 != 16:
            result += b' '
        return result + b'    ' + ask + b'\xfe'
    return result.rstrip() + b'\xff'


def tileDataToString(data, key=" 123"):
    result = ""
    for n in range(0, len(data), 2):
        a = data[n]
        b = data[n+1]
        for m in range(8):
            bit = 0x80 >> m
            if (a & bit) and (b & bit):
                result += key[3]
            elif (b & bit):
                result += key[2]
            elif (a & bit):
                result += key[1]
            else:
                result += key[0]
        result += "\n"
    return result

def createTileData(data, key=" 123"):
    result = []
    for line in data.split("\n"):
        line = line + "        "
        a = 0
        b = 0
        for n in range(8):
            if line[n] == key[3]:
                a |= 0x80 >> n
                b |= 0x80 >> n
            elif line[n] == key[2]:
                b |= 0x80 >> n
            elif line[n] == key[1]:
                a |= 0x80 >> n
        result.append(a)
        result.append(b)
    assert (len(result) % 16) == 0, len(result)
    return bytes(result)

if __name__ == "__main__":
    data = formatText("It is dangurous to go alone.\nTake\nthis\na\nline.")
    for i in range(0, len(data), 16):
        print(data[i:i+16])