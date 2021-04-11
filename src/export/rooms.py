import os
import roomEditor
import json
import entityData
import PIL.Image
import constants
import re as regex


MINIMAP_TYPES = {
    0x7D: "INVISIBLE",
    0xEF: "ROOM",
    0xED: "CHEST",
    0xEE: "BOSS",
}
ALL_ROOMS = list(range(0x2FF)) + list(range(0x300, 0x316)) + ["Alt06", "Alt0E", "Alt1B", "Alt2B", "Alt79", "Alt8C"]

EVENT_TRIGGERS = [
    "NONE",
    "KILL_ALL",
    "PUSH_BLOCK",
    "BUTTON",
    "UNKNOWN4",
    "TORCHES",
    "KILL_ORDER",
    "PUSH_BLOCKS",
    "KILL_SPECIALS",
    "SOLVE_TILE_PUZZLE",
    "KILL_SIDESCROLL_BOSS",
    "THROW_AT_DOOR",
    "HORSE_HEADS",
    "THROW_AT_CHEST",
    "FILL_LAVA",
    "SHOOT_EYE_WITH_BOW",
    "AWNSER_TUNICS"
]
EVENT_ACTIONS = [
    "NONE",
    "OPEN_DOORS",
    "KILL_ENEMIES",
    "SHOW_CHEST",
    "DROP_KEY",
    "SHOW_STAIRS",
    "CLEAR_MIDBOSS",
    "DROP_FAIRY",
]

class RoomTemplate:
    WALL_UP = 0x01
    WALL_DOWN = 0x02
    WALL_LEFT = 0x04
    WALL_RIGHT = 0x08

    def __init__(self, flags):
        self.tiles = [None] * 80
        for x in range(0, 10):
            if flags & RoomTemplate.WALL_UP:
                self.tiles[x + 0 * 10] = 0x21
            if flags & RoomTemplate.WALL_DOWN:
                self.tiles[x + 7 * 10] = 0x22
        for y in range(0, 8):
            if flags & RoomTemplate.WALL_LEFT:
                self.tiles[0 + y * 10] = 0x23
            if flags & RoomTemplate.WALL_RIGHT:
                self.tiles[9 + y * 10] = 0x24
        if flags & RoomTemplate.WALL_LEFT and flags & RoomTemplate.WALL_UP:
            self.tiles[0 + 0 * 10] = 0x25
        if flags & RoomTemplate.WALL_RIGHT and flags & RoomTemplate.WALL_UP:
            self.tiles[9 + 0 * 10] = 0x26
        if flags & RoomTemplate.WALL_LEFT and flags & RoomTemplate.WALL_DOWN:
            self.tiles[0 + 7 * 10] = 0x27
        if flags & RoomTemplate.WALL_RIGHT and flags & RoomTemplate.WALL_DOWN:
            self.tiles[9 + 7 * 10] = 0x28


INDOOR_ROOM_TEMPLATES = [
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_UP | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_UP | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_UP),
    RoomTemplate(RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_UP | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_DOWN),
    RoomTemplate(RoomTemplate.WALL_RIGHT | RoomTemplate.WALL_UP),
    RoomTemplate(RoomTemplate.WALL_LEFT | RoomTemplate.WALL_UP),
    RoomTemplate(0),
]


class RoomData:
    WALL_UP = 0x01
    WALL_DOWN = 0x02
    WALL_LEFT = 0x04
    WALL_RIGHT = 0x08

    def __init__(self):
        self.tiles = [0] * 10 * 8
        self.objects = []
        self.properties = {}
        self.tileset_image = ""

    def setTile(self, x, y, tile):
        if 0 <= x < 10 and 0 <= y < 8:
            self.tiles[x + y * 10] = tile

    def addObject(self, x, y, name, type):
        self.objects.append((int(x), int(y), name, type))

    def save(self, filename):
        objects = []
        for x, y, name, objtype in self.objects:
            objects.append({"width": 16, "height": 16, "x": x * 16, "y": y * 16, "name": name, "type": objtype})
        properties = []
        for key, value in sorted(self.properties.items()):
            if isinstance(value, str):
                properties.append({"name": key, "type": "string", "value": value})
            elif isinstance(value, int):
                properties.append({"name": key, "type": "int", "value": value})
            else:
                raise RuntimeError(type(value))

        data = {
            "width": 10, "height": 8,
            "type": "map", "renderorder": "right-down", "tiledversion": "1.4.3", "version": 1.4,
            "tilewidth": 16, "tileheight": 16, "orientation": "orthogonal",
            "tilesets": [
                {
                    "columns": 16, "firstgid": 1,
                    "image": self.tileset_image, "imageheight": 256, "imagewidth": 256,
                    "margin": 0, "name": "main", "spacing": 0,
                    "tilecount": 256, "tileheight": 16, "tilewidth": 16
                }
            ],
            "layers": [{
                "data": [n+1 for n in self.tiles],
                "width": 10, "height": 8,
                "id": 1, "name": "Tiles", "type": "tilelayer", "visible": True, "opacity": 1, "x": 0, "y": 0,
            }, {
                "id": 2, "name": "ObjectLayer", "type": "objectgroup", "visible": True, "opacity": 1, "x": 0, "y": 0,
                "objects": objects,
            }],
            "properties": properties
        }
        json.dump(data, open(filename, "wt"))

    def load(self, filename):
        data = json.load(open(filename, "rt"))
        shown_warning = False
        for layer in data['layers']:
            if layer['type'] == "tilelayer":
                for n in range(80):
                    self.tiles[n] = (layer['data'][n] - 1) & 0xFF
                    if self.tiles[n] != layer['data'][n] - 1 and not shown_warning:
                        print("Warning: %s contains incorrect tile." % (filename))
                        shown_warning = True
            elif layer['type'] == "objectgroup":
                for obj in layer['objects']:
                    self.addObject((obj["x"] + obj["width"] // 2) // 16, (obj["y"] + obj["height"] // 2) // 16, obj["name"], obj["type"])
        for prop in data["properties"]:
            self.properties[prop["name"]] = prop["value"]
        self.tileset_image = data["tilesets"][0]["image"]


def exportRooms(rom, path):
    os.makedirs(path, exist_ok=True)

    # Create overworld world file
    json.dump({
        "maps": [
            {"fileName": "room%03x.json" % (n), "height": 128, "width": 160, "x": (n & 0x0F) * 160, "y": (n >> 4) * 128}
            for n in range(0x100)
        ],
        "onlyShowAdjacentMaps": False,
        "type": "world"
    }, open(os.path.join(path, "overworld.world"), "wt"))

    map_per_room = {}
    minimap_data = {}
    # Create indoor maps
    for n in range(13):
        layout = rom.banks[0x14][0x0220 + n * 64:0x0220 + n * 64+64]
        offset = 0x100
        if n == 11:
            offset = 0x300
        elif n > 5:
            offset = 0x200
        for y in range(8):
            for x in range(8):
                if layout[x+y * 8] != 0 or (n == 11 and x == 1 and y == 3):
                    map_per_room[layout[x+y * 8]+offset] = n
        json.dump({
            "maps": [
                {"fileName": "room%03x.json" % (layout[x+y*8] + offset), "height": 128, "width": 160, "x": x * 160,
                 "y": y * 128}
                for y in range(8) for x in range(8) if layout[x+y*8] != 0 or (n == 11 and x == 1 and y == 3)
            ],
            "onlyShowAdjacentMaps": False,
            "type": "world"
        }, open(os.path.join(path, "layout_%02x.world" % (n)), "wt"))

        minimap = None
        if n < 8:
            minimap = rom.banks[0x02][0x2479 + n * 64:0x2479 + n * 64 + 64]
        elif n == 12:  # collapsed tower
            minimap = rom.banks[0x02][0x2479 + 8 * 64:0x2479 + 8 * 64 + 64]
        elif n == 11: # color dungeon
            minimap = rom.banks[0x02][0x2479 + 9 * 64:0x2479 + 9 * 64 + 64]
        if minimap:
            for idx in range(64):
                room = layout[idx]
                if room != 0 or n == 11:
                    minimap_data[room + offset] = MINIMAP_TYPES[minimap[idx]]

    sidescroller_rooms = set()
    # Figure out which rooms are sidescrollers
    for room_index in range(0x2FF):
        re = roomEditor.RoomEditor(rom, room_index)
        for warp in re.getWarps():
            if warp.warp_type == 2:
                sidescroller_rooms.add(warp.room)
            elif warp.warp_type == 1:
                map_per_room[warp.room] = warp.map_nr

    # Export each room.
    for room_index in ALL_ROOMS:
        re = roomEditor.RoomEditor(rom, room_index)
        data = RoomData()

        if re.overlay:
            # Overworld rooms
            for y in range(8):
                for x in range(10):
                    data.setTile(x, y, re.overlay[x+y*10])
            # In a few cases, there is a warp capable tile overwritten by a different tile to place a future warp there
            # We need to ensure that this is kept else we wrong warp.
            for obj in re.objects:
                if obj.type_id in roomEditor.WARP_TYPE_IDS and re.overlay[obj.x + obj.y * 10] != obj.type_id:
                    if obj.type_id != 0xE1 or re.overlay[obj.x + obj.y * 10] != 0x53: # Ignore the waterfall 'caves'
                        data.addObject(obj.x, obj.y, "%02X" % (obj.type_id), "HIDDEN_TILE")
                if obj.type_id == 0xC5 and re.overlay[obj.x + obj.y * 10] == 0xC4:
                    # Pushable gravestones have the wrong overlay by default
                    re.overlay[obj.x + obj.y * 10] = 0xC5
                if obj.type_id == 0xDC:
                    # Flowers above the rooster windmill need a different tile
                    data.addObject(obj.x, obj.y, "%02X" % (obj.type_id), "HIDDEN_TILE")
        else:
            for y in range(8):
                for x in range(10):
                    data.setTile(x, y, re.floor_object & 0x0F)
            for n, tile in enumerate(INDOOR_ROOM_TEMPLATES[re.floor_object >> 4].tiles):
                if tile is not None:
                    data.tiles[n] = tile

            for obj in re.objects:
                if isinstance(obj, roomEditor.ObjectHorizontal):
                    for n in range(obj.count):
                        data.setTile(obj.x + n, obj.y, obj.type_id)
                elif isinstance(obj, roomEditor.ObjectVertical):
                    for n in range(obj.count):
                        data.setTile(obj.x, obj.y + n, obj.type_id)
                elif isinstance(obj, roomEditor.ObjectWarp):
                    pass
                elif obj.type_id == 0xEC:  # key door
                    data.setTile(obj.x, obj.y, 0x2D)
                    data.setTile(obj.x + 1, obj.y, 0x2E)
                elif obj.type_id == 0xED:
                    data.setTile(obj.x, obj.y, 0x2F)
                    data.setTile(obj.x + 1, obj.y, 0x30)
                elif obj.type_id == 0xEE:
                    data.setTile(obj.x, obj.y, 0x31)
                    data.setTile(obj.x, obj.y + 1, 0x32)
                elif obj.type_id == 0xEF:
                    data.setTile(obj.x, obj.y, 0x33)
                    data.setTile(obj.x, obj.y + 1, 0x34)
                elif obj.type_id == 0xF0:  # closed door
                    data.setTile(obj.x, obj.y, 0x35)
                    data.setTile(obj.x + 1, obj.y, 0x36)
                elif obj.type_id == 0xF1:
                    data.setTile(obj.x, obj.y, 0x37)
                    data.setTile(obj.x + 1, obj.y, 0x38)
                elif obj.type_id == 0xF2:
                    data.setTile(obj.x, obj.y, 0x39)
                    data.setTile(obj.x, obj.y + 1, 0x3A)
                elif obj.type_id == 0xF3:
                    data.setTile(obj.x, obj.y, 0x3B)
                    data.setTile(obj.x, obj.y + 1, 0x3C)
                elif obj.type_id == 0xF4:  # open door
                    data.setTile(obj.x, obj.y, 0x43)
                    data.setTile(obj.x + 1, obj.y, 0x44)
                elif obj.type_id == 0xF5:
                    data.setTile(obj.x, obj.y, 0x8C)
                    data.setTile(obj.x + 1, obj.y, 0x08)
                elif obj.type_id == 0xF6:
                    data.setTile(obj.x, obj.y, 0x09)
                    data.setTile(obj.x, obj.y + 1, 0x0A)
                elif obj.type_id == 0xF7:
                    data.setTile(obj.x, obj.y, 0x0B)
                    data.setTile(obj.x, obj.y + 1, 0x0C)
                elif obj.type_id == 0xF8:  # boss door
                    data.setTile(obj.x, obj.y, 0xA4)
                    data.setTile(obj.x + 1, obj.y, 0xA5)
                elif obj.type_id == 0xF9:  # stairs door
                    data.setTile(obj.x, obj.y, 0xAF)
                    data.setTile(obj.x + 1, obj.y, 0xB0)
                elif obj.type_id == 0xFA:  # flipwall
                    data.setTile(obj.x, obj.y, 0xB1)
                    data.setTile(obj.x + 1, obj.y, 0xB2)
                elif obj.type_id == 0xFB:  # one way arrow
                    data.setTile(obj.x, obj.y, 0x45)
                    data.setTile(obj.x + 1, obj.y, 0x46)
                elif obj.type_id == 0xFC:  # entrance
                    data.setTile(obj.x + 0, obj.y, 0xB3)
                    data.setTile(obj.x + 1, obj.y, 0xB4)
                    data.setTile(obj.x + 2, obj.y, 0xB4)
                    data.setTile(obj.x + 3, obj.y, 0xB5)
                    data.setTile(obj.x + 0, obj.y + 1, 0xB6)
                    data.setTile(obj.x + 1, obj.y + 1, 0xB7)
                    data.setTile(obj.x + 2, obj.y + 1, 0xB8)
                    data.setTile(obj.x + 3, obj.y + 1, 0xB9)
                    data.setTile(obj.x + 0, obj.y + 2, 0xBA)
                    data.setTile(obj.x + 1, obj.y + 2, 0xBB)
                    data.setTile(obj.x + 2, obj.y + 2, 0xBC)
                    data.setTile(obj.x + 3, obj.y + 2, 0xBD)
                elif obj.type_id == 0xFD:  # entrance
                    data.setTile(obj.x, obj.y, 0xC1)
                    data.setTile(obj.x + 1, obj.y, 0xC2)
                else:
                    data.setTile(obj.x, obj.y, obj.type_id)

        for entity in re.entities:
            data.addObject(entity[0], entity[1], entityData.NAME[entity[2]], "ENTITY")

        warps = re.getWarps()
        for index in range(4):
            if index < len(warps):
                warp = warps[index]
                if warp.warp_type == 1:
                    data.properties["warp%d_type" % (index)] = "indoor"
                elif warp.warp_type == 2:
                    data.properties["warp%d_type" % (index)] = "sidescroll"
                else:
                    data.properties["warp%d_type" % (index)] = "overworld"
                data.properties["warp%d_map" % (index)] = "%02x" % (warp.map_nr)
                data.properties["warp%d_room" % (index)] = "%02x" % (warp.room & 0xFF)
                data.properties["warp%d_target" % (index)] = "%d,%d" % (warp.target_x, warp.target_y)
            else:
                data.properties["warp%d_type" % (index)] = "none"
                data.properties["warp%d_map" % (index)] = "00"
                data.properties["warp%d_room" % (index)] = "00"
                data.properties["warp%d_target" % (index)] = "0,0"

        room_nr = room_index
        if isinstance(room_nr, str):
            room_nr = int(room_nr[3:], 16)

        anim_addr = {2: 0x2B00, 3: 0x2C00, 4: 0x2D00, 5: 0x2E00, 6: 0x2F00, 7: 0x2D00, 8: 0x3000, 9: 0x3100, 10: 0x3200, 11: 0x2A00, 12: 0x3300, 13: 0x3500, 14: 0x3600, 15: 0x3400, 16: 0x3700}.get(re.animation_id, 0x0000)
        if room_nr < 0x100:
            tileset_index = rom.banks[0x3F][0x2f00 + room_nr]
            attributedata_bank = rom.banks[0x1A][0x2476 + room_nr]
            attributedata_addr = rom.banks[0x1A][0x1E76 + room_nr * 2]
            attributedata_addr |= rom.banks[0x1A][0x1E76 + room_nr * 2 + 1] << 8
            attributedata_addr -= 0x4000
            palette_index = rom.banks[0x21][0x02EF + room_nr]

            data.tileset_image = "ZZ_overworld_%02x_%02x_%02x_%02x_%04x.png" % (tileset_index, re.animation_id, palette_index, attributedata_bank, attributedata_addr)

            if not os.path.exists(os.path.join(path, data.tileset_image)):
                tilemap = rom.banks[0x2F][tileset_index*0x100:tileset_index*0x100+0x200]
                tilemap += rom.banks[0x2C][0x1200:0x1800]
                tilemap += rom.banks[0x2C][0x0800:0x1000]
                tilemap[0x6C0:0x700] = rom.banks[0x2C][anim_addr:anim_addr + 0x40]

                metatile_info = rom.banks[0x1A][0x2B1D:0x2B1D + 0x400]
                attrtile_info = rom.banks[attributedata_bank][attributedata_addr:attributedata_addr + 0x400]

                palette_addr = rom.banks[0x21][0x02B1 + palette_index * 2]
                palette_addr |= rom.banks[0x21][0x02B1 + palette_index * 2 + 1] << 8
                palette_addr -= 0x4000

                palette = []
                for n in range(8*4):
                    p0 = rom.banks[0x21][palette_addr]
                    p1 = rom.banks[0x21][palette_addr + 1]
                    pal = p0 | p1 << 8
                    palette_addr += 2
                    r = (pal & 0x1F) << 3
                    g = ((pal >> 5) & 0x1F) << 3
                    b = ((pal >> 10) & 0x1F) << 3
                    palette += [r, g, b]

                # Make some adjustments for special tiles
                # Bush with hole or stairs
                metatile_info[0xD3 * 4 + 1] = metatile_info[0xE8 * 4 + 1]
                metatile_info[0xD3 * 4 + 3] = metatile_info[0xC6 * 4 + 3]

                img = PIL.Image.new("P", (16*16, 16*16))
                img.putpalette(palette)
                def drawTile(x, y, index, attr):
                    for py in range(8):
                        a = tilemap[index * 16 + py * 2]
                        b = tilemap[index * 16 + py * 2 + 1]
                        if attr & 0x40:
                            a = tilemap[index * 16 + 14 - py * 2]
                            b = tilemap[index * 16 + 15 - py * 2]
                        for px in range(8):
                            bit = 0x80 >> px
                            if attr & 0x20:
                                bit = 0x01 << px
                            c = (attr & 7) << 2
                            if a & bit:
                                c |= 1
                            if b & bit:
                                c |= 2
                            img.putpixel((x+px, y+py), c)
                for x in range(16):
                    for y in range(16):
                        idx = x+y*16
                        metatiles = metatile_info[idx*4:idx*4+4]
                        attrtiles = attrtile_info[idx*4:idx*4+4]
                        drawTile(x * 16 + 0, y * 16 + 0, metatiles[0], attrtiles[0])
                        drawTile(x * 16 + 8, y * 16 + 0, metatiles[1], attrtiles[1])
                        drawTile(x * 16 + 0, y * 16 + 8, metatiles[2], attrtiles[2])
                        drawTile(x * 16 + 8, y * 16 + 8, metatiles[3], attrtiles[3])
                img.save(os.path.join(path, data.tileset_image))
        else:
            tileset_index = rom.banks[0x20][0x2eB3 + room_nr - 0x100]

            if room_index in sidescroller_rooms:
                data.tileset_image = "ZZ_sidescroll_%02x.png" % (re.animation_id)
            else:
                data.tileset_image = "ZZ_indoor_%02x_%02x.png" % (tileset_index, re.animation_id)

            if not os.path.exists(os.path.join(path, data.tileset_image)):
                metatile_info = rom.banks[0x08][0x0000:0x0400]

                if room_index in sidescroller_rooms:
                    # TODO: Tileset depends on map [0x3000:0x3800] is the other set
                    tilemap = rom.banks[0x0D][0x3800:0x4000]
                else:
                    if tileset_index == 0xFF:
                        tilemap = bytearray(0x100)
                    else:
                        tilemap = rom.banks[0x0D][0x1000 + tileset_index * 0x100:0x1100 + tileset_index * 0x100]
                    tilemap += rom.banks[0x0D][0x2100:0x2200]
                    tilemap += rom.banks[0x0D][0x0000:0x0600]
                tilemap += bytearray(0x700)
                tilemap += rom.banks[0x12][0x3800:0x3900]

                tilemap[0x6C0:0x700] = rom.banks[0x2C][anim_addr:anim_addr + 0x40]

                img = PIL.Image.new("P", (16*16, 16*16))
                img.putpalette([255,255,255, 170,170,170, 85,85,85, 0,0,0])
                def drawTile(x, y, index, attr):
                    for py in range(8):
                        a = tilemap[index * 16 + py * 2]
                        b = tilemap[index * 16 + py * 2 + 1]
                        if attr & 0x40:
                            a = tilemap[index * 16 + 14 - py * 2]
                            b = tilemap[index * 16 + 15 - py * 2]
                        for px in range(8):
                            bit = 0x80 >> px
                            if attr & 0x20:
                                bit = 0x01 << px
                            c = (attr & 7) << 2
                            if a & bit:
                                c |= 1
                            if b & bit:
                                c |= 2
                            img.putpixel((x+px, y+py), c)
                for x in range(16):
                    for y in range(16):
                        idx = x+y*16
                        metatiles = metatile_info[idx*4:idx*4+4]
                        attrtiles = (0, 0, 0, 0)
                        drawTile(x * 16 + 0, y * 16 + 0, metatiles[0], attrtiles[0])
                        drawTile(x * 16 + 8, y * 16 + 0, metatiles[1], attrtiles[1])
                        drawTile(x * 16 + 0, y * 16 + 8, metatiles[2], attrtiles[2])
                        drawTile(x * 16 + 8, y * 16 + 8, metatiles[3], attrtiles[3])
                img.save(os.path.join(path, data.tileset_image))

        if room_index in minimap_data:
            data.properties["MINIMAP"] = minimap_data[room_index]

        if isinstance(room_nr, int):
            data.properties["CHESTITEM"] = [k for k, v in constants.CHEST_ITEMS.items() if v == rom.banks[0x14][0x0560 + room_nr]][0]
            data.properties["ROOMITEM"] = [k for k, v in constants.CHEST_ITEMS.items() if v == rom.banks[0x3E][0x3800 + room_nr]][0]
            if room_nr > 0x100:
                event = rom.banks[0x14][room_nr - 0x100]
                data.properties["EVENT_TRIGGER"] = EVENT_TRIGGERS[event & 0x1F]
                data.properties["EVENT_ACTION"] = EVENT_ACTIONS[event >> 5]

        if isinstance(room_index, str):
            roomfilename = "room%s.json" % (room_index)
        else:
            roomfilename = "room%03x.json" % (room_index)
        data.save(os.path.join(path, roomfilename))


def importRooms(rom, path):
    minimap_address_per_room = {}
    for n in range(13):
        if n < 8:
            minimapaddr = 0x2479 + n * 64
        elif n == 12:  # collapsed tower
            minimapaddr = 0x2479 + 8 * 64
        elif n == 11: # color dungeon
            minimapaddr = 0x2479 + 9 * 64
        else:
            minimapaddr = None

        layout = bytearray(64)
        data = json.load(open(os.path.join(path, "layout_%02x.world" % (n)), "rt"))
        for mapdata in data["maps"]:
            x = mapdata["x"] // 160
            y = mapdata["y"] // 128
            assert 0 <= x < 8 and 0 <= y < 8
            room = int(regex.match(r"room([0-9a-f]+)\.json", mapdata["fileName"]).group(1), 16)
            layout[x + y * 8] = room & 0xFF
            if minimapaddr is not None:
                minimap_address_per_room[room] = minimapaddr + x + y * 8
        rom.banks[0x14][0x0220 + n * 64:0x0220 + n * 64+64] = layout

    # Clear out all the minimap data
    rom.banks[0x02][0x2479:0x2479+64*10] = b'\x7D' * 64 * 10

    for room_index in ALL_ROOMS:
        if isinstance(room_index, str):
            roomfilename = "room%s.json" % (room_index)
        else:
            roomfilename = "room%03x.json" % (room_index)

        data = RoomData()
        data.load(os.path.join(path, roomfilename))

        re = roomEditor.RoomEditor(rom, room_index)
        re.objects = []
        re.entities = []

        if re.overlay:
            for n in range(80):
                re.overlay[n] = data.tiles[n]
            # Simplify the overworld tiles, so they take less storage
            for n in range(80):
                if data.tiles[n] in {0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                            0x33, 0x34, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                            0x48, 0x49, 0x4B, 0x4C, 0x4E,
                            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F}:
                    data.tiles[n] = 0x3A  # Solid tiles
                elif data.tiles[n] in {0x08, 0x09, 0x0C, 0x44,
                            0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}:
                    data.tiles[n] = 0x04  # Open tiles

            # Count each tile, to figure out the most common one as floor tile
            counts = {}
            for n in data.tiles:
                counts[n] = counts.get(n, 0) + 1
            re.floor_object = max(counts, key=counts.get)
            template_tiles = [re.floor_object] * 80
        else:
            counts = {}
            for n in data.tiles:
                if n < 0x10: # Indoor maps can only have one of the first 16 metatiles as floor
                    counts[n] = counts.get(n, 0) + 1
            if counts:
                re.floor_object = max(counts, key=counts.get)
            else:
                re.floor_object = 0

            # Figure out which room template to apply.
            template_scores = {}
            for template_index, template in enumerate(INDOOR_ROOM_TEMPLATES):
                score = 0
                for idx, tile in enumerate(template.tiles):
                    if tile is None:
                        tile = re.floor_object
                    if data.tiles[idx] == tile:
                        score += 1
                template_scores[template_index] = score
            template_index = max(template_scores, key=template_scores.get)
            template_tiles = [re.floor_object] * 80
            for idx, tile in enumerate(INDOOR_ROOM_TEMPLATES[template_index].tiles):
                if tile is not None:
                    template_tiles[idx] = tile
            re.floor_object |= template_index << 4

        done = [data.tiles[n] == template_tiles[n] for n in range(80)]
        for y in range(8):
            for x in range(10):
                obj = data.tiles[x + y * 10]
                if done[x + y * 10]:
                    continue
                # Figure out if we should do a horizontal or vertical strip.
                xmax = x
                for x1 in range(x + 1, 10):
                    if done[x1 + y * 10]:
                        break
                    if data.tiles[x1 + y * 10] == obj:
                        xmax = x1
                ymax = y
                for y1 in range(y + 1, 8):
                    if done[x + y1 * 10]:
                        break
                    if data.tiles[x + y1 * 10] == obj:
                        ymax = y1
                w = xmax - x + 1
                h = ymax - y + 1
                if w > h:
                    for n in range(w):
                        if data.tiles[x + n + y * 10] == obj:
                            done[x + n + y * 10] = True
                    re.objects.append(roomEditor.ObjectHorizontal(x, y, obj, w))
                elif h > 1:
                    for n in range(h):
                        if data.tiles[x + (y + n) * 10] == obj:
                            done[x + (y + n) * 10] = True
                    re.objects.append(roomEditor.ObjectVertical(x, y, obj, h))
                else:
                    re.objects.append(roomEditor.Object(x, y, obj))

        for x, y, name, objtype in data.objects:
            if objtype == 'ENTITY':
                re.entities.append((x, y, entityData.NAME.index(name)))
            elif objtype == 'HIDDEN_TILE':
                re.objects.insert(0, roomEditor.Object(x,y, int(name, 16)))
        for n in range(4):
            if "warp%d_type" % (n) in data.properties:
                wtype = data.properties["warp%d_type" % (n)].lower()
                wmap = data.properties["warp%d_map" % (n)]
                wroom = data.properties["warp%d_room" % (n)]
                wtarget = [int(n.strip()) for n in data.properties["warp%d_target" % (n)].split(",")]
                if wtype == "overworld":
                    wtype = 0
                elif wtype == "indoor":
                    wtype = 1
                elif wtype == "sidescroll":
                    wtype = 2
                else:
                    continue
                re.objects.append(roomEditor.ObjectWarp(wtype, int(wmap, 16), int(wroom, 16), wtarget[0], wtarget[1]))

        if isinstance(room_index, int):
            rom.banks[0x14][0x0560 + room_index] = constants.CHEST_ITEMS[data.properties["CHESTITEM"]]
            rom.banks[0x3E][0x3800 + room_index] = constants.CHEST_ITEMS[data.properties["ROOMITEM"]]

            if room_index > 0x100 and "EVENT_TRIGGER" in data.properties:
                event = EVENT_TRIGGERS.index(data.properties["EVENT_TRIGGER"])
                event |= EVENT_ACTIONS.index(data.properties["EVENT_ACTION"]) << 5
                rom.banks[0x14][room_index - 0x100] = event

            if room_index in minimap_address_per_room:
                rom.banks[0x02][minimap_address_per_room[room_index]] = [k for k, v in MINIMAP_TYPES.items() if v == data.properties["MINIMAP"]][0]

            m = regex.match(r"ZZ_overworld_([0-9a-f]+)_([0-9a-f]+)_([0-9a-f]+)_([0-9a-f]+)_([0-9a-f]+).png", data.tileset_image)
            if m and room_index < 0x100:
                tileset_index, re.animation_id, palette_index, attributedata_bank, attributedata_addr = [int(v, 16) for v in m.groups()]
                attributedata_addr += 0x4000

                rom.banks[0x3F][0x2f00 + room_index] = tileset_index
                rom.banks[0x1A][0x2476 + room_index] = attributedata_bank
                rom.banks[0x1A][0x1E76 + room_index * 2] = attributedata_addr & 0xFF
                rom.banks[0x1A][0x1E76 + room_index * 2 + 1] = (attributedata_addr >> 8)
                rom.banks[0x21][0x02EF + room_index] = palette_index

            m = regex.match(r"ZZ_indoor_([0-9a-f]+)_([0-9a-f]+).png", data.tileset_image)
            if m and room_index >= 0x100:
                tileset_index, re.animation_id = [int(v, 16) for v in m.groups()]
                rom.banks[0x20][0x2eB3 + room_index - 0x100] = tileset_index

            m = regex.match(r"ZZ_sidescroll_([0-9a-f]+).png", data.tileset_image)
            if m and room_index >= 0x100:
                re.animation_id = [int(v, 16) for v in m.groups()][0]

        re.store(rom)
