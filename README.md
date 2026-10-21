# Metal Gear Solid: Portable Ops / Portable Ops Plus - Noesis plugin

`fmt_mgs_portableops.py` adds support for both PSP games (USA releases tested) to Noesis:

| File | Support |
|---|---|
| `slot.dat` | archive extraction (character / weapon slot pages) |
| `stage/<stage>/_zar` | archive extraction via **Tools > MGS Portable Ops**, or rename to `<name>.zar` and open it |
| `.dar`, `.qar` | archive extraction (nested stage archives) |
| `.mdp` | models: meshes, normals, UVs, vertex colours, materials, skeleton + skinning, textures and animations auto-loaded |
| `.txp` | textures: every frame (sub image) of the texture archive |
| `.mtar` | motion archives: shown on the matching model found next to them |

## Installation

Copy `fmt_mgs_portableops.py` into `<Noesis>/plugins/python/` (Noesis 4.4+, uses its embedded Python 3.2).

## Usage

1. **Extract**: *Tools > MGS Portable Ops > Extract game data (slot.dat + all stages)...* and pick the game folder
   (the one containing `PSP_GAME`) and an output folder. Or open `slot.dat` / a renamed `.zar` directly.
   - stages are written to `stage/<stage>/`; the stage's `cache.dar` + `cache.qar` (and `resident.*`) are unpacked
     together into `cache/` (`resident/`) because the game uses them together and their names never collide.
     `-mpoarcraw` writes the nested archives as files instead.
   - slot pages are written to `slot/<page>/`. Names are restored from a dictionary built from the stage archive
     listings (type id and name hash must both match); other files keep their 24-bit name hash, e.g. `496bce.mdp`.
2. **View**: open any `.mdp`. Its textures are looked up exactly like the game does it (the `.txp` named by the
   model first, then every other `.txp` in the folder); every `.mtar` in the folder whose skeleton matches is
   loaded as animations (60 fps). Opening a `.mtar` shows it on the first matching model of its folder (or of a
   sibling folder, e.g. another slot page).
3. **Export**: use Noesis' normal export (FBX, glTF, ...) to get meshes, textures, skeleton and animations.

### Options

| Option | Meaning |
|---|---|
| `-mpoanims <all\|none\|a.mtar,b.mtar>` | which motion archives of the folder to load (default all) |
| `-mpomotions <0,2,5-7>` | only load these motion indices from each archive |
| `-mpoanimpath <file or folder>` | extra motion archive(s); also *Tools > MGS Portable Ops > Set extra animation folder...* |
| `-mpoinplace` | remove the horizontal root motion (the root height is kept) |
| `-mponoroot` | do not apply the root motion channel at all |
| `-mpokeepwinding` | keep the arbitrary original winding of geometry that the game draws without culling |
| `-mpoarcraw` | archive extraction: don't unpack nested `.dar` / `.qar` |
| `-mpohexnames` | slot extraction: always name files by hash |

## Conventions of the output

- Units are the game's (a soldier is 1843 units tall, i.e. 1 unit ≈ 1 mm), Y up, characters face +Z. Skinned
  models have their hips at the origin in the bind pose.
- Bones are named `b_<hash>` (the game's 24-bit name hashes); the same names are used by every motion archive.
- Animations are sampled at every frame of the motion (60 fps, the game's motion frame rate: 5 time units per frame,
  10 units per 30 fps game tick). The root channel places the character on a floor at Y = 0 exactly like the game
  (hips at `floor + root height`)

## Reverse-engineered formats (all little endian)

**_zar**: `u32 size` + zlib stream → DAR.
**DAR**: `u32 count`, then per file: name `\0` (pad 4), `u32 size` (pad 16), data, one `\0`.
**QAR**: last `u32` = list offset; list = `u32 count`, `count × (u32 hash, u32 size)`, names; data from offset 0, 0x80 aligned.
**Resource hash**: `(type << 24) | strcode24(name)`, `strcode24`: `v = ((v >> 19 | v << 5) + c) & 0xFFFFFF` (0 → 1).
**slot.dat**: 0x800 header (`u32 time, u16 1, u16 1, u16 pages, u16 groups`); each page: TOC
(`u32 n`, `n × (u32 hash, u32 offset & 0x3FFFFFFF)`, first entry `0x7F000002` = data size, `0x7F000000` end) padded to
0x800, then data padded to 0x800; file size = next offset − offset.

**TXP**: header `u32 0, flags, texCount, texOfs, frameCount, frameOfs`; texture 0x10 (`u16 w|log2w<<12, u16 h|log2h<<12,
u16 fmt, u16 flags (2 = zlib: u32 size + stream), u32 pixels, u32 clut`); frame 0x30 (`u32 flags, u32 hash, u32, u16 w, h,
x, y, u32 texture, u16 palette, u16, f32 uOfs, vOfs, uScale, vScale, u32`). Formats seen: 4 = 4-bit, 5 = 8-bit indexed,
RGBA8888 palettes (`sceGuClutMode(8888)`), always PSP swizzled (16 bytes × 8 rows). GE texel coordinate:
`(u16 / 4096 · uScale + uOfs) · 2^log2w`. Frame flags: 1 nearest, 2 repeat (else clamp; sub frames bound as own texture),
8 TFX_REPLACE (else MODULATE + colour doubling), 0x70 blend (0x10 alpha, 0x20 add, 0x30 reverse subtract),
0x300 = 0x100 environment-map overlay, 0x1000 alpha reference 0x7F (blended frames).

**MDP**: header 0x50 (`"MDP "`, bone/group/object counts, `u32` txp name hash, table offsets, `f32` scale at 0x20, bbox).
Bone 0x50 (`hash, ?, s32 parent, ?, vec4 local, vec4 world, bbox`), group 0x10, object 0x50 (`hash, flags, faceCount,
faceOfs, vertexOfs, paletteOfs, vertexCount, ?, bbox, vec4 position`), face 12 bytes (`u16 flags, u16 count,
u32 indices or strip, u32 material`), material 0x18 (`u32 frame hash, u16, u16, u32 ambient, diffuse, specular,
f32 power`). Object flags: low 4 bits vertex format (0: tc/nrm/pos 16 bytes, 1/2/3: 2/4/8 u8 weights + tc/nrm/pos,
4: tc/colour/nrm/pos), 0x20 backface culling (rigid models), 0x1000 non-indexed strips. Positions are `s16 × scale`
(+ object position for rigid models); skinned vertices are in model space, skin matrix = `world × T(−bind world)`;
weights are u8 with 128 = 1.0 on the object's bone palette.

**MTAR**: `"Mtar"`, bone count, motion count, data base, flags (0x10000: bone hash + parent hash tables follow at 0x20),
then `(offset, size)` per motion. Motion header: hash, flags, time units per frame (5), frame count, data offset,
size, track count, 128-bit bit-width class mask, two bit widths, channel offsets (u16 units). Rotation keys (bit
stream, LSB first, n = the track's bit width): `dur:8, angle:n, x:n, y:n, signs:3`; with `s = 2^n − 1` the axis is
`(±x/s, ±y/s, ±(1 − x/s − y/s))` normalised and the angle `π·angle/s`; spherical interpolation, key k is reached at
time `Σ dur(0..k) − unit`. Translation/root keys: `dur:8` + three 16-bit floats whose exponent is rebiased by 119
(IEEE half × 128). Motions with flag 0x10000 store bone 1's rotation in world space.

## Limitations

- Unnamed slot files keep their hash names (the names are not stored on the disc).
