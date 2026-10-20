#Metal Gear Solid: Portable Ops / Portable Ops Plus (PSP, Konami/Kojima Productions 2006/2007) - Noesis plugin
#
#Reverse engineered from the game data and executables (BOOT.BIN) of both games. The two games share the same
#engine formats; every loader/decoder routine used here was verified to be identical in both executables.
#
#Supported files:
#  slot.dat         character/weapon slot archive (archive extraction)
#  _zar             stage archives (zlib compressed DAR). Noesis cannot open extensionless files, so use
#                   Tools > MGS Portable Ops > "Extract stage archive(s)..." or rename the file to <anything>.zar
#  .zar             stage archive (renamed _zar), archive extraction
#  .dar / .qar      nested archives (archive extraction)
#  .mdp             models: meshes, materials, skeleton/skinning; textures are taken from .txp files in the same
#                   folder (the txp named by the model, then any other txp). Animations: .mtar files in the same
#                   folder whose skeleton matches the model are loaded automatically (see options)
#  .txp             textures (every frame/sub image is loaded as its own texture)
#  .mtar            motion archives. Shown on the first model with a matching skeleton in the same folder (or a
#                   sibling folder such as another slot page). To combine a model with motion archives from another
#                   folder use -mpoanimpath or Tools > MGS Portable Ops > "Set extra animation folder..."
#
#Options (command line / advanced options):
#  -mpoanims <mode>     all (default: load every matching .mtar in the folder), none, or a comma separated list of
#                       .mtar file names to load
#  -mpomotions <list>   only load the listed motion indices (e.g. 0,2,5-7) from each .mtar
#  -mpoanimpath <path>  extra .mtar file or folder to take animations from (also settable from the Tools menu)
#  -mpoinplace          remove the horizontal root motion (the root height is kept)
#  -mponoroot           don't apply the root motion channel to the root bone at all
#  -mpokeepwinding      keep the original (arbitrary) triangle winding of double-sided geometry
#  -mpoarcraw           archive extraction: write nested .dar/.qar as files instead of unpacking them
#  -mpohexnames         archive extraction: always name slot.dat files by hash

from inc_noesis import *
import os
import math
import time

MPO_PLUGIN_VERSION = "1.0"
MPO_FPS = 60.0

try:
	MPO_NOESIS = noesis.getAPIVersion() > 0
except Exception:
	MPO_NOESIS = False

mpoSettings = {"rapiTex": True}


def mpoInflate(src, size):
	return rapi.decompInflate(src, size)


def mpoLog(msg):
	print("[MPO] " + msg)


#=====================================================================================================
# core: binary helpers, hashing, archives (no Noesis dependency below this line until the glue part)
#=====================================================================================================

def mpoU16(d, o):
	return noeUnpackFrom("<H", d, o)[0]


def mpoS16(d, o):
	return noeUnpackFrom("<h", d, o)[0]


def mpoU32(d, o):
	return noeUnpackFrom("<I", d, o)[0]


def mpoS32(d, o):
	return noeUnpackFrom("<i", d, o)[0]


def mpoF32(d, o):
	return noeUnpackFrom("<f", d, o)[0]


class MpoError(Exception):
	pass


#strcode as implemented by the game (FUN_0003c230): 24-bit rotate-and-add hash, 0 maps to 1
def mpoStrcode(s):
	if isinstance(s, str):
		s = s.encode("latin-1")
	v = 0
	for c in s:
		v = ((v >> 19) | (v << 5)) & 0xFFFFFFFF
		v = (v + c) & 0xFFFFFF
	return v if v else 1


#resource type ids (extension table of the game, identical in both games)
MPO_EXT_TO_TYPE = {"bin": 0x01, "gcx": 0x02, "tri": 0x03, "mdh": 0x04, "mds": 0x05, "lt2": 0x06, "cv2": 0x07, "mtar": 0x08,
	"mtsq": 0x09, "mtfa": 0x0A, "mtcm": 0x0B, "geom": 0x0C, "nav": 0x0F, "cvd": 0x10, "eft": 0x11, "zon": 0x12, "mdb": 0x13,
	"mdc": 0x13, "mdl": 0x13, "mdp": 0x13, "txp": 0x14, "kms": 0x15, "rpd": 0x16, "fcx": 0x17, "mtst": 0x18, "mdpb": 0x19,
	"mgm": 0x30, "prx": 0x31, "rlc": 0x32, "ptcp": 0x33, "cddl": 0x34, "cap": 0x35, "pcmp": 0x36, "sep": 0x37, "bgp": 0x38,
	"la2": 0x5F, "slot": 0x60, "png": 0x68, "img": 0x69, "vib": 0x6A, "rat": 0x6B, "rcm": 0x6C, "ola": 0x6D, "row": 0x6E,
	"mtra": 0x6F, "psq": 0xFF}
MPO_TYPE_TO_EXT = {}
for _e, _t in MPO_EXT_TO_TYPE.items():
	if _t not in MPO_TYPE_TO_EXT or _e == "mdp":
		MPO_TYPE_TO_EXT[_t] = _e


#full resource hash of "name.ext" (FUN_0003c274): strcode of the part before the first '.', type id in the top byte
def mpoResourceHash(fileName):
	i = fileName.find(".")
	if i < 0:
		return mpoStrcode(fileName)
	h = mpoStrcode(fileName[:i])
	t = MPO_EXT_TO_TYPE.get(fileName[i + 1:].lower(), 0)
	return h | (t << 24)


def mpoNameForHash(h):
	name = MPO_NAMES.get(h)
	ext = MPO_TYPE_TO_EXT.get(h >> 24, "t%02x" % (h >> 24))
	if name is None:
		name = "%06x" % (h & 0xFFFFFF)
	return name + "." + ext


def mpoIsPrintableName(b):
	if len(b) == 0 or len(b) > 128:
		return False
	for c in b:
		if c < 0x21 or c > 0x7E or c in (0x2F, 0x5C, 0x3A, 0x2A, 0x3F, 0x22, 0x3C, 0x3E, 0x7C):
			return False
	return True


def mpoAlign(v, a):
	return (v + a - 1) & ~(a - 1)


#PSP DAR: u32 count, then per entry name\0 (padded to 4), u32 size (padded to 16), data, 1 null byte
#returns a list of (name, offset, size) with offsets relative to the start of d, or None if invalid
def mpoParseDar(d, base = 0, end = None):
	if end is None:
		end = len(d)
	if end - base < 8:
		return None
	n = mpoU32(d, base)
	if n <= 0 or n > 65536:
		return None
	pos = base + 4
	out = []
	for i in range(n):
		e = d.find(b"\0", pos, min(end, pos + 130))
		if e < 0:
			return None
		nm = d[pos:e]
		if not mpoIsPrintableName(nm):
			return None
		pos = base + mpoAlign(e + 1 - base, 4)
		if pos + 4 > end:
			return None
		size = mpoU32(d, pos)
		pos = base + mpoAlign(pos + 4 - base, 16)
		if size > end - pos:
			return None
		out.append((noeStrFromBytes(nm), pos, size))
		pos += size + 1
	if pos > end + 1:
		return None
	return out


#PSP QAR: list offset in the last u32; list = u32 count, (u32 hash, u32 size) * count, names; data aligned to 0x80
def mpoParseQar(d, base = 0, end = None):
	if end is None:
		end = len(d)
	if end - base < 8:
		return None
	listOfs = mpoU32(d, end - 4)
	if listOfs < 0 or base + listOfs + 4 > end - 4:
		return None
	lp = base + listOfs
	n = mpoU32(d, lp)
	if n <= 0 or n > 65536 or lp + 4 + n * 8 > end:
		return None
	ents = []
	for i in range(n):
		ents.append(noeUnpackFrom("<II", d, lp + 4 + 8 * i))
	p = lp + 4 + n * 8
	out = []
	pos = 0
	for i in range(n):
		e = d.find(b"\0", p, min(end, p + 130))
		if e < 0:
			return None
		nm = d[p:e]
		if not mpoIsPrintableName(nm):
			return None
		p = e + 1
		h, size = ents[i]
		if pos + size > listOfs:
			return None
		out.append((noeStrFromBytes(nm), base + pos, size, h))
		pos = mpoAlign(pos + size, 0x80)
	return out


#_zar: u32 decompressed size + zlib stream containing a DAR
def mpoIsZar(d):
	if len(d) < 8:
		return False
	usz = mpoU32(d, 0)
	cmf = d[4]
	flg = d[5]
	if (cmf & 0x0F) != 8 or (cmf >> 4) > 7 or ((cmf << 8) | flg) % 31 != 0:
		return False
	return 8 <= usz <= 0x8000000


def mpoUnzar(d):
	usz = mpoU32(d, 0)
	out = mpoInflate(d[4:], usz)
	if len(out) != usz:
		raise MpoError("zar: decompressed %d bytes, expected %d" % (len(out), usz))
	return out


#slot.dat: 0x800 byte header sector, then pages; each page = table of contents sector(s) + data (0x800 aligned)
MPO_SLOT_SECTOR = 0x800


def mpoParseSlotHeader(h):
	if len(h) < 0x10:
		return None
	ts, v1, v2, nPages, nGroups, one = noeUnpackFrom("<IHHHHI", h, 0)
	if v1 != 1 or v2 != 1 or nPages == 0 or nPages > 4096:
		return None
	return (ts, nPages, nGroups)


#parses a page table of contents (bytes starting at the page). returns (dataOffset, dataSize, [(hash, offset, size)])
def mpoParseSlotToc(t, tocLen = None):
	if len(t) < 12:
		return None
	n = mpoU32(t, 0)
	if n < 3 or n > 4096:
		return None
	need = 4 + n * 8
	if need > len(t):
		return None
	ents = []
	for i in range(n):
		ents.append(noeUnpackFrom("<II", t, 4 + 8 * i))
	if ents[0][0] != 0x7F000002 or ents[-1] != (0, 0):
		return None
	dataSize = ents[0][1] & 0x3FFFFFFF
	dataOfs = (n * 8 + 0x803) & ~0x7FF
	files = []
	for i in range(n):
		h, o = ents[i]
		if h == 0 or (h & 0xFF000000) == 0x7F000000:
			continue
		if i + 1 >= n:
			return None
		o &= 0x3FFFFFFF
		nxt = ents[i + 1][1] & 0x3FFFFFFF
		if nxt < o or nxt > dataSize:
			return None
		files.append((h, o, nxt - o))
	return (dataOfs, dataSize, files)


#walks all pages of a slot.dat given a read(offset, size) callable
def mpoScanSlot(readFn, fileSize):
	hdr = mpoParseSlotHeader(readFn(0, 0x10))
	if hdr is None:
		return None
	ts, nPages, nGroups = hdr
	pages = []
	off = MPO_SLOT_SECTOR
	for i in range(nPages):
		if off + MPO_SLOT_SECTOR > fileSize:
			return None
		t = readFn(off, MPO_SLOT_SECTOR)
		n = mpoU32(t, 0)
		if n * 8 + 4 > MPO_SLOT_SECTOR:
			t = readFn(off, (n * 8 + 0x803) & ~0x7FF)
		toc = mpoParseSlotToc(t)
		if toc is None:
			return None
		dataOfs, dataSize, files = toc
		pages.append((off, off + dataOfs, dataSize, files))
		off += dataOfs + mpoAlign(dataSize, MPO_SLOT_SECTOR)
	if off > fileSize:
		return None
	return (ts, nGroups, pages)


#=====================================================================================================
# core: TXP textures
#=====================================================================================================

#GE pixel formats
MPO_TEX_BPP = {0: 16, 1: 16, 2: 16, 3: 32, 4: 4, 5: 8, 6: 16, 7: 32}
MPO_TEX_FMTNAME = {0: "5650", 1: "5551", 2: "4444", 3: "8888", 4: "T4", 5: "T8", 6: "T16", 7: "T32", 8: "DXT1", 9: "DXT3", 10: "DXT5"}


class MpoTexture:
	pass


class MpoFrame:
	pass


class MpoTxp:
	pass


#header: u32 runtime link, u32 flags, u32 texture count, u32 texture table, u32 frame count, u32 frame table, u32 x2
#texture (0x10): u16 width (low 12 = buffer width, high 4 = log2 width), u16 height (same), u16 format, u16 flags,
#                u32 pixel data, u32 clut
#frame (0x30): u32 flags, u32 hash, u32 runtime, u16 w, u16 h, u16 x, u16 y, u32 texture header, u16 palette index,
#              u16 pad, f32 u offset, f32 v offset, f32 u scale, f32 v scale, u32 pad
def mpoParseTxp(d, base = 0, end = None):
	if end is None:
		end = len(d)
	size = end - base
	if size < 0x20:
		return None
	link, flags, nTex, texOfs, nFrm, frmOfs, r0, r1 = noeUnpackFrom("<8I", d, base)
	if link != 0 or nTex == 0 or nTex > 4096 or nFrm > 65536:
		return None
	if texOfs < 0x20 or texOfs + nTex * 0x10 > size or (nFrm and (frmOfs < 0x20 or frmOfs + nFrm * 0x30 > size)):
		return None
	txp = MpoTxp()
	txp.flags = flags
	txp.textures = []
	txp.frames = []
	txp.data = d
	txp.base = base
	for i in range(nTex):
		o = base + texOfs + i * 0x10
		w, h, fmt, tflags, pix, clut = noeUnpackFrom("<HHHHII", d, o)
		t = MpoTexture()
		t.index = i
		t.bufWidth = w & 0xFFF
		t.height = h & 0xFFF
		t.potWidth = 1 << (w >> 12)
		t.potHeight = 1 << (h >> 12)
		t.fmt = fmt
		t.flags = tflags
		t.pixOfs = pix
		t.clutOfs = clut
		if t.bufWidth == 0 or t.height == 0 or pix >= size or (fmt in (4, 5, 6, 7) and clut >= size):
			return None
		txp.textures.append(t)
	for i in range(nFrm):
		o = base + frmOfs + i * 0x30
		fflags, fhash, frt, fw, fh, fx, fy, ftex, fpal, fpad = noeUnpackFrom("<IIIHHHHIHH", d, o)
		uo, vo, us, vs = noeUnpackFrom("<4f", d, o + 0x1C)
		ti = (ftex - texOfs) // 0x10
		if ftex < texOfs or (ftex - texOfs) % 0x10 or ti >= nTex:
			return None
		f = MpoFrame()
		f.index = i
		f.flags = fflags
		f.hash = fhash
		f.width = fw
		f.height = fh
		f.x = fx
		f.y = fy
		f.tex = ti
		f.palette = fpal
		f.uvOffset = (uo, vo)
		f.uvScale = (us, vs)
		txp.frames.append(f)
	return txp


#PSP GE texture swizzle: blocks of 16 bytes x 8 rows stored contiguously
def mpoUnswizzle(src, rowBytes, height):
	if MPO_NOESIS and mpoSettings.get("rapiTex", True):
		return rapi.imageUntwiddlePSP(src, rowBytes, height, 8)
	out = bytearray(rowBytes * height)
	bw = rowBytes // 16
	s = 0
	for by in range(0, height, 8):
		for bx in range(bw):
			dst = by * rowBytes + bx * 16
			for r in range(8):
				out[dst:dst + 16] = src[s:s + 16]
				s += 16
				dst += rowBytes
	return bytes(out)


#returns the (unswizzled) texel data of a texture
def mpoTexturePixels(txp, t):
	d = txp.data
	bpp = MPO_TEX_BPP.get(t.fmt)
	if bpp is None:
		raise MpoError("unsupported texture format %d" % t.fmt)
	rowBytes = t.bufWidth * bpp // 8
	size = rowBytes * t.height
	o = txp.base + t.pixOfs
	if t.flags & 2:
		csz = mpoU32(d, o) & 0xFFFFFF
		raw = mpoInflate(d[o + 4:o + 4 + csz], size)
		if len(raw) < size:
			raise MpoError("texture decompression failed (%d of %d bytes)" % (len(raw), size))
		raw = raw[:size]
	else:
		raw = d[o:o + size]
		if len(raw) < size:
			raise MpoError("texture data truncated")
	if (rowBytes % 16) == 0 and (t.height % 8) == 0:
		raw = mpoUnswizzle(raw, rowBytes, t.height)
	return raw, rowBytes, bpp


def mpoPalette(txp, t, palIndex):
	n = {4: 16, 5: 256, 6: 65536, 7: 65536}[t.fmt]
	o = txp.base + t.clutOfs + palIndex * 0x40
	if t.fmt in (6, 7):
		n = (len(txp.data) - o) // 4
	pal = txp.data[o:o + n * 4]
	if len(pal) < n * 4:
		pal = pal + bytes(n * 4 - len(pal))
	return pal


def mpoDecodeDirect(pix, w, h, fmt):
	out = bytearray(w * h * 4)
	if fmt == 3:
		return bytes(pix[:w * h * 4])
	for i in range(w * h):
		v = pix[i * 2] | (pix[i * 2 + 1] << 8)
		if fmt == 0:
			r = (v & 0x1F) << 3; g = ((v >> 5) & 0x3F) << 2; b = ((v >> 11) & 0x1F) << 3; a = 255
			r |= r >> 5; g |= g >> 6; b |= b >> 5
		elif fmt == 1:
			r = (v & 0x1F) << 3; g = ((v >> 5) & 0x1F) << 3; b = ((v >> 10) & 0x1F) << 3; a = 255 if (v & 0x8000) else 0
			r |= r >> 5; g |= g >> 5; b |= b >> 5
		else:
			r = (v & 0xF) * 17; g = ((v >> 4) & 0xF) * 17; b = ((v >> 8) & 0xF) * 17; a = ((v >> 12) & 0xF) * 17
		out[i * 4] = r; out[i * 4 + 1] = g; out[i * 4 + 2] = b; out[i * 4 + 3] = a
	return bytes(out)


#decodes the whole stored texture (buffer width x height) to RGBA32 using the given palette
def mpoDecodeTexture(txp, t, palIndex = 0):
	pix, rowBytes, bpp = mpoTexturePixels(txp, t)
	w = t.bufWidth
	h = t.height
	if t.fmt in (0, 1, 2, 3):
		return mpoDecodeDirect(pix, w, h, t.fmt)
	pal = mpoPalette(txp, t, palIndex)
	if MPO_NOESIS and mpoSettings.get("rapiTex", True) and bpp in (4, 8):
		return bytes(rapi.imageDecodeRawPal(pix, pal, w, h, bpp, "r8g8b8a8"))
	out = bytearray(w * h * 4)
	if bpp == 4:
		j = 0
		for b in pix:
			lo = (b & 15) * 4
			hi = (b >> 4) * 4
			out[j:j + 4] = pal[lo:lo + 4]
			out[j + 4:j + 8] = pal[hi:hi + 4]
			j += 8
	elif bpp == 8:
		j = 0
		for b in pix:
			out[j:j + 4] = pal[b * 4:b * 4 + 4]
			j += 4
	else:
		ib = bpp // 8
		for i in range(w * h):
			idx = pix[i * ib] | (pix[i * ib + 1] << 8)
			if ib == 4:
				idx |= (pix[i * ib + 2] << 16) | (pix[i * ib + 3] << 24)
			out[i * 4:i * 4 + 4] = pal[idx * 4:idx * 4 + 4]
	return bytes(out)


def mpoCropRGBA(rgba, w, h, x, y, cw, ch):
	if x == 0 and y == 0 and cw == w and ch == h:
		return rgba
	out = bytearray(cw * ch * 4)
	for r in range(ch):
		s = ((y + r) * w + x) * 4
		out[r * cw * 4:(r + 1) * cw * 4] = rgba[s:s + cw * 4]
	return bytes(out)


#decodes a frame (the image a material refers to) and returns (width, height, rgba)
def mpoDecodeFrame(txp, f, cache = None):
	t = txp.textures[f.tex]
	key = (f.tex, f.palette)
	rgba = None
	if cache is not None:
		rgba = cache.get(key)
	if rgba is None:
		rgba = mpoDecodeTexture(txp, t, f.palette)
		if cache is not None:
			cache[key] = rgba
	cw = max(1, min(f.width, t.bufWidth - f.x))
	ch = max(1, min(f.height, t.height - f.y))
	return cw, ch, mpoCropRGBA(rgba, t.bufWidth, t.height, f.x, f.y, cw, ch)


#frame flags (texture bind FUN_000480f8 / material setup FUN_0004504c + FUN_00047ffc, identical in both games):
#  0x0001 nearest filtering (GE TEXFILTER), otherwise linear
#  0x0002 repeat wrapping (GE TEXWRAP), otherwise clamp. a repeating frame smaller than the texture page is bound as
#         its own texture (data pointer moved to the frame, texture size = frame size, no uv offset) so it tiles
#  0x0008 GU_TFX_REPLACE (texture colour only, no lighting / vertex colour), otherwise MODULATE with colour doubling
#  0x0070 blending: 0x10 alpha, 0x20 additive, 0x30 reverse subtract
#  0x0300 == 0x100: environment map overlay pass (additive)
#  0x1000 alpha test reference 0x7F instead of 0 (only used together with blending)
def mpoFrameIsSubTexture(txp, f):
	t = txp.textures[f.tex]
	return (f.flags & 2) != 0 and (f.width != t.potWidth or f.height != t.potHeight)


#maps the hardware texture coordinate to the cropped frame image.
#normal frames:       texel = (u * scaleU + offsetU) * potWidth   ->  u_img = (texel - x) / w
#repeating sub-frames: texel (inside the frame) = u * scaleU * potWidth  ->  u_img = texel / w
def mpoFrameUVTransform(txp, f):
	t = txp.textures[f.tex]
	cw = max(1, min(f.width, t.bufWidth - f.x))
	ch = max(1, min(f.height, t.height - f.y))
	su = f.uvScale[0] * t.potWidth / cw
	sv = f.uvScale[1] * t.potHeight / ch
	if mpoFrameIsSubTexture(txp, f):
		return (su, sv, 0.0, 0.0)
	bu = (f.uvOffset[0] * t.potWidth - f.x) / cw
	bv = (f.uvOffset[1] * t.potHeight - f.y) / ch
	return (su, sv, bu, bv)


#uv transform onto the whole stored texture page (used for clamped frames whose coordinates leave the frame,
#where the hardware samples the neighbouring texels of the page)
def mpoPageUVTransform(txp, f):
	t = txp.textures[f.tex]
	su = f.uvScale[0] * t.potWidth / t.bufWidth
	sv = f.uvScale[1] * t.potHeight / t.height
	bu = f.uvOffset[0] * t.potWidth / t.bufWidth
	bv = f.uvOffset[1] * t.potHeight / t.height
	return (su, sv, bu, bv)


#=====================================================================================================
# core: MDP models
#=====================================================================================================

#vertex formats (object flags & 0xF -> GE vertex type, table at 0x1f1450 in both executables):
# 0: tc u16, nrm s16, pos s16                    (16 bytes)
# 1: 2 weights u8, tc u16, nrm s16, pos s16       (18 bytes)
# 2: 4 weights u8, tc u16, nrm s16, pos s16       (20 bytes)
# 3: 8 weights u8, tc u16, nrm s16, pos s16       (24 bytes)
# 4: tc u16, color 8888, nrm s16, pos s16         (20 bytes)
MPO_VTX_STRIDE = {0: 16, 1: 18, 2: 20, 3: 24, 4: 20}
MPO_VTX_WEIGHTS = {0: 0, 1: 2, 2: 4, 3: 8, 4: 0}


class MpoBone:
	pass


class MpoGroup:
	pass


class MpoObject:
	pass


class MpoFace:
	pass


class MpoMaterial:
	pass


class MpoMdp:
	pass


def mpoParseMdp(d, base = 0, end = None):
	if end is None:
		end = len(d)
	size = end - base
	if size < 0x50 or d[base:base + 4] != b"MDP ":
		return None
	nb, ng, no, txpHash, boneOfs, grpOfs, objOfs = noeUnpackFrom("<7I", d, base + 4)
	if nb > 255 or ng > 4096 or no == 0 or no > 4096:
		return None
	if (nb and boneOfs + nb * 0x50 > size) or (ng and grpOfs + ng * 0x10 > size) or objOfs + no * 0x50 > size:
		return None
	m = MpoMdp()
	m.data = d
	m.base = base
	m.size = size
	m.txpHash = txpHash & 0xFFFFFF
	m.scale = mpoF32(d, base + 0x20)
	m.flags = mpoU32(d, base + 0x2C)
	m.bboxMax = noeUnpackFrom("<3f", d, base + 0x30)
	m.bboxMin = noeUnpackFrom("<3f", d, base + 0x40)
	m.bones = []
	for i in range(nb):
		o = base + boneOfs + i * 0x50
		b = MpoBone()
		b.index = i
		b.hash, b.u4, b.parent, b.uc = noeUnpackFrom("<IIiI", d, o)
		b.local = noeUnpackFrom("<3f", d, o + 0x10)
		b.world = noeUnpackFrom("<3f", d, o + 0x20)
		b.bboxMax = noeUnpackFrom("<3f", d, o + 0x30)
		b.bboxMin = noeUnpackFrom("<3f", d, o + 0x40)
		if b.parent >= i or b.parent < -1:
			return None
		m.bones.append(b)
	m.groups = []
	grpIndex = {}
	for i in range(ng):
		g = MpoGroup()
		g.index = i
		g.hash, g.flags, g.parent, g.uc = noeUnpackFrom("<IIiI", d, base + grpOfs + i * 0x10)
		if g.hash not in grpIndex:
			grpIndex[g.hash] = i
		m.groups.append(g)
	m.objects = []
	mats = {}
	for i in range(no):
		o = base + objOfs + i * 0x50
		ob = MpoObject()
		ob.index = i
		ob.hash, ob.flags, nf, faceOfs, ob.vtxOfs, ob.palOfs, ob.nVerts = noeUnpackFrom("<7I", d, o)
		ob.fmt = ob.flags & 0xF
		ob.bboxMax = noeUnpackFrom("<3f", d, o + 0x20)
		ob.bboxMin = noeUnpackFrom("<3f", d, o + 0x30)
		ob.pos = noeUnpackFrom("<3f", d, o + 0x40)
		ob.group = grpIndex.get(ob.hash & 0xFFFFFF, -1)
		if nf > 4096 or (nf and faceOfs + nf * 12 > size):
			return None
		ob.palette = []
		if ob.palOfs:
			if ob.palOfs + 4 > size:
				return None
			pn = mpoU16(d, base + ob.palOfs + 2)
			if ob.palOfs + 4 + pn > size:
				return None
			ob.palette = list(d[base + ob.palOfs + 4:base + ob.palOfs + 4 + pn])
			for p in ob.palette:
				if p >= nb:
					return None
		ob.faces = []
		for j in range(nf):
			ff, cnt, buf, mat = noeUnpackFrom("<HHII", d, base + faceOfs + j * 12)
			fc = MpoFace()
			fc.index = j
			fc.flags = ff
			fc.count = cnt
			fc.bufOfs = buf
			if mat and mat + 0x18 <= size:
				mt = mats.get(mat)
				if mt is None:
					mt = MpoMaterial()
					mt.offset = mat
					mt.index = len(mats)
					mt.texHash, mt.unk, mt.flags, mt.ambient, mt.diffuse, mt.specular, mt.power = noeUnpackFrom("<IHHIIIf", d, base + mat)
					mats[mat] = mt
				fc.material = mt
			else:
				fc.material = None
			ob.faces.append(fc)
		m.objects.append(ob)
	m.materials = sorted(mats.values(), key = lambda x: x.index)
	return m


#vertex buffer decoding. returns lists: pos (s16 triples), nrm (s16 triples), uv (u16 pairs), clr (rgba tuples or None),
#wgt (lists of u8 weights or None)
def mpoReadVerts(d, ofs, count, fmt):
	stride = MPO_VTX_STRIDE[fmt]
	nw = MPO_VTX_WEIGHTS[fmt]
	if ofs + stride * count > len(d):
		raise MpoError("vertex buffer out of range")
	pos = []
	nrm = []
	uv = []
	clr = [] if fmt == 4 else None
	wgt = [] if nw else None
	tco = nw
	if tco & 1:
		tco += 1
	if fmt == 4:
		co = tco + 4
		no = co + 4
	else:
		no = tco + 4
	po = no + 6
	for i in range(count):
		o = ofs + i * stride
		if nw:
			wgt.append(d[o:o + nw])
		uv.append(noeUnpackFrom("<HH", d, o + tco))
		if fmt == 4:
			clr.append(d[o + co:o + co + 4])
		nrm.append(noeUnpackFrom("<3h", d, o + no))
		pos.append(noeUnpackFrom("<3h", d, o + po))
	return pos, nrm, uv, clr, wgt


#triangle-strip index list (u16) for a face of an indexed object
def mpoReadIndices(d, ofs, count):
	if ofs + count * 2 > len(d):
		raise MpoError("index buffer out of range")
	return list(noeUnpackFrom("<%dH" % count, d, ofs))


#draw calls of an object: list of (face, vertexArrays, stripIndices, vertexIndexList)
#vertexIndexList are the indices into the object's shared buffer (or None for non-indexed objects)
def mpoObjectDrawCalls(m, ob):
	d = m.data
	if ob.fmt not in MPO_VTX_STRIDE:
		return []
	calls = []
	if ob.flags & 0x1000:
		for fc in ob.faces:
			if fc.count < 3:
				continue
			va = mpoReadVerts(d, m.base + fc.bufOfs, fc.count, ob.fmt)
			calls.append((fc, va, list(range(fc.count)), None))
	else:
		if ob.nVerts == 0:
			return []
		shared = mpoReadVerts(d, m.base + ob.vtxOfs, ob.nVerts, ob.fmt)
		for fc in ob.faces:
			if fc.count < 3:
				continue
			idx = mpoReadIndices(d, m.base + fc.bufOfs, fc.count)
			for i in idx:
				if i >= ob.nVerts:
					raise MpoError("vertex index out of range")
			calls.append((fc, shared, idx, True))
	return calls


#triangle strip -> triangle list, skipping degenerate triangles. the GE alternates winding every triangle.
def mpoStripToTris(idx):
	tris = []
	for i in range(len(idx) - 2):
		a = idx[i]
		b = idx[i + 1]
		c = idx[i + 2]
		if a == b or b == c or a == c:
			continue
		if i & 1:
			tris.extend((b, a, c))
		else:
			tris.extend((a, b, c))
	return tris


#=====================================================================================================
# core: MTAR motion archives
#=====================================================================================================

class MpoMtar:
	pass


class MpoMotion:
	pass


def mpoParseMtar(d, base = 0, end = None):
	if end is None:
		end = len(d)
	size = end - base
	if size < 0x20 or d[base:base + 4] != b"Mtar":
		return None
	nb, nm, dataBase, flags = noeUnpackFrom("<4I", d, base + 4)
	if nb > 255 or nm > 65536 or dataBase > size:
		return None
	mt = MpoMtar()
	mt.data = d
	mt.base = base
	mt.flags = flags
	mt.boneHashes = []
	mt.parentHashes = []
	tab = base + 0x20
	if flags & 0x10000:
		if 0x20 + nb * 8 > size:
			return None
		mt.boneHashes = list(noeUnpackFrom("<%dI" % nb, d, tab))
		mt.parentHashes = list(noeUnpackFrom("<%dI" % nb, d, tab + nb * 4))
		tab += nb * 8
	if tab - base + nm * 8 > size:
		return None
	mt.motions = []
	for i in range(nm):
		mo, msz = noeUnpackFrom("<II", d, tab + i * 8)
		a = base + dataBase + mo
		if a + 0x40 > end:
			return None
		mt.motions.append(a)
	return mt


#motion header (all offsets relative to the motion start):
# 0x00 hash, 0x04 flags, 0x08 time units per frame, 0x0C frame count, 0x10 data offset, 0x14 data size, 0x18 track count,
# 0x1C 128-bit per-track bit width class mask, 0x2C u8 bit widths (class 0, class 1), 0x30 root (s16) channel,
# 0x34 root (half) channel, 0x3C step channel, 0x40 rotation track offsets, then translation track offsets
# (offsets are in 16-bit units from the data start)
# flags: 0x02 bone rotations, 0x04 step channel, 0x10 root (s16 keys), 0x20 root (half keys), 0x40 bone translations,
#        0x10000 bone 1 rotation is absolute (not parented to bone 0)
def mpoMotionHeader(mt, index):
	d = mt.data
	a = mt.motions[index]
	mo = MpoMotion()
	mo.index = index
	mo.ofs = a
	mo.hash, mo.flags, mo.unit, mo.frames, dofs, mo.dataSize, mo.tracks = noeUnpackFrom("<7I", d, a)
	m0, m1, m2, m3 = noeUnpackFrom("<4I", d, a + 0x1C)
	mo.classMask = m0 | (m1 << 32) | (m2 << 64) | (m3 << 96)
	mo.bits = (d[a + 0x2C], d[a + 0x2D])
	mo.ofsRootS16, mo.ofsRootHalf, mo.ofs38, mo.ofsStep = noeUnpackFrom("<4I", d, a + 0x30)
	mo.dataOfs = a + dofs
	if mo.tracks > 255 or mo.unit == 0 or mo.frames == 0:
		raise MpoError("bad motion header")
	tabEnd = a + 0x40 + mo.tracks * 8
	if tabEnd > len(d):
		raise MpoError("motion track table out of range")
	mo.rotOfs = list(noeUnpackFrom("<%dI" % mo.tracks, d, a + 0x40)) if mo.tracks else []
	mo.trnOfs = list(noeUnpackFrom("<%dI" % mo.tracks, d, a + 0x40 + mo.tracks * 4)) if (mo.tracks and (mo.flags & 0x40)) else []
	return mo


#16-bit float as converted by the game (FUN_00081668): exponent rebiased by +119 (not IEEE's +112), i.e. IEEE half * 128.
#exponent 0 maps to a zero exponent (denormal float, effectively 0), exponent 31 is an ordinary exponent.
def mpoHalf(h):
	e = (h >> 10) & 0x1F
	bits = ((h & 0x8000) << 16) | (((e + 119) << 23) if e else 0) | ((h & 0x3FF) << 13)
	return noeUnpack("<f", noePack("<I", bits))[0]


class MpoBitReader:
	def __init__(self, d, byteOfs):
		self.d = d
		self.ofs = byteOfs
		self.pos = 0

	def read(self, n):
		p = self.ofs + (self.pos >> 3)
		sh = self.pos & 7
		d = self.d
		v = 0
		k = 0
		while k < 4 and p + k < len(d):
			v |= d[p + k] << (8 * k)
			k += 1
		self.pos += n
		return (v >> sh) & ((1 << n) - 1)


#reads a keyed track: returns list of (durationUnits, value) with the game's semantics:
#the value of key k is reached at time sum(dur[0..k]) - unit, segments are interpolated linearly / spherically
def mpoReadRotTrack(mo, trackIndex):
	d = mo_data(mo)
	cls = (mo.classMask >> trackIndex) & 1
	bits = mo.bits[cls]
	if bits < 1 or bits > 16:
		raise MpoError("bad rotation bit width %d" % bits)
	mx = float((1 << bits) - 1)
	br = MpoBitReader(d, mo.dataOfs + mo.rotOfs[trackIndex] * 2)
	total = mo.frames * mo.unit
	keys = []
	acc = 0
	while acc < total and len(keys) < 65536:
		dur = br.read(8) * mo.unit
		v0 = br.read(bits)
		v1 = br.read(bits)
		v2 = br.read(bits)
		s = br.read(3)
		a = v1 / mx
		b = v2 / mx
		c = 1.0 - a - b
		x = -a if (s & 1) else a
		y = -b if (s & 2) else b
		z = -c if (s & 4) else c
		n = 1.0 / math.sqrt(x * x + y * y + z * z)
		h = (v0 / mx) * math.pi * 0.5
		sn = math.sin(h) * n
		keys.append((dur, (x * sn, y * sn, z * sn, math.cos(h))))
		acc += dur
	return keys


def mpoReadTrnTrack(mo, trackIndex):
	d = mo_data(mo)
	br = MpoBitReader(d, mo.dataOfs + mo.trnOfs[trackIndex] * 2)
	total = mo.frames * mo.unit
	keys = []
	acc = 0
	while acc < total and len(keys) < 65536:
		dur = br.read(8) * mo.unit
		x = mpoHalf(br.read(16))
		y = mpoHalf(br.read(16))
		z = mpoHalf(br.read(16))
		keys.append((dur, (x, y, z)))
		acc += dur
	return keys


#root channel with half float keys: 3 halves (value before key 0) then (dur:8, x:16, y:16, z:16) keys
def mpoReadRootHalf(mo):
	d = mo_data(mo)
	o = mo.dataOfs + mo.ofsRootHalf * 2
	init = (mpoHalf(mpoU16(d, o)), mpoHalf(mpoU16(d, o + 2)), mpoHalf(mpoU16(d, o + 4)))
	br = MpoBitReader(d, o + 6)
	total = mo.frames * mo.unit
	keys = []
	acc = 0
	while acc < total and len(keys) < 65536:
		dur = br.read(8) * mo.unit
		x = mpoHalf(br.read(16))
		y = mpoHalf(br.read(16))
		z = mpoHalf(br.read(16))
		keys.append((dur, (x, y, z)))
		acc += dur
	return init, keys


#root channel with s16 keys: (u16 dur, s16 x, s16 y, s16 z) then (u16 dur, s16 dx, s16 y, s16 dz); x/z accumulate
def mpoReadRootS16(mo):
	d = mo_data(mo)
	o = mo.dataOfs + mo.ofsRootS16 * 2
	total = mo.frames * mo.unit
	keys = []
	acc = 0
	x = z = 0.0
	first = True
	while acc < total and len(keys) < 65536 and o + 8 <= len(d):
		dur, vx, vy, vz = noeUnpackFrom("<Hhhh", d, o)
		o += 8
		if first:
			x = float(vx)
			z = float(vz)
			first = False
		else:
			x += vx
			z += vz
		dur *= mo.unit
		keys.append((dur, (x, float(vy), z)))
		acc += dur
	return keys


def mo_data(mo):
	return mo.mtarData


def mpoQuatSlerp(q0, q1, t):
	#game slerp (FUN_0007cebc): shortest path, linear blend when nearly identical, then normalized by the caller
	d = q0[0] * q1[0] + q0[1] * q1[1] + q0[2] * q1[2] + q0[3] * q1[3]
	if d > 1.0:
		d = 1.0
	elif d < -1.0:
		d = -1.0
	if d > 0.998046875:
		a = 1.0 - t
		b = t
	else:
		if d < 0.0:
			q1 = (-q1[0], -q1[1], -q1[2], -q1[3])
		om = math.acos(abs(d))
		so = math.sin(om)
		if so < 5e-5:
			return q0
		a = math.sin((1.0 - t) * om) / so
		b = math.sin(t * om) / so
	r = (q0[0] * a + q1[0] * b, q0[1] * a + q1[1] * b, q0[2] * a + q1[2] * b, q0[3] * a + q1[3] * b)
	n = math.sqrt(r[0] * r[0] + r[1] * r[1] + r[2] * r[2] + r[3] * r[3])
	if n <= 0.0:
		return q0
	return (r[0] / n, r[1] / n, r[2] / n, r[3] / n)


def mpoLerp3(a, b, t):
	return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t)


#samples a keyed track at frames 0..frames-1. prev = value before key 0 (only used if key 0 is longer than one frame)
def mpoSampleTrack(keys, unit, frames, interp, prev = None):
	out = []
	if not keys:
		return out
	if prev is None:
		prev = keys[0][1]
	#key times
	times = []
	acc = 0
	for dur, v in keys:
		acc += dur
		times.append(acc - unit)
	k = 0
	n = len(keys)
	for f in range(frames):
		T = f * unit
		while k < n and times[k] < T:
			k += 1
		if k >= n:
			out.append(keys[-1][1])
			continue
		dur = keys[k][0]
		a = keys[k - 1][1] if k > 0 else prev
		if dur <= 0:
			out.append(keys[k][1])
			continue
		t = (T - (times[k] - dur)) / float(dur)
		if t >= 1.0:
			out.append(keys[k][1])
		elif t <= 0.0:
			out.append(a)
		else:
			out.append(interp(a, keys[k][1], t))
	return out


def mpoQuatMul(a, b):
	#Hamilton product a*b (same as the VFPU vqmul used by the game for parent * child)
	ax, ay, az, aw = a
	bx, by, bz, bw = b
	return (aw * bx + ax * bw + ay * bz - az * by,
		aw * by - ax * bz + ay * bw + az * bx,
		aw * bz + ax * by - ay * bx + az * bw,
		aw * bw - ax * bx - ay * by - az * bz)


def mpoQuatConj(q):
	return (-q[0], -q[1], -q[2], q[3])


def mpoQuatNorm(q):
	n = math.sqrt(q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3])
	if n <= 0.0:
		return (0.0, 0.0, 0.0, 1.0)
	return (q[0] / n, q[1] / n, q[2] / n, q[3] / n)


class MpoMotionSample:
	pass


#decodes a motion into per-frame local rotations/translations for a skeleton with the given parent list.
#returns MpoMotionSample with .rot[bone][frame] (quaternions, None if the bone has no track), .trn[bone][frame]
#(translation offsets added to the bind local translation, or None), .root[frame] (root channel position)
def mpoSampleMotion(mt, index, parents):
	mo = mpoMotionHeader(mt, index)
	mo.mtarData = mt.data
	nb = len(parents)
	frames = mo.frames
	smp = MpoMotionSample()
	smp.header = mo
	smp.frames = frames
	smp.rot = [None] * nb
	smp.trn = [None] * nb
	smp.root = None
	smp.rootHalf = None
	smp.rootS16 = None
	ntr = min(mo.tracks, nb)
	if mo.flags & 2:
		for i in range(ntr):
			keys = mpoReadRotTrack(mo, i)
			smp.rot[i] = mpoSampleTrack(keys, mo.unit, frames, mpoQuatSlerp)
	if mo.flags & 0x40:
		for i in range(ntr):
			keys = mpoReadTrnTrack(mo, i)
			smp.trn[i] = mpoSampleTrack(keys, mo.unit, frames, mpoLerp3)
	if mo.flags & 0x20:
		init, keys = mpoReadRootHalf(mo)
		smp.rootHalf = mpoSampleTrack(keys, mo.unit, frames, mpoLerp3, init)
	if mo.flags & 0x10:
		keys = mpoReadRootS16(mo)
		smp.rootS16 = mpoSampleTrack(keys, mo.unit, frames, mpoLerp3)
	#bone 1 absolute rotation (motions with flag 0x10000, FUN_0007f264): convert to parent-relative
	if (mo.flags & 0xFF0000) == 0x10000 and nb > 1 and smp.rot[1] is not None and parents[1] >= 0:
		p = parents[1]
		pw = mpoWorldRotations(smp, parents, p)
		if pw is not None:
			r1 = smp.rot[1]
			smp.rot[1] = [mpoQuatNorm(mpoQuatMul(mpoQuatConj(pw[f]), r1[f])) for f in range(frames)]
	return smp


#world rotation (parent chain composition) of a bone for every frame
def mpoWorldRotations(smp, parents, bone):
	chain = []
	b = bone
	while b >= 0:
		chain.append(b)
		b = parents[b]
	out = []
	for f in range(smp.frames):
		q = (0.0, 0.0, 0.0, 1.0)
		for b in reversed(chain):
			r = smp.rot[b]
			if r is not None:
				q = mpoQuatMul(q, r[f])
		out.append(q)
	return out


#=====================================================================================================
# Noesis glue: archive extraction
#=====================================================================================================

def mpoOpt(name):
	try:
		return noesis.optWasInvoked(name)
	except Exception:
		return 0


def mpoOptArg(name):
	try:
		if noesis.optWasInvoked(name):
			return noesis.optGetArg(name)
	except Exception:
		pass
	return None


class MpoExporter:
	#writes files either through Noesis' archive export (inside an archive handler) or directly to a folder (tools)
	def __init__(self, outDir = None):
		self.outDir = outDir
		self.written = {}
		self.count = 0

	def unique(self, path):
		key = path.lower()
		if key not in self.written:
			self.written[key] = 1
			return path
		i = 1
		while True:
			base, ext = os.path.splitext(path)
			p = "%s_%d%s" % (base, i, ext)
			if p.lower() not in self.written:
				self.written[p.lower()] = 1
				return p
			i += 1

	def write(self, path, data):
		path = self.unique(path.replace("\\", "/"))
		self.count += 1
		if self.outDir is None:
			rapi.exportArchiveFile(path, data)
			return
		full = os.path.join(self.outDir, path.replace("/", os.sep))
		d = os.path.dirname(full)
		if d and not os.path.isdir(d):
			os.makedirs(d)
		f = open(full, "wb")
		f.write(data)
		f.close()


#exports the entries of a DAR, unpacking nested .dar/.qar archives into a folder named after the archive
#(cache.dar + cache.qar -> cache/, the game uses both together and their names never collide)
def mpoExportDarEntries(ex, d, ents, prefix, raw):
	for nm, off, sz in ents:
		sub = None
		low = nm.lower()
		if not raw and low.endswith(".dar"):
			sub = mpoParseDar(d, off, off + sz)
			if sub is not None:
				mpoExportDarEntries(ex, d, sub, prefix + nm[:-4] + "/", raw)
				continue
		if not raw and low.endswith(".qar"):
			sub = mpoParseQar(d, off, off + sz)
			if sub is not None:
				for n2, o2, s2, h2 in sub:
					ex.write(prefix + nm[:-4] + "/" + n2, d[o2:o2 + s2])
				continue
		ex.write(prefix + nm, d[off:off + sz])


def mpoExportZarData(ex, raw, prefix, rawMode):
	d = mpoUnzar(raw)
	ents = mpoParseDar(d)
	if ents is None:
		raise MpoError("decompressed data is not a DAR archive")
	mpoExportDarEntries(ex, d, ents, prefix, rawMode)
	return len(ents)


def mpoReadFile(fileName, size = None):
	f = open(fileName, "rb")
	try:
		if size is None:
			return f.read()
		return f.read(size)
	finally:
		f.close()


def mpoExtractZar(fileName, fileLen, justChecking):
	if fileLen < 16:
		return 0
	try:
		head = mpoReadFile(fileName, 16)
		if not mpoIsZar(head):
			return 0
		if justChecking:
			return 1
		raw = mpoReadFile(fileName)
		ex = MpoExporter()
		n = mpoExportZarData(ex, raw, "", mpoOpt("-mpoarcraw"))
		mpoLog("extracted %d files from %s" % (ex.count, fileName))
	except Exception as e:
		if justChecking:
			return 0
		mpoLog("zar extraction failed: %s" % repr(e))
		return 0
	return 1


def mpoExtractDar(fileName, fileLen, justChecking):
	if fileLen < 16:
		return 0
	try:
		d = mpoReadFile(fileName)
		ents = mpoParseDar(d)
		if ents is None:
			return 0
		if justChecking:
			return 1
		ex = MpoExporter()
		mpoExportDarEntries(ex, d, ents, "", mpoOpt("-mpoarcraw"))
		mpoLog("extracted %d files from %s" % (ex.count, fileName))
	except Exception as e:
		if justChecking:
			return 0
		mpoLog("dar extraction failed: %s" % repr(e))
		return 0
	return 1


def mpoExtractQar(fileName, fileLen, justChecking):
	if fileLen < 16:
		return 0
	try:
		d = mpoReadFile(fileName)
		ents = mpoParseQar(d)
		if ents is None:
			return 0
		if justChecking:
			return 1
		ex = MpoExporter()
		for nm, off, sz, h in ents:
			ex.write(nm, d[off:off + sz])
		mpoLog("extracted %d files from %s" % (ex.count, fileName))
	except Exception as e:
		if justChecking:
			return 0
		mpoLog("qar extraction failed: %s" % repr(e))
		return 0
	return 1


class MpoFileReader:
	def __init__(self, fileName):
		self.f = open(fileName, "rb")

	def read(self, ofs, size):
		self.f.seek(ofs)
		return self.f.read(size)

	def close(self):
		self.f.close()


def mpoCheckSlotFile(fileName, fileLen):
	if fileLen < MPO_SLOT_SECTOR * 2:
		return False
	fr = MpoFileReader(fileName)
	try:
		if mpoParseSlotHeader(fr.read(0, 0x10)) is None:
			return False
		return mpoParseSlotToc(fr.read(MPO_SLOT_SECTOR, MPO_SLOT_SECTOR)) is not None
	finally:
		fr.close()


#slot.dat pages are written as <page>/<name>.<ext>; names are resolved from the built-in dictionary when known
def mpoExportSlot(ex, fileName, fileLen, hexNames = False):
	fr = MpoFileReader(fileName)
	try:
		res = mpoScanSlot(fr.read, fileLen)
		if res is None:
			raise MpoError("not a valid slot.dat")
		ts, nGroups, pages = res
		for pi, (pageOfs, dataOfs, dataSize, files) in enumerate(pages):
			for h, o, sz in files:
				if hexNames:
					nm = "%06x.%s" % (h & 0xFFFFFF, MPO_TYPE_TO_EXT.get(h >> 24, "t%02x" % (h >> 24)))
				else:
					nm = mpoNameForHash(h)
				ex.write("%03d/%s" % (pi, nm), fr.read(dataOfs + o, sz))
		return len(pages)
	finally:
		fr.close()


def mpoExtractSlot(fileName, fileLen, justChecking):
	try:
		if not mpoCheckSlotFile(fileName, fileLen):
			return 0
		if justChecking:
			return 1
		ex = MpoExporter()
		n = mpoExportSlot(ex, fileName, fileLen, mpoOpt("-mpohexnames"))
		mpoLog("extracted %d files from %d slot pages" % (ex.count, n))
	except Exception as e:
		if justChecking:
			return 0
		mpoLog("slot extraction failed: %s" % repr(e))
		return 0
	return 1


#=====================================================================================================
# Noesis glue: textures, models, animations
#=====================================================================================================

def mpoBaseName(path):
	b = os.path.basename(path)
	i = b.find(".")
	return b[:i] if i >= 0 else b


#name hash of a file as the game would have registered it (strcode of the base name, or the hash itself for
#files extracted with hashed names)
def mpoFileNameHash(path):
	b = mpoBaseName(path)
	h = mpoStrcode(b)
	if len(b) == 6:
		try:
			hv = int(b, 16)
			return (h, hv)
		except ValueError:
			pass
	return (h, None)


def mpoListFiles(folder, ext):
	out = []
	try:
		names = os.listdir(folder)
	except Exception:
		return out
	for n in sorted(names):
		if n.lower().endswith(ext):
			p = os.path.join(folder, n)
			if os.path.isfile(p):
				out.append(p)
	return out


#folders searched for textures/animations of a model: its own folder plus sibling folders produced by other
#extraction tools (cache.qar/, resident.qar/ ...)
def mpoSearchFolders(path):
	folder = os.path.dirname(os.path.abspath(path))
	out = [folder]
	parent = os.path.dirname(folder)
	try:
		for n in sorted(os.listdir(parent)):
			p = os.path.join(parent, n)
			if p != folder and os.path.isdir(p) and n.lower().endswith((".qar", ".dar")):
				out.append(p)
	except Exception:
		pass
	return out


class MpoTexLib:
	def __init__(self):
		self.txps = []
		self.noeTex = []
		self.byHash = {}
		self.cache = {}

	def addFile(self, path):
		try:
			d = rapi.loadIntoByteArray(path) if MPO_NOESIS else open(path, "rb").read()
		except Exception:
			return None
		t = mpoParseTxp(d)
		if t is None:
			return None
		t.name = mpoBaseName(path)
		t.nameHash = mpoFileNameHash(path)
		self.txps.append(t)
		return t

	#game lookup order (FUN_00047f0c / FUN_00047eb4): the txp named by the model first, then all txps
	def findFrame(self, primaryHash, frameHash):
		for t in self.txps:
			if primaryHash in t.nameHash:
				for f in t.frames:
					if f.hash == frameHash:
						return t, f
		for t in self.txps:
			for f in t.frames:
				if f.hash == frameHash:
					return t, f
		return None, None

	def decoded(self, t, f):
		ck = id(t)
		if ck not in self.cache:
			self.cache[ck] = {}
		return self.cache[ck]

	def hasTexture(self, name):
		for nt in self.noeTex:
			if nt.name == name:
				return True
		return False

	#returns (texName, uvTransform, frame, txp) for a frame hash, creating the NoeTexture on first use.
	#page=True maps onto the whole stored texture page instead of the cropped frame
	def resolve(self, primaryHash, frameHash, page = False):
		key = (primaryHash, frameHash, page)
		if key in self.byHash:
			return self.byHash[key]
		t, f = self.findFrame(primaryHash, frameHash)
		res = None
		if f is not None:
			if page:
				tx = t.textures[f.tex]
				name = "%s_page%02d_p%02d%s" % (t.name, f.tex, f.palette, "_n" if (f.flags & 1) else "")
				if not self.hasTexture(name):
					cache = self.decoded(t, f)
					k = (f.tex, f.palette)
					if k not in cache:
						cache[k] = mpoDecodeTexture(t, tx, f.palette)
					self.noeTex.append(mpoMakeNoeTexture(name, tx.bufWidth, tx.height, cache[k], f))
				res = (name, mpoPageUVTransform(t, f), f, t)
			else:
				name = "%s_%02d_%06x" % (t.name, f.index, f.hash)
				if not self.hasTexture(name):
					w, h, rgba = mpoDecodeFrame(t, f, self.decoded(t, f))
					self.noeTex.append(mpoMakeNoeTexture(name, w, h, rgba, f))
				res = (name, mpoFrameUVTransform(t, f), f, t)
		self.byHash[key] = res
		return res


#sampling state of a frame: flag 1 = nearest filter, flag 2 = repeat (otherwise clamp)
def mpoMakeNoeTexture(name, w, h, rgba, f):
	tex = NoeTexture(name, w, h, rgba, noesis.NOESISTEX_RGBA32)
	fl = 0
	if f is not None:
		fl |= noesis.NTEXFLAG_WRAP_REPEAT if (f.flags & 2) else noesis.NTEXFLAG_WRAP_CLAMP
		if f.flags & 1:
			fl |= noesis.NTEXFLAG_FILTER_NEAREST
	tex.setFlags(fl)
	return tex


def mpoColor(c):
	return NoeVec4([(c & 0xFF) / 255.0, ((c >> 8) & 0xFF) / 255.0, ((c >> 16) & 0xFF) / 255.0, ((c >> 24) & 0xFF) / 255.0])


#builds (or reuses) the Noesis material for a game material + per draw call state.
#res is the resolved texture (texName, uvTransform, frame, txp) or None
def mpoGetMaterial(ctx, mat, res, twoSided, vtxAlpha):
	texName = res[0] if res is not None else ""
	frame = res[2] if res is not None else None
	key = (mat.offset if mat else -1, texName, twoSided, vtxAlpha)
	if key in ctx.matByKey:
		return ctx.matByKey[key]
	name = "mat%02d" % (mat.index if mat else 99)
	if mat is not None:
		name += "_%06x" % mat.texHash
	if "_page" in texName:
		name += "_page"
	if not twoSided:
		name += "_1s"
	if vtxAlpha:
		name += "_va"
	nm = NoeMaterial(name, texName)
	flags = 0
	if twoSided:
		flags |= noesis.NMATFLAG_TWOSIDED
	unlit = 0
	if mat is not None:
		dif = mpoColor(mat.diffuse | 0xFF000000)
		nm.setDiffuseColor(dif)
		nm.setAmbientColor(mpoColor(mat.ambient | 0xFF000000))
		spc = mpoColor(mat.specular)
		#the game clamps the specular power to at least 2.0 (FUN_0004aa1c)
		nm.setSpecularColor(NoeVec4([spc[0], spc[1], spc[2], max(2.0, mat.power)]))
	blend = None
	#alpha test GU_GREATER (FUN_0004504c): reference 0, or 0x7F for blended frames with flag 0x1000.
	#noesis keeps alpha >= value, so the value is ref + 1
	alphaRef = 0
	if frame is not None:
		ff = frame.flags
		if ff & 8:
			#GU_TFX_REPLACE: the texture colour is used as is
			unlit = 1
		if (ff & 0x300) == 0x100:
			#environment (sphere) map overlay pass: the game adds the env-mapped texture (generated texture
			#coordinates) on top of the surface, so only the reflection must contribute
			nm.setEnvTexture(texName)
			nm.setTexture("")
			nm.setDiffuseColor(NoeVec4([0.0, 0.0, 0.0, 1.0]))
			nm.setEnvColor(NoeVec4([1.0, 1.0, 1.0, 1.0]))
			blend = ("GL_ONE", "GL_ONE")
		else:
			m70 = ff & 0x70
			if m70 == 0x10:
				blend = ("GL_SRC_ALPHA", "GL_ONE_MINUS_SRC_ALPHA")
			elif m70 == 0x20:
				blend = ("GL_SRC_ALPHA", "GL_ONE")
			elif m70 == 0x30:
				#reverse subtract (dst - src*alpha) has no Noesis equivalent; darken by the source instead
				blend = ("GL_ZERO", "GL_ONE_MINUS_SRC_COLOR")
		if blend is not None and (ff & 0x1000):
			alphaRef = 0x7F
	if blend is None and vtxAlpha:
		#faces with translucent vertex colours (draw routine FUN_00045410), alpha test unchanged
		blend = ("GL_SRC_ALPHA", "GL_ONE_MINUS_SRC_ALPHA")
	if blend is not None:
		nm.setBlendMode(blend[0], blend[1])
	else:
		nm.setDefaultBlend(0)
	if frame is not None:
		nm.setAlphaTest((alphaRef + 1) / 255.0)
	nm.setFlags(flags, unlit)
	ctx.materials.append(nm)
	ctx.matByKey[key] = nm
	return nm


class MpoBuildCtx:
	pass


def mpoBoneName(h):
	return "b_%06x" % (h & 0xFFFFFF)


def mpoNormalize3(v):
	x, y, z = v
	l = math.sqrt(x * x + y * y + z * z)
	if l <= 0.0:
		return (0.0, 1.0, 0.0)
	return (x / l, y / l, z / l)


#true when a clamped (non repeating) frame is sampled outside its own rectangle by these vertices
def mpoLeavesFrame(res, uv, indices):
	su, sv, bu, bv = res[1]
	f = res[2]
	if f.flags & 2:
		return False
	eps = 0.01 / max(1, f.width)
	epsv = 0.01 / max(1, f.height)
	for i in indices:
		t = uv[i]
		u = t[0] * (1.0 / 4096.0) * su + bu
		v = t[1] * (1.0 / 4096.0) * sv + bv
		if u < -eps or u > 1.0 + eps or v < -epsv or v > 1.0 + epsv:
			return True
	return False


#commits all draw calls of a model to the active rpg context
def mpoCommitModel(ctx, m, fixWinding):
	for ob in m.objects:
		calls = mpoObjectDrawCalls(m, ob)
		if not calls:
			continue
		#backface culling: object flag 0x20 on rigid models (FUN_00045410). skinned models are drawn without
		#culling (FUN_00045ea4 only culls for special instance states)
		culled = (ob.flags & 0x20) != 0
		twoSided = (not culled) or bool(m.bones)
		meshName = "o%03d_%06x" % (ob.index, ob.hash & 0xFFFFFF)
		pal = ob.palette
		npal = len(pal) if m.bones else 0
		ofs = ob.pos if not m.bones else (0.0, 0.0, 0.0)
		sc = m.scale
		for fc, va, idx, shared in calls:
			pos, nrm, uv, clr, wgt = va
			tris = mpoStripToTris(idx)
			#drop zero-area triangles produced by repeated vertices (strip stitching)
			ft = []
			for k in range(0, len(tris), 3):
				a = tris[k]
				b = tris[k + 1]
				c = tris[k + 2]
				pa = pos[a]
				pb = pos[b]
				pc = pos[c]
				if pa == pb or pb == pc or pa == pc:
					continue
				if fixWinding and not culled:
					#geometry authored without culling has arbitrary winding: orient it by its vertex normals
					ux = pb[0] - pa[0]; uy = pb[1] - pa[1]; uz = pb[2] - pa[2]
					vx = pc[0] - pa[0]; vy = pc[1] - pa[1]; vz = pc[2] - pa[2]
					nx = uy * vz - uz * vy; ny = uz * vx - ux * vz; nz = ux * vy - uy * vx
					na = nrm[a]; nb = nrm[b]; nc = nrm[c]
					if nx * (na[0] + nb[0] + nc[0]) + ny * (na[1] + nb[1] + nc[1]) + nz * (na[2] + nb[2] + nc[2]) < 0:
						b, c = c, b
				ft.append(a)
				ft.append(b)
				ft.append(c)
			if not ft:
				continue
			#compact vertex set used by this draw call
			remap = {}
			order = []
			for i in ft:
				if i not in remap:
					remap[i] = len(order)
					order.append(i)
			mat = fc.material
			#the game (FUN_0004aa1c) enables alpha blending for a face when any vertex it references has alpha != 0xFF
			vtxAlpha = False
			if clr is not None:
				for i in idx:
					if clr[i][3] != 255:
						vtxAlpha = True
						break
			res = ctx.texlib.resolve(m.txpHash, mat.texHash) if (mat is not None and mat.texHash) else None
			if res is not None and mpoLeavesFrame(res, uv, order):
				res = ctx.texlib.resolve(m.txpHash, mat.texHash, True)
			nm = mpoGetMaterial(ctx, mat, res, twoSided, vtxAlpha)
			if res is not None:
				su, sv, bu, bv = res[1]
			else:
				su = sv = 1.0
				bu = bv = 0.0
			#GU_TFX_REPLACE frames ignore the vertex colour
			useClr = clr is not None and not (res is not None and (res[2].flags & 8))
			fp = []
			fn = []
			fu = []
			for i in order:
				p = pos[i]
				fp.append(p[0] * sc + ofs[0])
				fp.append(p[1] * sc + ofs[1])
				fp.append(p[2] * sc + ofs[2])
				n = mpoNormalize3(nrm[i])
				fn.extend(n)
				t = uv[i]
				fu.append(t[0] * (1.0 / 4096.0) * su + bu)
				fu.append(t[1] * (1.0 / 4096.0) * sv + bv)
			nv = len(order)
			rapi.rpgSetName(meshName)
			rapi.rpgSetMaterial(nm.name)
			rapi.rpgBindPositionBuffer(noePack("<%df" % (nv * 3), *fp), noesis.RPGEODATA_FLOAT, 12)
			rapi.rpgBindNormalBuffer(noePack("<%df" % (nv * 3), *fn), noesis.RPGEODATA_FLOAT, 12)
			rapi.rpgBindUV1Buffer(noePack("<%df" % (nv * 2), *fu), noesis.RPGEODATA_FLOAT, 8)
			if useClr:
				cb = bytearray()
				for i in order:
					cb += clr[i]
				rapi.rpgBindColorBuffer(bytes(cb), noesis.RPGEODATA_UBYTE, 4, 4)
			if npal:
				bi = bytearray()
				bw = []
				pb = bytes(bytearray(pal))
				for i in order:
					bi += pb
					w = wgt[i]
					for j in range(npal):
						bw.append(w[j] / 128.0)
				rapi.rpgBindBoneIndexBuffer(bytes(bi), noesis.RPGEODATA_UBYTE, npal, npal)
				rapi.rpgBindBoneWeightBuffer(noePack("<%df" % len(bw), *bw), noesis.RPGEODATA_FLOAT, npal * 4, npal)
			ib = noePack("<%dI" % len(ft), *[remap[i] for i in ft])
			rapi.rpgCommitTriangles(ib, noesis.RPGEODATA_UINT, len(ft), noesis.RPGEO_TRIANGLE, 1)
			rapi.rpgClearBufferBinds()


def mpoMakeBones(m):
	bones = []
	for b in m.bones:
		mat = NoeMat43()
		mat[3] = NoeVec3((b.world[0], b.world[1], b.world[2]))
		pn = mpoBoneName(m.bones[b.parent].hash) if b.parent >= 0 else None
		bones.append(NoeBone(b.index, mpoBoneName(b.hash), mat, pn, b.parent))
	return bones


def mpoParseIndexList(s, count):
	out = []
	for part in s.split(","):
		part = part.strip()
		if not part:
			continue
		if "-" in part:
			a, b = part.split("-", 1)
			a = int(a)
			b = int(b)
			out.extend(range(a, b + 1))
		else:
			out.append(int(part))
	return [i for i in out if 0 <= i < count]


#motion tracks are applied by bone index (FUN_0007e0a8 / FUN_0007edac); bones past the motion's bone count keep an
#identity rotation. a motion archive therefore fits a model whose skeleton starts with the archive's bone list
#(e.g. Metal Gear's 61-bone motions on its 63-bone model)
def mpoSkeletonMatches(m, mt):
	n = len(mt.boneHashes)
	if n == 0 or n > len(m.bones):
		return False
	for i in range(n):
		if m.bones[i].hash != mt.boneHashes[i]:
			return False
	return True


#the game's quaternions are standard Hamilton rotations (VFPU vqmul, parent * child). Noesis' quaternions rotate the
#opposite way (NoeQuat.toMat43 + NoeMat43.transformPoint apply the inverse rotation, the same reason Noesis' UE4
#importer negates x/y/z), so keys are passed as the conjugate
def mpoNoeQuat(q):
	return NoeQuat((-q[0], -q[1], -q[2], q[3]))


#converts a sampled motion into a NoeKeyFramedAnim for the model's skeleton
def mpoMakeAnim(name, m, smp, bones, inPlace, rootMotion):
	frames = smp.frames
	kfBones = []
	tEnd = frames / MPO_FPS
	for bi, b in enumerate(m.bones):
		kb = NoeKeyFramedBone(bi)
		rot = smp.rot[bi]
		if rot is not None:
			keys = []
			last = None
			for f in range(frames):
				q = rot[f]
				#drop keys inside runs of identical values (exact for any interpolation)
				if last is not None and q == last and f + 1 < frames and rot[f + 1] == q:
					continue
				keys.append(NoeKeyFramedValue(f / MPO_FPS, mpoNoeQuat(q)))
				last = q
			keys.append(NoeKeyFramedValue(tEnd, mpoNoeQuat(rot[frames - 1])))
			kb.setRotation(keys)
		trn = None
		if b.parent < 0 and rootMotion and smp.rootHalf is not None:
			r = smp.rootHalf
			x0 = r[0][0]
			z0 = r[0][2]
			trn = []
			for f in range(frames):
				if inPlace:
					trn.append((b.local[0], b.local[1] + r[f][1], b.local[2]))
				else:
					trn.append((b.local[0] + r[f][0] - x0, b.local[1] + r[f][1], b.local[2] + r[f][2] - z0))
		elif smp.trn[bi] is not None:
			t = smp.trn[bi]
			trn = [(b.local[0] + t[f][0], b.local[1] + t[f][1], b.local[2] + t[f][2]) for f in range(frames)]
		if trn is not None:
			keys = []
			last = None
			for f in range(frames):
				v = trn[f]
				if last is not None and v == last and f + 1 < frames and trn[f + 1] == v:
					continue
				keys.append(NoeKeyFramedValue(f / MPO_FPS, NoeVec3(v)))
				last = v
			keys.append(NoeKeyFramedValue(tEnd, NoeVec3(trn[frames - 1])))
			kb.setTranslation(keys)
		if kb.hasAnyKeys():
			kfBones.append(kb)
	if not kfBones:
		return None
	return NoeKeyFramedAnim(name, bones, kfBones, MPO_FPS)


#loads animations from the given mtar files for the model
def mpoLoadAnims(m, bones, mtarPaths, motionSel = None):
	anims = []
	parents = [b.parent for b in m.bones]
	inPlace = mpoOpt("-mpoinplace")
	rootMotion = not mpoOpt("-mponoroot")
	for p in mtarPaths:
		try:
			d = rapi.loadIntoByteArray(p) if MPO_NOESIS else open(p, "rb").read()
			mt = mpoParseMtar(d)
		except Exception:
			mt = None
		if mt is None or not mpoSkeletonMatches(m, mt):
			continue
		base = mpoBaseName(p)
		sel = range(len(mt.motions)) if motionSel is None else mpoParseIndexList(motionSel, len(mt.motions))
		for i in sel:
			try:
				smp = mpoSampleMotion(mt, i, parents)
			except Exception as e:
				mpoLog("%s motion %d: %s" % (base, i, repr(e)))
				continue
			nm = "%s_%03d_%06x" % (base, i, smp.header.hash & 0xFFFFFF)
			a = mpoMakeAnim(nm, m, smp, bones, inPlace, rootMotion)
			if a is not None:
				anims.append(a)
	return anims


def mpoFindTextures(texlib, path):
	for folder in mpoSearchFolders(path):
		for p in mpoListFiles(folder, ".txp"):
			texlib.addFile(p)


def mpoFindMtars(path, m):
	out = []
	mode = mpoOptArg("-mpoanims")
	if mode is not None and mode.lower() == "none":
		return out
	want = None
	if mode is not None and mode.lower() != "all":
		want = set(x.strip().lower() for x in mode.split(",") if x.strip())
	cands = []
	for folder in mpoSearchFolders(path):
		cands.extend(mpoListFiles(folder, ".mtar"))
	#extra animation source: -mpoanimpath <file or folder>, or the folder set via the Tools menu
	extra = mpoOptArg("-mpoanimpath") or mpoSettings.get("animPath")
	if extra:
		extra = extra.strip().strip('"')
		if os.path.isfile(extra):
			cands.append(extra)
		elif os.path.isdir(extra):
			cands.extend(mpoListFiles(extra, ".mtar"))
	seen = set()
	for p in cands:
		k = os.path.normcase(os.path.abspath(p))
		if k in seen:
			continue
		seen.add(k)
		if want is not None and os.path.basename(p).lower() not in want and mpoBaseName(p).lower() not in want:
			continue
		out.append(p)
	return out


def mpoBuildModel(m, path, mtarPaths, motionSel = None):
	ctx = MpoBuildCtx()
	ctx.mdp = m
	ctx.texlib = MpoTexLib()
	ctx.materials = []
	ctx.matByKey = {}
	mpoFindTextures(ctx.texlib, path)
	rctx = rapi.rpgCreateContext()
	rapi.rpgSetOption(noesis.RPGOPT_TRIWINDBACKWARD, 0)
	mpoCommitModel(ctx, m, not mpoOpt("-mpokeepwinding"))
	mdl = rapi.rpgConstructModel()
	bones = []
	if m.bones:
		bones = mpoMakeBones(m)
		mdl.setBones(bones)
		if mtarPaths:
			anims = mpoLoadAnims(m, bones, mtarPaths, motionSel)
			if anims:
				mdl.setAnims(anims)
				rapi.setPreviewOption("setAnimSpeed", str(MPO_FPS))
	mdl.setModelMaterials(NoeModelMaterials(ctx.texlib.noeTex, ctx.materials))
	rapi.rpgReset()
	return mdl


def mpoCheckMdp(data):
	return 1 if mpoParseMdp(data) is not None else 0


def mpoLoadMdp(data, mdlList):
	t0 = time.time()
	m = mpoParseMdp(data)
	if m is None:
		return 0
	path = rapi.getInputName()
	mtars = mpoFindMtars(path, m) if m.bones else []
	mdl = mpoBuildModel(m, path, mtars, mpoOptArg("-mpomotions"))
	mdlList.append(mdl)
	mpoLog("model %s: %d objects, %d bones, %d meshes, %d textures, %d animations (%.1fs)" % (os.path.basename(path), len(m.objects), len(m.bones), len(mdl.meshes), len(mdl.modelMats.texList), len(mdl.anims), time.time() - t0))
	return 1


def mpoCheckTxp(data):
	return 1 if mpoParseTxp(data) is not None else 0


def mpoLoadTxp(data, texList):
	t = mpoParseTxp(data)
	if t is None:
		return 0
	name = mpoBaseName(rapi.getInputName())
	cache = {}
	for f in t.frames:
		try:
			w, h, rgba = mpoDecodeFrame(t, f, cache)
		except Exception as e:
			mpoLog("frame %d: %s" % (f.index, repr(e)))
			continue
		texList.append(mpoMakeNoeTexture("%s_%02d_%06x" % (name, f.index, f.hash), w, h, rgba, f))
	if not t.frames:
		#no frames: show the raw textures
		for tx in t.textures:
			try:
				rgba = mpoDecodeTexture(t, tx, 0)
			except Exception as e:
				mpoLog("texture %d: %s" % (tx.index, repr(e)))
				continue
			texList.append(mpoMakeNoeTexture("%s_t%02d" % (name, tx.index), tx.bufWidth, tx.height, rgba, None))
	return 1


def mpoCheckMtar(data):
	return 1 if mpoParseMtar(data) is not None else 0


#cheap skeleton test without parsing the whole model
def mpoMdpBoneHashes(d):
	if len(d) < 0x50 or d[0:4] != b"MDP ":
		return None
	nb = mpoU32(d, 4)
	bo = mpoU32(d, 0x14)
	if nb == 0 or nb > 255 or bo + nb * 0x50 > len(d):
		return None
	return [mpoU32(d, bo + i * 0x50) for i in range(nb)]


def mpoFindModelForMtar(mt, path):
	folders = mpoSearchFolders(path)
	#then the sibling folders (e.g. the other pages of an extracted slot.dat)
	parent = os.path.dirname(os.path.dirname(os.path.abspath(path)))
	try:
		for n in sorted(os.listdir(parent)):
			p = os.path.join(parent, n)
			if os.path.isdir(p) and p not in folders:
				folders.append(p)
	except Exception:
		pass
	want = mt.boneHashes
	for folder in folders:
		for p in mpoListFiles(folder, ".mdp"):
			try:
				f = open(p, "rb")
				d = f.read()
				f.close()
			except Exception:
				continue
			bh = mpoMdpBoneHashes(d)
			if bh is None or len(bh) < len(want) or bh[:len(want)] != want:
				continue
			m = mpoParseMdp(bytearray(d))
			if m is not None and m.bones and mpoSkeletonMatches(m, mt):
				return m, p
	return None, None


#an opened .mtar is shown on the first model (own folder first, then sibling folders) whose skeleton matches it
def mpoLoadMtar(data, mdlList):
	t0 = time.time()
	mt = mpoParseMtar(data)
	if mt is None:
		return 0
	path = rapi.getInputName()
	m, p = mpoFindModelForMtar(mt, path)
	if m is None:
		noesis.messagePrompt("No model with a matching skeleton was found for this motion archive.\n"
			"The .mdp it belongs to must be in the same folder or a sibling folder (extract the whole archive).")
		return 0
	mdl = mpoBuildModel(m, p, [path], mpoOptArg("-mpomotions"))
	mdlList.append(mdl)
	mpoLog("motion archive %s shown on %s: %d animations (%.1fs)" % (os.path.basename(path), p, len(mdl.anims), time.time() - t0))
	return 1


#=====================================================================================================
# Noesis registration and tools
#=====================================================================================================

def registerNoesisTypes():
	h = noesis.register("MGS Portable Ops Slot Archive", ".dat")
	noesis.setHandlerExtractArc(h, mpoExtractSlot)
	noesis.addOption(h, "-mpohexnames", "name extracted slot files by hash.", 0)

	h = noesis.register("MGS Portable Ops Stage Archive (renamed _zar)", ".zar")
	noesis.setHandlerExtractArc(h, mpoExtractZar)
	noesis.addOption(h, "-mpoarcraw", "don't unpack nested .dar/.qar archives.", 0)

	h = noesis.register("MGS Portable Ops DAR Archive", ".dar")
	noesis.setHandlerExtractArc(h, mpoExtractDar)
	noesis.addOption(h, "-mpoarcraw", "don't unpack nested .dar/.qar archives.", 0)

	h = noesis.register("MGS Portable Ops QAR Texture Archive", ".qar")
	noesis.setHandlerExtractArc(h, mpoExtractQar)

	h = noesis.register("MGS Portable Ops Model", ".mdp")
	noesis.setHandlerTypeCheck(h, mpoCheckMdp)
	noesis.setHandlerLoadModel(h, mpoLoadMdp)
	mpoAddModelOptions(h)

	h = noesis.register("MGS Portable Ops Motion Archive", ".mtar")
	noesis.setHandlerTypeCheck(h, mpoCheckMtar)
	noesis.setHandlerLoadModel(h, mpoLoadMtar)
	mpoAddModelOptions(h)

	h = noesis.register("MGS Portable Ops Texture", ".txp")
	noesis.setHandlerTypeCheck(h, mpoCheckTxp)
	noesis.setHandlerLoadRGBA(h, mpoLoadTxp)

	t = noesis.registerTool("Extract game data (slot.dat + all stages)...", mpoToolExtractGame, "Extract slot.dat and every stage archive of an MGS Portable Ops (Plus) game folder.")
	noesis.setToolSubMenuName(t, "MGS Portable Ops")
	t = noesis.registerTool("Extract stage archive(s) (_zar)...", mpoToolExtractStages, "Extract a stage _zar file, a stage folder or a whole stage directory.")
	noesis.setToolSubMenuName(t, "MGS Portable Ops")
	t = noesis.registerTool("Extract slot.dat...", mpoToolExtractSlot, "Extract a slot.dat archive into a folder.")
	noesis.setToolSubMenuName(t, "MGS Portable Ops")
	t = noesis.registerTool("Set extra animation folder...", mpoToolAnimFolder, "Also look for .mtar files in this folder when loading models (this session).")
	noesis.setToolSubMenuName(t, "MGS Portable Ops")
	return 1


def mpoToolAnimFolder(toolIndex):
	cur = mpoSettings.get("animPath") or ""
	r = noesis.userPrompt(noesis.NOEUSERVAL_STRING, "MGS Portable Ops - Extra animations", "Folder (or .mtar file) searched for motion archives in addition to the model's folder. Leave empty to disable:", cur, None)
	if r is None:
		return 0
	r = r.strip().strip('"')
	mpoSettings["animPath"] = r if r else None
	noesis.messagePrompt("Extra animation source: " + (r if r else "(none)"))
	return 0


def mpoAddModelOptions(h):
	noesis.addOption(h, "-mpoanims", "all (default), none, or comma separated .mtar names to load with the model.", noesis.OPTFLAG_WANTARG)
	noesis.addOption(h, "-mpomotions", "only load these motion indices (e.g. 0,2,5-7) from each .mtar.", noesis.OPTFLAG_WANTARG)
	noesis.addOption(h, "-mpoanimpath", "extra .mtar file or folder to take animations from.", noesis.OPTFLAG_WANTARG)
	noesis.addOption(h, "-mpoinplace", "remove the horizontal root motion (keep the root height).", 0)
	noesis.addOption(h, "-mponoroot", "don't apply the root motion channel at all.", 0)
	noesis.addOption(h, "-mpokeepwinding", "keep the original triangle winding of double-sided geometry.", 0)


def mpoFindStageArchives(root):
	out = []
	if os.path.isfile(root):
		return [root]
	for dirpath, dirnames, filenames in os.walk(root):
		dirnames.sort()
		for fn in sorted(filenames):
			if fn.lower() == "_zar" or fn.lower().endswith(".zar"):
				out.append(os.path.join(dirpath, fn))
	return out


def mpoStageNameFor(path):
	b = os.path.basename(path)
	if b.lower() == "_zar":
		return os.path.basename(os.path.dirname(os.path.abspath(path)))
	return mpoBaseName(path)


def mpoExtractStagesTo(archives, outDir):
	ok = 0
	files = 0
	for p in archives:
		try:
			raw = mpoReadFile(p)
			if not mpoIsZar(raw):
				mpoLog("not a stage archive: %s" % p)
				continue
			ex = MpoExporter(os.path.join(outDir, mpoStageNameFor(p)))
			mpoExportZarData(ex, raw, "", False)
			files += ex.count
			ok += 1
		except Exception as e:
			mpoLog("failed: %s: %s" % (p, repr(e)))
	return ok, files


#rapi is only initialised inside format handlers. tools must create a module and attach its rapi before calling
#rapi functions (decompression of stage archives uses rapi.decompInflate)
def mpoWithRapi(fn):
	mod = noesis.instantiateModule()
	noesis.setModuleRAPI(mod)
	try:
		return fn()
	finally:
		noesis.freeModule(mod)


def mpoAskFolder(title, prompt, initial = None):
	if initial is None:
		try:
			initial = noesis.getSelectedDirectory() or ""
		except Exception:
			initial = ""
	return noesis.userPrompt(noesis.NOEUSERVAL_FOLDERPATH, title, prompt, initial, None)


def mpoToolExtractStages(toolIndex):
	src = noesis.userPrompt(noesis.NOEUSERVAL_STRING, "MGS Portable Ops - Extract stages", "Stage _zar file, stage folder, or the USRDIR/stage folder:", noesis.getSelectedFile() or noesis.getSelectedDirectory() or "", None)
	if src is None:
		return 0
	src = src.strip().strip('"')
	archives = mpoFindStageArchives(src)
	if not archives:
		noesis.messagePrompt("No stage archives (_zar) found in:\n" + src)
		return 0
	out = mpoAskFolder("MGS Portable Ops - Extract stages", "Output folder (one sub folder per stage):")
	if out is None:
		return 0
	noesis.logPopup()
	ok, files = mpoWithRapi(lambda: mpoExtractStagesTo(archives, out))
	msg = "Extracted %d of %d stage archives (%d files) to\n%s" % (ok, len(archives), files, out)
	if ok < len(archives):
		msg += "\n\nSee the debug log for the archives that failed."
	noesis.messagePrompt(msg)
	return 0


def mpoToolExtractSlot(toolIndex):
	src = noesis.userPrompt(noesis.NOEUSERVAL_FILEPATH, "MGS Portable Ops - Extract slot.dat", "slot.dat file:", noesis.getSelectedFile() or "", None)
	if src is None:
		return 0
	size = os.path.getsize(src)
	if not mpoCheckSlotFile(src, size):
		noesis.messagePrompt("Not a MGS Portable Ops slot.dat:\n" + src)
		return 0
	out = mpoAskFolder("MGS Portable Ops - Extract slot.dat", "Output folder:")
	if out is None:
		return 0
	noesis.logPopup()
	ex = MpoExporter(out)
	n = mpoWithRapi(lambda: mpoExportSlot(ex, src, size))
	noesis.messagePrompt("Extracted %d files from %d pages to\n%s" % (ex.count, n, out))
	return 0


def mpoToolExtractGame(toolIndex):
	src = mpoAskFolder("MGS Portable Ops - Extract game data", "Game folder (the one containing PSP_GAME, or PSP_GAME/USRDIR):")
	if src is None:
		return 0
	usr = None
	for cand in (src, os.path.join(src, "USRDIR"), os.path.join(src, "PSP_GAME", "USRDIR")):
		if os.path.isfile(os.path.join(cand, "slot.dat")) or os.path.isdir(os.path.join(cand, "stage")):
			usr = cand
			break
	if usr is None:
		noesis.messagePrompt("slot.dat / stage folder not found below:\n" + src)
		return 0
	out = mpoAskFolder("MGS Portable Ops - Extract game data", "Output folder:")
	if out is None:
		return 0
	noesis.logPopup()
	msg = mpoWithRapi(lambda: mpoExtractGameTo(usr, out))
	noesis.messagePrompt("\n".join(msg) + "\n\nOutput: " + out)
	return 0


def mpoExtractGameTo(usr, out):
	msg = []
	sp = os.path.join(usr, "slot.dat")
	if os.path.isfile(sp) and mpoCheckSlotFile(sp, os.path.getsize(sp)):
		ex = MpoExporter(os.path.join(out, "slot"))
		n = mpoExportSlot(ex, sp, os.path.getsize(sp))
		msg.append("slot.dat: %d files from %d pages" % (ex.count, n))
	archives = mpoFindStageArchives(os.path.join(usr, "stage"))
	if archives:
		ok, files = mpoExtractStagesTo(archives, os.path.join(out, "stage"))
		line = "stages: %d of %d archives, %d files" % (ok, len(archives), files)
		if ok < len(archives):
			line += " (see the debug log for failures)"
		msg.append(line)
	return msg


#=====================================================================================================
# names of slot.dat resources (full resource hash -> name), recovered from the stage archive listings of both games
# (type id and 24-bit name hash must both match; only unambiguous names are listed)
#=====================================================================================================

MPO_NAMES = {
	0x08027945: "sna_wp_saa", 0x08027EF8: "sna_wp_tnt", 0x0802846D: "sna_wp_uzi", 0x08182321: "sna_wp_shield",
	0x084963A5: "sna_wp_gove", 0x084EE597: "sna_wp_rpg7", 0x085EA57B: "sna_wp_scorpion", 0x086BC12E: "sna_wp_knife",
	0x0875691B: "sna_wp_laser", 0x08856A4C: "sna_wp_dragnov", 0x088C6997: "sna_wp_mosin", 0x08A5C8F9: "sna_wp_machete",
	0x08D791EA: "sna_wp_ithaca", 0x08F05AAD: "sna_wp_sword", 0x09027945: "sna_wp_saa", 0x09027EF8: "sna_wp_tnt",
	0x0902846D: "sna_wp_uzi", 0x09182321: "sna_wp_shield", 0x094963A5: "sna_wp_gove", 0x094EE597: "sna_wp_rpg7",
	0x095EA57B: "sna_wp_scorpion", 0x096BC12E: "sna_wp_knife", 0x0975691B: "sna_wp_laser", 0x09856A4C: "sna_wp_dragnov",
	0x098C6997: "sna_wp_mosin", 0x09A5C8F9: "sna_wp_machete", 0x09D791EA: "sna_wp_ithaca", 0x09F05AAD: "sna_wp_sword",
	0x1101D832: "m16a_normal_model", 0x1101E3A9: "uzi", 0x11312E84: "p90_amo", 0x113163C5: "p90_p90",
	0x11383272: "mk22", 0x113CABE5: "remington_m870", 0x11412DBD: "m4a_amo", 0x1141568F: "m4a_m4a",
	0x114314C0: "bowie_knife", 0x11591D57: "cun_laser", 0x11612AF0: "aks_aks", 0x11612B2C: "aks_amo",
	0x11612C70: "fms_amo", 0x11612DBE: "m63_amo", 0x11612FAF: "smc_amo", 0x11614074: "fms_fms",
	0x116177A3: "smc_smc", 0x11649536: "mk23_amo", 0x116D846E: "ithaca_model", 0x116D9111: "akm_model",
	0x1177DA91: "m63_model", 0x117DE615: "mosin_nagant_model", 0x117F3E11: "saa_model", 0x11823CB6: "m16a_m203_model",
	0x118C0B95: "rpg7_rocket", 0x11920FA6: "ingram_M10", 0x1198975F: "mk23_mk23", 0x119BA8CE: "m1911a1_amo",
	0x11A200E3: "spetsnaz_knf_blade", 0x11A70CC9: "spetsnaz_knife", 0x11A96BF6: "m1911a1", 0x11B622D0: "shield",
	0x11B74B1E: "xm177", 0x11BC639F: "rpg7_model", 0x11C13049: "uzi_amo", 0x11DB2C8F: "svd_doragunov_model",
	0x11EC6769: "sv_knife", 0x11F6D54A: "scorpion_vz61_model", 0x130137A9: "gnm_def", 0x1301D832: "m16a_normal_model",
	0x1301E3A9: "uzi", 0x130BB24B: "wor_f_def", 0x13112E3D: "bdn_bdn", 0x131136B7: "cun_def",
	0x13113839: "ivn_def", 0x13113957: "nen_def", 0x131157F5: "cun_lod", 0x13115977: "ivn_lod",
	0x13115A95: "nen_lod", 0x13312E84: "p90_amo", 0x13313B5F: "vip_def", 0x13315C9D: "vip_lod",
	0x133163C5: "p90_p90", 0x13383272: "mk22", 0x133CABE5: "remington_m870", 0x13412DBD: "m4a_amo",
	0x13413AA8: "sna_def", 0x1341568F: "m4a_m4a", 0x134314C0: "bowie_knife", 0x13513BAB: "wor_def",
	0x13515CE9: "wor_lod", 0x13591D57: "cun_laser", 0x13612AF0: "aks_aks", 0x13612B2C: "aks_amo",
	0x13612C70: "fms_amo", 0x13612DBE: "m63_amo", 0x13612FAF: "smc_amo", 0x13613B69: "vns_def",
	0x13614074: "fms_fms", 0x13615CA7: "vns_lod", 0x136177A3: "smc_smc", 0x13649536: "mk23_amo",
	0x136D846E: "ithaca_model", 0x136D9111: "akm_model", 0x13713828: "ind_def", 0x13713916: "med_def",
	0x13713929: "mnt_def", 0x137139FF: "pyt_def", 0x13715966: "ind_lod", 0x13715A54: "med_lod",
	0x13715A67: "mnt_lod", 0x1377DA91: "m63_model", 0x137DE615: "mosin_nagant_model", 0x137F3E11: "saa_model",
	0x13813728: "ene_def", 0x13813738: "eve_def", 0x13815866: "ene_lod", 0x13815876: "eve_lod",
	0x13823CB6: "m16a_m203_model", 0x138C0B95: "rpg7_rocket", 0x13920FA6: "ingram_M10", 0x1398975F: "mk23_mk23",
	0x139B4A8B: "gbs_p_def", 0x139BA8CE: "m1911a1_amo", 0x139CD68B: "htc_p_def", 0x13A13A9E: "sig_def",
	0x13A15BDC: "sig_lod", 0x13A200E3: "spetsnaz_knf_blade", 0x13A70CC9: "spetsnaz_knife", 0x13A760CB: "sel_p_def",
	0x13A8A78B: "tng_p_def", 0x13A96BF6: "m1911a1", 0x13B1376B: "fox_def", 0x13B158A9: "fox_lod",
	0x13B622D0: "shield", 0x13B74B1E: "xm177", 0x13BC639F: "rpg7_model", 0x13C13049: "uzi_amo",
	0x13C13A6B: "roy_def", 0x13C15BA9: "roy_lod", 0x13DB2C8F: "svd_doragunov_model", 0x13E13AAA: "sok_def",
	0x13E13AF0: "trk_def", 0x13E15BE8: "sok_lod", 0x13E15C2E: "trk_lod", 0x13EC6769: "sv_knife",
	0x13F13976: "nul_def", 0x13F6D54A: "scorpion_vz61_model", 0x13F9A70A: "ene_f_def", 0x1401D832: "m16a_normal_model",
	0x1401E3A9: "uzi", 0x141157F5: "cun_lod", 0x14115977: "ivn_lod", 0x1415C13F: "ind_def_bc",
	0x1415D9B2: "moshinnagan_0", 0x141E113F: "ivn_def_bc", 0x1420113A: "bdn_bdn_bc", 0x14270E7C: "wor_f_def_bc",
	0x14312E84: "p90_amo", 0x14315C9D: "vip_lod", 0x143163C5: "p90_p90", 0x143468FB: "rpg7_0",
	0x14376940: "roy_def_bc", 0x14383272: "mk22", 0x143CABE5: "remington_m870", 0x14412DBD: "m4a_amo",
	0x1441568F: "m4a_m4a", 0x144314C0: "bowie_knife", 0x14475648: "gbs_p_def_bc", 0x1447570E: "htc_p_def_bc",
	0x1450D940: "sig_def_bc", 0x14515CE9: "wor_lod", 0x1456F940: "sok_def_bc", 0x14591D57: "cun_laser",
	0x145D113E: "cun_def_bc", 0x14612AF0: "aks_aks", 0x14612B2C: "aks_amo", 0x14612C70: "fms_amo",
	0x14612FAF: "smc_amo", 0x14614074: "fms_fms", 0x14615CA7: "vns_lod", 0x146177A3: "smc_smc",
	0x14649536: "mk23_amo", 0x14675C53: "sel_p_def_bc", 0x146D846E: "ithaca_model", 0x14715966: "ind_lod",
	0x14715A54: "med_lod", 0x14715A67: "mnt_lod", 0x1479F940: "trk_def_bc", 0x147DE615: "mosin_nagant_model",
	0x147F3E11: "saa_model", 0x14815866: "ene_lod", 0x14815876: "eve_lod", 0x14823CB6: "m16a_m203_model",
	0x14870576: "ene_f_def_bc", 0x148C0B95: "rpg7_rocket", 0x148CC13F: "med_def_bc", 0x14920FA6: "ingram_M10",
	0x1495C93E: "ene_def_bc", 0x1496413F: "mnt_def_bc", 0x1498975F: "mk23_mk23", 0x149BA8CE: "m1911a1_amo",
	0x149DC93E: "eve_def_bc", 0x14A15BDC: "sig_lod", 0x14A200E3: "spetsnaz_knf_blade", 0x14A70CC9: "spetsnaz_knife",
	0x14A96BF6: "m1911a1", 0x14B12140: "vip_def_bc", 0x14B158A9: "fox_lod", 0x14B63940: "vns_def_bc",
	0x14B74B1E: "xm177", 0x14B7613E: "fox_def_bc", 0x14BC639F: "rpg7_model", 0x14BD013F: "nul_def_bc",
	0x14C13049: "uzi_amo", 0x14C15BA9: "roy_lod", 0x14C75CF6: "tng_p_def_bc", 0x14D6093E: "gnm_def_bc",
	0x14D73140: "wor_def_bc", 0x14DBF27F: "shield_Bclip", 0x14E15BE8: "sok_lod", 0x14E15C2E: "trk_lod",
	0x14EC6769: "sv_knife", 0x14F6D54A: "scorpion_vz61_model", 0x3702E97B: "segrp_8_paramedic", 0x371C2628: "segrp_93_e_hofficer_b_pow",
	0x3720277E: "segrp_51_mainte_pow", 0x372555F2: "segrp_68_campbell_pow", 0x372DBDBE: "segrp_54_eva_pow", 0x372F0D67: "segrp_23_teriko",
	0x372F86EA: "segrp_60_vinus_pow", 0x3730796A: "segrp_61_sokolov_pow", 0x3732BCDC: "segrp_26_e_hofficer", 0x3738B048: "segrp_27_e_women",
	0x373E6E22: "segrp_50_worker_pow", 0x3748D8F7: "segrp_53_wor_women_pow", 0x374F8F9B: "segrp_52_gofficer_pow", 0x3755B12F: "segrp_14_sokolov",
	0x3761B72C: "segrp_84_e_soviet_b", 0x376885CA: "segrp_12_sigint", 0x3769598D: "segrp_17_null1", 0x376959CE: "segrp_18_null2",
	0x376BD1BB: "segrp_3_eva", 0x376C0768: "segrp_56_pmedic_pow", 0x376E33F6: "segrp_46_e_fox_pow", 0x37717D0E: "segrp_85_e_hofficer_b",
	0x3778A8F9: "segrp_31_wor_women", 0x3787210C: "segrp_16_cunning", 0x37938057: "segrp_9_raicov", 0x37A41439: "segrp_30_gofficer",
	0x37A47F2D: "segrp_63_teriko_pow", 0x37B8F95B: "segrp_49_e_women_pow", 0x37BD6160: "segrp_94_e_women_b_pow", 0x37C13020: "segrp_86_e_women_b",
	0x37CE4973: "segrp_24_e_fox", 0x37CF3CB0: "segrp_28_worker", 0x37D027B5: "segrp_57_raicov_pow", 0x37D81A33: "segrp_59_sigint_pow",
	0x37DA9852: "segrp_25_e_soviet", 0x37E10AF7: "segrp_11_jene", 0x37E2F7DC: "segrp_47_e_soviet_pow", 0x37E361EF: "segrp_13_vinus",
	0x37E4DB7B: "segrp_83_e_fox_b", 0x37EA9DDD: "segrp_20_paison", 0x37EAD26E: "segrp_29_mainte", 0x37F17C0E: "segrp_91_e_fox_b_pow",
	0x37F47C34: "segrp_48_e_hofficer_pow", 0x37F76AB9: "segrp_92_e_soviet_b_pow", 0x5F3ACD17: "rpg7", 0x5F688573: "moshinnagan",
}
