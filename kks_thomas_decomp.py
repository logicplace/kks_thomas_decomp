#!/usr/bin/env python3
import sys
import struct
import argparse
from io import BytesIO
from pathlib import Path
from typing import Any, Dict

import yaml

LSB_FIRST_BITMASKS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
PALETTE = b"".join([
	# https://mokole.com/palette.html
	# 32 colors, 5% <= luminosity <= 90%, 5000 loops
	# Palette 0
	b"\x69\x69\x69",  # Dim Gray
	b"\x55\x6b\x2f",  # Dark Olive Green
	b"\x80\x00\x00",  # Maroon
	b"\x48\x3d\x8b",  # Dark Slate Blue

	# Palette 1
	b"\x00\x80\x00",  # Green
	b"\xb8\x86\x0b",  # Dark Goldenrod
	b"\x00\x8b\x8b",  # Dark Cyan
	b"\x9a\xcd\x32",  # Yellow-green

	# Palette 2
	b"\x00\x00\x8b",  # Dark Blue
	b"\x8f\xbc\x8f",  # Dark Sea Green
	b"\x8b\x00\x8b",  # Dark Magenta
	b"\xb0\x30\x60",  # Maroon 3

	# Palette 3
	b"\xff\x45\x00",  # Orange-red
	b"\xff\x8c\x00",  # Dark orange
	b"\xff\xd7\x00",  # Gold
	b"\xde\xb8\x87",  # Burlywood

	# Palette 4
	b"\x7f\xff\x00",  # Chartreuse
	b"\x94\x00\xd3",  # Dark Violet
	b"\x00\xff\x7f",  # Spring Green
	b"\xdc\x14\x3c",  # Crimson

	# Palette 5
	b"\x00\xff\xff",  # Aqua
	b"\x00\xbf\xff",  # Deep Sky Blue
	b"\x00\x00\xff",  # Blue
	b"\xda\x70\xd6",  # Orchid

	# Palette 6
	b"\xff\x00\xff",  # Fuchsia
	b"\x1e\x90\xff",  # Dodger Blue
	b"\xfa\x80\x72",  # Salmon
	b"\x90\xee\x90",  # Light Green

	# Palette 7
	b"\xad\xd8\xe6",  # Light Blue
	b"\xff\x14\x93",  # Deep Pink
	b"\x7b\x68\xee",  # Medium Slate Blue
	b"\xff\xb6\xc1",  # Light Pink
])


class ProgramError(Exception): pass
def warn(warning):
	print(f"Warning: {warning}", file=sys.stderr)


def sp_int(i: str):
	if i.startswith("0x"):
		return int(i, 16)
	return int(i)


def ptr_to_rom(i: int):
	return ((i & 0xff0000) >> 2) - 0x4000 + (i & 0xffff)


def gb_palette_int_to_bytes(i: int):
	red = (i & 0x001F) * 255 // 0x1F
	green = ((i & 0x03E0) >> 5) * 255 // 0x1F
	blue = ((i & 0x7C00) >> 10) * 255 // 0x1F

	return bytes((red, green, blue))

class Decompressor:
	def __init__(self, rom: str):
		self.fd = open(rom, "rb")
		self.table: Dict[str, Dict[int, int]] = {}
		self.info: Dict[str, Dict[str, Any]] = {}

	def __del__(self):
		self.fd.close()

	def clear_table(self):
		self.table.clear()
		self.info.clear()

	def read_table(self, start: int, names=()):
		# The table pointed to is just a series of 2-byte absolute pointers
		# The table it points into is of the format:
		#  struct {
		#    uint_24 compressed_data_ptr
		#    uint_24 ram_write_location
		#  }[x];
		#  b'\xff\xff\xff'
		fd = self.fd
		fd.seek(start)

		if isinstance(names, int):
			count = names
			names = [f"unk_{i}" for i in range(1, count + 1)]
		else:
			count = len(names)

		addresses = struct.unpack(f"<{count}H", fd.read(count * 2))

		for name, address in zip(names, addresses):
			fd.seek(address)
	
			if isinstance(name, dict):
				info = name
				name = info["name"]
				self.info[name] = info
				if "palette" in info:
					# Assume List[List[int]]
					info["palette"] = b"".join(
						gb_palette_int_to_bytes(x)
						for x in sum(info["palette"], [])
					)
			else:
				self.info[name] = {}

			entries = self.table[name] = {}
			while True:
				compressed_data_ptr = int.from_bytes(fd.read(3), "little")
				if compressed_data_ptr == 0xffffff:
					break
				ram_write_location = int.from_bytes(fd.read(3), "little")
				if ram_write_location in entries:
					raise ProgramError(f"Duplicate entry {ram_write_location}")
				entries[ram_write_location] = compressed_data_ptr

	def dump_table(self, fn: Path):
		with fn.open("wt", encoding="utf8") as f:
			f.write("Entry name,Compressed data ptr,RAM ptr\n")
			for loc, entries in sorted(self.table.items()):
				for rptr, cptr in entries.items():
					f.write(f"{loc},0x{cptr:06x},0x{rptr:06x}\n")

	def dump_all_data(self, folder: Path):
		folder.mkdir(parents=True, exist_ok=True)
		for name, entries in self.table.items():
			info = self.info[name]
			if "." in name:
				name, ext = name.split(".", 1)
			else:
				ext = "bin"

			p = folder / name
			p.mkdir(exist_ok=True)

			if ext == "bin":
				self._dump_bins(entries, p)
			elif ext == "png":
				self._dump_png(info, entries, p)

	def _dump_bins(self, entries: Dict[int, int], p: Path):
		for rptr, cptr in entries.items():
			res = self.decompress(ptr_to_rom(cptr))
			rptr_ub = rptr & 0xFFFF
			if 0x8000 <= rptr_ub < 0x9800:
				pfx = "gfx"
			elif 0x9800 <= rptr_ub < 0xA000:
				pfx = "map"
			else:
				pfx = "unk"
			with (p / f"{pfx}_{rptr:06x}.bin").open("wb") as f:
				f.write(res)

	def _entries_to_ram(self, entries: Dict[int, int]):
		ram = [
			BytesIO(b"\0" * (0xA000 - 0x8000)),
			BytesIO(b"\0" * (0xA000 - 0x8000)),
		]

		set_blocks = [[False] * 5, [False] * 5]

		for rptr, cptr in entries.items():
			bank = (rptr & 0xff0000) >> 16
			cur_ram = ram[bank]
			address = rptr & 0xffff
			cur_ram.seek(address - 0x8000)
			res = self.decompress(ptr_to_rom(cptr))
			cur_ram.write(res)

			if 0x008000 <= address < 0x009800:
				set_blocks[bank][(address - 0x8000) // 0x0800] = True
			elif 0x009800 <= address < 0x00A000:
				set_blocks[bank][3 + (address - 0x9800) // 0x0400] = True

		return ram, set_blocks

	def _ram_to_tiledata(self, ram: BytesIO, blocks_to_extract):
		# Extract tiles from RAM as images
		from PIL import Image
		import gameboy_decoder

		blocks = [[[], [], []], [[], [], []]]
		for bank in (0, 1):
			cur_ram = ram[bank]
			cur_blocks = blocks[bank]
			for block, addr in enumerate((0x8000, 0x8800, 0x9000)):
				addr -= 0x8000
				if blocks_to_extract[bank][block]:
					cur_ram.seek(addr)
					cur_block = cur_blocks[block]
					for _ in range(128):
						tile = cur_ram.read(16)
						img = Image.frombytes("P", (8, 8), tile, "gameboy")
						cur_block.append(img)

		return blocks

	def _dump_png(self, info: dict, entries: Dict[int, int], p: Path):
		from PIL import Image

		ram, set_blocks = self._entries_to_ram(entries)
		tiles = self._ram_to_tiledata(ram, set_blocks)

		has_tileset0 = any(set_blocks[0][:3])
		#has_tileset1 = any(set_blocks[1][:3])
		has_tilemap = any(set_blocks[0][-2:])

		if has_tilemap:
			# Read the tilemaps to build the PNG
			method = info.get("addressing", 8000)
			palette = info.get("palette", PALETTE)
			assert method in (8000, 8800)
			for addr, i in ((0x9800, -2), (0x9C00, -1)):
				addr -= 0x8000
				if set_blocks[0][i]:
					if set_blocks[1][i]:
						ram[1].seek(addr)
						cgb_map = ram[1].read(0x400)
					else:
						byte = b"\0" if has_tileset0 else b"\x08"
						cgb_map = byte * 0x400
					
					ram[0].seek(addr)
					tilemap = ram[0].read(0x400)
					bg = Image.new("P", (32 * 8, 32 * 8), 0)
					bg.putpalette(palette)
					above = bytearray()
					for idx, (tile, properties) in enumerate(zip(tilemap, cgb_map)):
						palette_idx = properties & 7
						bank = 1 if properties & 0x08 else 0
						h_flip = bool(properties & 0x20)
						v_flip = bool(properties & 0x40)
						above.append((properties & 0x80) >> 4)

						if tile < 0x80:
							block = 0 if method == 8000 else 2
						else:
							block = 1
							tile -= 0x80

						gfx: Image.Image = tiles[bank][block][tile]

						if h_flip:
							gfx = gfx.transpose(Image.FLIP_LEFT_RIGHT)
						if v_flip:
							gfx = gfx.transpose(Image.FLIP_TOP_BOTTOM)
						if palette_idx > 0:
							# Adjust palette indexes
							palette_idx *= 4
							if not h_flip and not v_flip:
								gfx = gfx.copy()
							gfx.putdata(list(x + palette_idx for x in gfx.getdata()))

						x = (idx % 32) * 8
						y = (idx // 32) * 8
						bg.paste(gfx, (x, y, x+8, y+8))
					bg.save(p / f"bank_{2+i}.png")

					with open(p / f"above_{2+i}.bin", "wb") as f:
						f.write(above)
		else:
			# Just dump the graphics RAM
			for bank, blocks in enumerate(tiles):
				im = Image.new("P", (16 * 8, 8 * 3 * 8), 0)
				im.putpalette(PALETTE)
				for top, block in zip((0, 8*8, 8*2*8), blocks):
					for idx, gfx in enumerate(block):
						x = (idx % 16) * 8
						y = top + (idx // 16) * 8
						im.paste(gfx, (x, y, x+8, y+8))
				im.save(p / f"bank_{bank}.png")

	def decompress(self, offset: int):
		fd = self.fd
		fd.seek(offset)
		d_length = int.from_bytes(fd.read(2), "little")
		c_length = int.from_bytes(fd.read(2), "little")
		c_buffer = BytesIO(fd.read(c_length))

		d_buffer = bytearray()
		while True:
			# Get the control byte
			check = c_buffer.read(1)
			if not check:
				break
			control_byte = check[0]

			for bit in LSB_FIRST_BITMASKS:
				if control_byte & bit:
					# Copy a literal byte
					d_buffer.append(c_buffer.read(1)[0])
				else:
					# Read in a copy sequence
					# Format: 0xOO OC
					#  Where O is the backwards offset (LE)
					#  and C is the number of bytes to copy, total
					check = c_buffer.read(1)
					if not check:
						# EOF
						break
					backset = check[0]

					check = c_buffer.read(1)
					if not check:
						# EOF
						break
					backset |= (check[0] & 0xf0) << 4
					backset += 1
					to_copy = (check[0] & 0x0f) + 3
					count = to_copy // backset
					trailing = to_copy % backset

					repeated = d_buffer[-backset:]
					trail = repeated[:trailing]

					d_buffer.extend(repeated * count)
					if trail:
						d_buffer.extend(trail)

		if len(d_buffer) != d_length:
			warn(f"Unexpected decompressed stream length {len(d_buffer)} (expected {d_length})")

		return d_buffer


def main():
	parser = argparse.ArgumentParser(
		description="Decompress graphics from Kikanshi Thomas for GBC.")
	parser.add_argument("--out", "-o", type=Path, default="",
		help="Output file or folder.")
	parser.add_argument("--decompress", "-d", type=sp_int, default="0",
		help="Decompress a single binary block starting at this offset.")
	parser.add_argument("--config", "-c", default="",
		help="Specify the config file.")
	parser.add_argument("--table", "-t", default="",
		help="Extract the specified table. (Default: all)")
	parser.add_argument("rom", type=Path, nargs="?", default="",
		help="Kikanshi Thomas .GBC file. If unspecified, tries the name in the config.")

	args = parser.parse_args()

	if args.config:
		config = Path(args.config)
	else:
		config = Path(__file__).with_name("config.yaml")
	with open(config, "rt", encoding="utf8") as f:
		config: dict = yaml.safe_load(f)
	
	rom: Path = args.rom
	if not rom.is_file():
		rom /= config.get("using", {}).get("rom")
	if not rom.is_file():
		raise ProgramError("ROM filename must be specified.")

	try:
		decomp = Decompressor(rom)
	except FileNotFoundError as err:
		raise ProgramError(f"ROM not found: {err.filename}") from None

	# TODO: check MD5

	if args.decompress:
		res = decomp.decompress(args.decompress)
		out: Path = args.out
		if out == Path():
			out /= "out.bin"

		if out.suffix == ".bin":
			with out.open("wb") as f:
				f.write(res)
		else:
			raise ProgramError(f"Unknown output filetype {out.suffix}")
	else:
		for name, table in config.get("tables", {}).items():
			if args.table and args.table != name:
				continue

			decomp.clear_table()
			decomp.read_table(table["start"], table["entries"])
			decomp.dump_all_data(args.out / name)
			decomp.dump_table(args.out / f"{name}.csv")

if __name__ == "__main__":
	try:
		main()
	except ProgramError as err:
		print(f"Error: {err}", file=sys.stderr)
		sys.exit(1)
	except (KeyboardInterrupt, EOFError):
		print("\nExecution stopped by user.")
		sys.exit(130)
