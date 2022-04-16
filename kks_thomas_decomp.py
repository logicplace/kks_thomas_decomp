#!/usr/bin/env python3
import sys
import argparse
from io import BytesIO
from pathlib import Path

LSB_FIRST_BITMASKS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)


def sp_int(i: str):
	if i.startswith("0x"):
		return int(i, 16)
	return int(i)


def ptr_to_rom(i: int):
	return ((i & 0xff0000) >> 2) - 0x4000 + (i & 0xffff)


class Decompressor:
	def __init__(self, rom: str):
		self.fd = open(rom, "rb")
		self.table = {}

	def __del__(self):
		self.fd.close()

	def read_table(self, start: int, end: int = 0, *, size: int = 0):
		# The table of the format:
		#  struct {
		#    uint_24 compressed_data_ptr
		#    uint_24 ram_write_location
		#  }[x];
		#  b'\xff\xff\xff'
		fd = self.fd
		fd.seek(start)
		if size:
			end = start + size
		
		while fd.tell() < end:
			entries = self.table[fd.tell()] = []
			while True:
				compressed_data_ptr = int.from_bytes(fd.read(3), "little")
				if compressed_data_ptr == 0xffffff:
					break
				ram_write_location = int.from_bytes(fd.read(3), "little")
				entries.append((compressed_data_ptr, ram_write_location))

		if fd.tell() != end:
			print(f"Warning: End of table (0x{fd.tell():06x}) came before expected end (0x{end:06x})", file=sys.stderr)

	def dump_table(self, fn: Path):
		with fn.open("wt", encoding="utf8") as f:
			f.write("Entry start,Compressed data ptr,RAM ptr")
			for loc, entries in sorted(self.table.items()):
				for cptr, rptr in entries:
					f.write(f"0x{loc:06x},0x{cptr:06x},0x{rptr:06x}")

	def dump_all_graphics(self, folder: Path):
		folder.mkdir(parents=True, exist_ok=True)
		for loc, entries in self.table.items():
			p = folder / f"entry_0x{loc:06x}"
			p.mkdir(exist_ok=True)
			for cptr, rptr in entries:
				res = self.decompress(ptr_to_rom(cptr))
				with (p / f"gfx_{rptr:06x}.bin").open("wb") as f:
					f.write(res)

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
			print(f"Warning: Unexpected decompressed stream length {len(d_buffer)} (expected {d_length})")

		return d_buffer


def main():
	parser = argparse.ArgumentParser(
		description="Decompress graphics from Kikanshi Thomas for GBC.")
	parser.add_argument("--out", "-o", type=Path, default="",
		help="Output file or folder.")
	parser.add_argument("--graphic", "-g", type=sp_int, default="0",
		help="Decompress a single tileset starting at this offset.")
	parser.add_argument("--table", "-t", default="",
		help="Decompress the entire graphics table specified by start-end like 0x10f3-0x13c0.")
	parser.add_argument("rom",
		help="Kikanshi Thomas .GBC file.")

	args = parser.parse_args()
	decomp = Decompressor(args.rom)

	if args.graphic:
		res = decomp.decompress(args.graphic)
		out: Path = args.out
		if out == Path():
			out /= "out.bin"

		if out.suffix == ".bin":
			with out.open("wb") as f:
				f.write(res)
		else:
			print(f"Unknown output filetype {out.suffix}")
	elif args.table:
		s_start, s_end = args.table.split("-")
		start = sp_int(s_start.strip())
		end = sp_int(s_end.strip())
		decomp.read_table(start, end)
		decomp.dump_all_graphics(args.out)
		decomp.dump_table(args.out / "table.csv")
	else:
		parser.print_help()

if __name__ == "__main__":
	main()
