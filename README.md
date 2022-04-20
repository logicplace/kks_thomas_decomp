# Kikansha Thomas graphics decompressor

As the title says.

## Usage

Using the ROM with the MD5: `1a0aac7a746e247879d6b970bf9a9f32  Kikansha Thomas - Sodor-tou no Nakama-tachi (Japan).gbc`

Export all the graphics (assuming the filename above) with: `python3 kks_thomas_decomp.py -o out`

# config.yaml

## using

* `rom` - expected ROM filename
* `md5` - MD5 hash of ROM (not yet verified when running)

## tables

Entries in this dict are arbitrarily named and contain dicts of the following schema:

* `start` - start address of the pointer table in the ROM
* `entries` - list of entires in the table
	* If it's just a string, that's the name, and exports as bin
	* `name` - Name to export as, assumes `.bin` ext (you may also specify `.png`)
	* `addressing` - Addressing mode for tiles. Can be 8000 (default) or 8800.
	* `palette` - Specify the palette for this map, should be a list of 7 lists containing 4 two-byte hex codes (as specified in BGB's Palettes viewer).
