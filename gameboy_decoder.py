from PIL import Image
from PIL.ImageFile import PyDecoder

MSB_FIRST = (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01)
BOOL2BYTE = {
	(False, False): 0b00,
	(False, True): 0b10,
	(True, False): 0b01,
	(True, True): 0b11,
}

class GameboyDecoder(PyDecoder):
	def decode(self, buffer) -> None:
		data = bytearray()
		for i in range(0, len(buffer), 2):
			b1 = buffer[i]
			b2 = buffer[i+1]
			
			for mask in MSB_FIRST:
				s1 = bool(b1 & mask)
				s2 = bool(b2 & mask)
				data.append(BOOL2BYTE[(s1, s2)])

		self.set_as_raw(bytes(data), "P")
		return -1, 0

Image.register_decoder("gameboy", GameboyDecoder)
