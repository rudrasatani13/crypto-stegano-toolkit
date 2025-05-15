from PIL import Image

def _bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def hide_file_in_image(input_image_path, output_image_path, file_data: bytes):
    image = Image.open(input_image_path)
    if image.mode != 'RGB':
        image = image.convert('RGB')

    max_bytes = (image.width * image.height * 3) // 8 - 4
    if len(file_data) > max_bytes:
        raise ValueError(f"File too large to hide in image! Max bytes: {max_bytes}")

    # prepend length of data (4 bytes)
    length_bytes = len(file_data).to_bytes(4, 'big')
    data = length_bytes + file_data
    bits = _bytes_to_bits(data)

    pixels = list(image.getdata())
    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    image.save(output_image_path)

def extract_file_from_image(image_path) -> bytes:
    image = Image.open(image_path)
    pixels = list(image.getdata())

    bits = ""
    for pixel in pixels:
        for channel in pixel[:3]:
            bits += str(channel & 1)

    # read first 32 bits to get length
    length_bits = bits[:32]
    length = int(length_bits, 2)
    data_bits = bits[32:32 + (length * 8)]

    return _bits_to_bytes(data_bits)
