import wave

def _bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def hide_file_in_audio(audio_in, audio_out, file_data: bytes):
    with wave.open(audio_in, 'rb') as song:
        params = song.getparams()
        frames = bytearray(song.readframes(song.getnframes()))

    max_bytes = (len(frames) // 8) - 4
    if len(file_data) > max_bytes:
        raise ValueError(f"File too large to hide in audio! Max bytes: {max_bytes}")

    length_bytes = len(file_data).to_bytes(4, 'big')
    data = length_bytes + file_data
    bits = _bytes_to_bits(data)

    for i in range(len(bits)):
        frames[i] = (frames[i] & 254) | int(bits[i])

    with wave.open(audio_out, 'wb') as modified:
        modified.setparams(params)
        modified.writeframes(bytes(frames))

def extract_file_from_audio(audio_path) -> bytes:
    with wave.open(audio_path, 'rb') as song:
        frames = bytearray(song.readframes(song.getnframes()))

    bits = ""
    for byte in frames:
        bits += str(byte & 1)

    length_bits = bits[:32]
    length = int(length_bits, 2)
    data_bits = bits[32:32 + (length * 8)]

    return _bits_to_bytes(data_bits)
