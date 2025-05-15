from stegano_image import hide_message, extract_message
from stegano_audio import hide_message_in_audio, extract_message_from_audio
from crypto_utils import encrypt_message, decrypt_message

msg = "Secret CLI test!"
pwd = "mypassword123"

# Image Test
hide_message("input.png", "output.png", encrypt_message(msg, pwd))
print("Extracted from image:", decrypt_message(extract_message("output.png"), pwd))

# Audio Test
hide_message_in_audio("input.wav", "output.wav", msg, pwd)
print("Extracted from audio:", extract_message_from_audio("output.wav", pwd))
