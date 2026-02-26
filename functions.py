from PIL import Image


def _shift_alpha(char, shift):
    if 'a' <= char <= 'z':
        base = ord('a')
        return chr((ord(char) - base + shift) % 26 + base)
    if 'A' <= char <= 'Z':
        base = ord('A')
        return chr((ord(char) - base + shift) % 26 + base)
    return char

def encrypt_message(image_path, message, shift, output_path):
    # Open image 
    img = Image.open(image_path)
    pixels = img.load()
    end_marker = "###END###"

    # Encryption
    encrypted_message = ""
    for char in message:
        encrypted_message += _shift_alpha(char, shift)

    payload = (encrypted_message + end_marker).encode("utf-8")
     
    # Hide the values in pixels
    width,height=img.size
    if len(payload)> width*height:
        raise ValueError("Message too long to encode in the image")
    
    char_index = 0
    for y in range(height):
        for x in range(width):
            if char_index < len(payload):
                pixel = pixels[x, y]
                if isinstance(pixel, int):
                    r, g, b = pixel, 0, 0
                elif len(pixel) == 4:
                    r, g, b, a = pixel
                else:
                    r, g, b = pixel

                r = payload[char_index]
                char_index += 1

                if isinstance(pixel, int):
                    pixels[x, y] = r
                elif len(pixel) == 4:
                    pixels[x, y] = (r, g, b, a)
                else:
                    pixels[x, y] = (r, g, b)
            else:
                break
        if char_index>=len(payload):
            break
    
    # Save the image
    img.save(output_path)
    return True

def decrypt_without_key(image_path):
    end_marker = "###END###"
    encrypted_payload = _extract_payload_until_marker(image_path, end_marker.encode("utf-8"))
    if encrypted_payload is None:
        return []

    try:
        encrypted_payload = encrypted_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return []

    candidates = []
    for shift in range(26):
        decrypted_message = ""
        for char in encrypted_payload:
            decrypted_message += _shift_alpha(char, -shift)

        candidates.append({
            'shift': shift,
            'message': decrypted_message,
        })

    return candidates

def _extract_payload_until_marker(image_path, end_marker, max_chars_to_check=None):
    img = Image.open(image_path)
    pixels = img.load()
 
    extracted_bytes = bytearray()
    found_end = False
    if max_chars_to_check is None:
        max_chars_to_check = min(img.size[0] * img.size[1], 200000)
    else:
        max_chars_to_check = min(max_chars_to_check, img.size[0] * img.size[1])

    for y in range(img.size[1]):
        for x in range(img.size[0]):
            if len(extracted_bytes) >= max_chars_to_check:
                break

            pixel = pixels[x, y]
            if isinstance(pixel, int):
                r = pixel
            elif len(pixel) == 4:
                r, g, b, a = pixel
            else:
                r, g, b = pixel

            extracted_bytes.append(r)

            if len(extracted_bytes) >= len(end_marker) and extracted_bytes[-len(end_marker):] == end_marker:
                found_end = True
                break

        if found_end or len(extracted_bytes) >= max_chars_to_check:
            break

    if not found_end:
        return None

    return bytes(extracted_bytes[:-len(end_marker)])

def decrypt_with_key(image_path, shift, max_chars_to_check=None):
    end_marker = "###END###"
    encrypted_message = _extract_payload_until_marker(image_path, end_marker.encode("utf-8"), max_chars_to_check=max_chars_to_check)
    if encrypted_message is None:
        return None

    try:
        encrypted_message = encrypted_message.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None

    decrypted_message = ''
    for char in encrypted_message:
        decrypted_message += _shift_alpha(char, -shift)

    return decrypted_message
