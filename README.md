# Image Encrypter–Decrypter

A Python desktop app that hides an encrypted text message inside an image and retrieves it later.

## Features

- Encrypt a secret message into an image (PNG recommended)
- Decrypt using a known key (shift)
- Decrypt without a key by showing all **26 brute forced combinations**
- Encrypts **only alphabetic characters** (`A–Z`, `a–z`) using a Caesar shift (`0–25`)
- Leaves numbers, spaces, and symbols unchanged
- Drag-and-drop image support
- Centered, themed popups and scrollable output for long messages

## Tech Stack / Libraries

- `tkinter` (GUI)
- `tkinterdnd2` (drag and drop)
- `Pillow (PIL)` (image read/write and pixel manipulation)

## How it works (high level)

1. Your message is Caesar-shift encrypted (letters only).
2. The encrypted text is UTF-8 encoded and embedded into the image by writing bytes into pixel channel values.
3. A marker (`###END###`) is embedded to detect where the message ends.
4. For decryption, the app extracts bytes until the marker and decrypts using either:
   - the provided shift key, or
   - all 26 shifts (brute force) if the key is unknown.

## Setup

### 1) Install dependencies

```bash
pip install pillow tkinterdnd2
```

> Note: `tkinter` comes bundled with most Python installations on Windows.

### 2) Run the app

```bash
python main.py
```

## Usage

### Encrypt

1. Open the app and choose **Encrypt**
2. Drag-and-drop an image (or use **Select Image File**)
3. Enter:
   - your **message**
   - a **shift key** between `0` and `25`
4. Choose where to save the encrypted image

### Decrypt

1. Open the app and choose **Decrypt**
2. Select the encrypted image
3. Choose:
   - **I know the shift key** to decode directly
   - **I don't know the key** to view all 26 brute-forced combinations

## Notes

- PNG is recommended because it is lossless.
- Images created with older versions of the app may not decode correctly after format changes.

## Project Structure

- `main.py` — GUI and user flow
- `functions.py` — encryption/decryption + embedding/extraction logic

## License

Add a license if you plan to make this public on GitHub.
