# codes by vision
import cv2
import numpy as np
from pyzbar.pyzbar import decode
from PIL import Image
import io

def decode_qr_code(image_data):
    try:
        if not image_data:
            return None, "Received empty image data."

        image_array = None
        try:
            image = Image.open(io.BytesIO(image_data))
            image_array = np.array(image)
        except Exception:
            nparr = np.frombuffer(image_data, np.uint8)
            image_array = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
        if image_array is None:
            return None, "Could not identify or decode the image file. Please ensure it's a valid image (JPG, PNG, etc.)."

        if len(image_array.shape) == 3 and image_array.shape[2] == 4:
            image_array = cv2.cvtColor(image_array, cv2.COLOR_RGBA2RGB)
        elif len(image_array.shape) == 2 or (len(image_array.shape) == 3 and image_array.shape[2] == 1):
            image_array = cv2.cvtColor(image_array, cv2.COLOR_GRAY2RGB)
        def attempt_decode(img):

            decoded = decode(img)
            if decoded:
                urls = [obj.data.decode('utf-8') for obj in decoded]
                return urls

            detector = cv2.QRCodeDetector()
            val, points, qrcode = detector.detectAndDecode(img)
            if val:
                return [val]
            return None

        results = attempt_decode(image_array)
        if results:
            return results[0], None if len(results) == 1 else f"Multiple QR codes found ({len(results)}), analyzing the first one"

        gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
        results = attempt_decode(gray)
        if results:
            return results[0], None

        alpha = 1.5
        beta = 0
        adjusted = cv2.convertScaleAbs(gray, alpha=alpha, beta=beta)
        results = attempt_decode(adjusted)
        if results:
            return results[0], None

        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        results = attempt_decode(thresh)
        if results:
            return results[0], None

        return None, "No QR code found in the image. Try a clearer photo with better lighting."
    except Exception as e:
        return None, f"Error decoding QR code: {str(e)}"

def is_url(text):
    return text.startswith('http://') or text.startswith('https://') or '.' in text
