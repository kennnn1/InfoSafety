import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
import logging

# configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_qr_code(data, output_path, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_L):
    """
    Generate a QR code from data and save it to the output path.
    
    Args:
        data (str): The data to encode in the QR code
        output_path (str): Path where the QR code image will be saved
        box_size (int): Size of each box in pixels
        border (int): Border size in boxes
        error_correction: Error correction level
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Generating QR code with {len(data)} bytes of data")
        
        # create qe code instance
        qr = qrcode.QRCode(
            version=None,  # auto-size the qr code
            error_correction=error_correction,
            box_size=box_size,
            border=border,
        )
        
        # add data to qr code
        qr.add_data(data)
        qr.make(fit=True)
        
        # create an image from the QR code instance
        img = qr.make_image(fill_color="black", back_color="white")
        
        # save the image
        img.save(output_path)
        logger.info(f"QR code saved to {output_path}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return False

def read_qr_code(image_path):
    """
    Read a QR code from an image and return the decoded data.
    
    Args:
        image_path (str): Path to the image file containing the QR code
        
    Returns:
        str: Decoded data from the QR code, or None if reading failed
    """
    try:
        logger.info(f"Reading QR code from {image_path}")
        
        # open the image
        image = Image.open(image_path)
        
        # decode the QR code
        decoded_objects = decode(image)
        
        # check if any qr codes were found
        if len(decoded_objects) == 0:
            logger.warning(f"No QR code found in {image_path}")
            return None
        
        # get the data from the first qr code found
        qr_data = decoded_objects[0].data.decode('utf-8')
        logger.info(f"Successfully decoded QR code containing {len(qr_data)} bytes of data")
        
        return qr_data
    
    except Exception as e:
        logger.error(f"Error reading QR code: {e}")
        return None

def optimize_qr_code(data):
    """
    Optimize data for QR code by determining the best parameters.
    
    Args:
        data (str): The data to be encoded in the QR code
        
    Returns:
        tuple: (version, error_correction, box_size, border) optimized parameters
    """
    # calculate data size
    data_size = len(data)
    
    # determine version and error correction based on data size
    if data_size < 100:
        version = 1
        error_correction = qrcode.constants.ERROR_CORRECT_H  # high error correction
        box_size = 10
        border = 4
    elif data_size < 500:
        version = 10
        error_correction = qrcode.constants.ERROR_CORRECT_M  # medium error correction
        box_size = 8
        border = 4
    else:
        version = 25  # use a larger version for more data
        error_correction = qrcode.constants.ERROR_CORRECT_L  # low error correction for more data capacity
        box_size = 6
        border = 3
    
    logger.info(f"Optimized QR code parameters: version={version}, box_size={box_size}")
    
    return (version, error_correction, box_size, border)