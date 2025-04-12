import os
import secrets
import json
import logging
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, send_from_directory, session
)
from werkzeug.utils import secure_filename

# for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors

# import custom modules
from crypto import AESCipher, BlowfishCipher, ChaCha20Cipher
from qr_handler import generate_qr_code, read_qr_code

# setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='securecrypt.log'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# add datetime filter
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# set up directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, 'downloads')
QR_FOLDER = os.path.join(BASE_DIR, 'static', 'qrcodes')
PROFILES_FOLDER = os.path.join(BASE_DIR, 'profiles')

# create directories kung hindi nagexist
for folder in [UPLOAD_FOLDER, DOWNLOAD_FOLDER, QR_FOLDER, PROFILES_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['QR_FOLDER'] = QR_FOLDER
app.config['PROFILES_FOLDER'] = PROFILES_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16mb max upload size

# allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'csv'}

def is_valid_profile_name(name):
    """
    Validate profile name:
    - Only alphanumeric characters and underscores
    - 3-30 characters long
    """
    import re
    return re.match(r'^[a-zA-Z0-9_]{3,30}$', name) is not None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_cipher(algorithm, key):
    """
    Select appropriate cipher based on algorithm
    
    Args:
        algorithm (str): Encryption algorithm
        key (str): Encryption/Decryption key
    
    Returns:
        Cipher object
    """
    cipher_map = {
        'aes': AESCipher,
        'blowfish': BlowfishCipher,
        'chacha20': ChaCha20Cipher
    }
    
    cipher_class = cipher_map.get(algorithm.lower())
    if not cipher_class:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    return cipher_class(key)

def generate_pdf(content, output_path):
    """Generate a PDF containing the decrypted information
    
    Args:
        content (str): Decrypted content to include in the PDF
        output_path (str): Path where the PDF will be saved
    
    Returns:
        bool: Success status
    """
    try:
        # create document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            title="Decrypted Information"
        )
        
        # styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            alignment=TA_CENTER,
            textColor=colors.navy,
            spaceAfter=24
        )
        
        # content elements
        elements = []
        
        # add title
        elements.append(Paragraph("SecureCrypt Decrypted Information", title_style))
        elements.append(Spacer(1, 20))
        
        # add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(f"Decrypted on: {timestamp}", styles["Normal"]))
        elements.append(Spacer(1, 20))
        
        # add content header
        elements.append(Paragraph("Your Information:", styles["Heading2"]))
        elements.append(Spacer(1, 10))
        
        # format actual content tas split by lines
        content_lines = content.split('\n')
        for line in content_lines:
            elements.append(Paragraph(line, styles["Normal"]))
            elements.append(Spacer(1, 6))
        
        # add security notice
        elements.append(Spacer(1, 30))
        security_note = """This document contains sensitive information that was previously encrypted. 
                         Please store it securely and avoid sharing it unnecessarily."""
        elements.append(Paragraph(security_note, styles["Italic"]))
        
        # build PDF
        doc.build(elements)
        logger.info(f"PDF generated at {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error generating PDF: {e}")
        return False

def get_profiles():
    """
    Retrieve all saved profiles
    
    Returns:
        list: List of profile dictionaries
    """
    profiles = []
    
    try:
        # ensure the profiles folder exists
        if not os.path.exists(app.config['PROFILES_FOLDER']):
            os.makedirs(app.config['PROFILES_FOLDER'])
        
        for filename in os.listdir(app.config['PROFILES_FOLDER']):
            if filename.endswith('.json'):
                profile_path = os.path.join(app.config['PROFILES_FOLDER'], filename)
                
                try:
                    with open(profile_path, 'r') as f:
                        profile_data = json.load(f)
                        profile_data['name'] = os.path.splitext(filename)[0]
                        profiles.append(profile_data)
                except json.JSONDecodeError:
                    logger.error(f"Error decoding profile: {filename}")
    except Exception as e:
        logger.error(f"Error loading profiles: {e}")
    
    # sort profiles by creation date
    return sorted(profiles, key=lambda x: x.get('created_at', ''), reverse=True)

def save_profile(profile_name, generate_qr=False, compress=False, algorithm="aes", old_name=None):
    """
    Save encryption profile settings
    
    Args:
        profile_name (str): Name of the profile
        generate_qr (bool): Whether to generate QR code
        compress (bool): Whether to compress data
        algorithm (str): Encryption algorithm
        old_name (str, optional): Previous profile name for renaming
    
    Returns:
        bool: Whether profile was saved successfully
    """
    # validate profile name
    if not is_valid_profile_name(profile_name):
        logger.warning(f"Invalid profile name attempt: {profile_name}")
        return False
    
    profile_data = {
        'algorithm': algorithm,
        'generate_qr': generate_qr,
        'compress': compress,
        'created_at': datetime.now().isoformat(),
        'last_modified': datetime.now().isoformat()
    }
    
    # ff renaming, delete old profile
    if old_name and old_name != profile_name:
        old_profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(old_name)}.json")
        if os.path.exists(old_profile_path):
            os.remove(old_profile_path)
            logger.info(f"Deleted old profile: {old_name}")
    
    profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(profile_name)}.json")
    
    try:
        with open(profile_path, 'w') as f:
            json.dump(profile_data, f, indent=4)
        logger.info(f"Profile saved: {profile_name}")
        return True
    except Exception as e:
        logger.error(f"Error saving profile {profile_name}: {e}")
        return False

def get_profile(profile_name):
    """
    Retrieve a specific profile by name
    
    Args:
        profile_name (str): Name of the profile
    
    Returns:
        dict or None: Profile data
    """
    profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(profile_name)}.json")
    
    if os.path.exists(profile_path):
        try:
            with open(profile_path, 'r') as f:
                profile_data = json.load(f)
                profile_data['name'] = profile_name
                return profile_data
        except json.JSONDecodeError:
            logger.error(f"Error decoding profile: {profile_name}")
    
    return None

# route handlers
@app.route('/')
def index():
    profiles = get_profiles()
    return render_template('index.html', profiles=profiles)

@app.route('/encrypt')
def encrypt_page():
    profiles = get_profiles()
    return render_template('encrypt.html', profiles=profiles)

@app.route('/encrypt_data', methods=['GET', 'POST'])
def encrypt_data():
    if request.method == 'GET':
        return redirect(url_for('encrypt_page'))
    
    try:
        # get form data
        algorithm = request.form.get('algorithm', 'aes')
        key = request.form.get('key', '')
        input_type = request.form.get('input_type', 'text')
        generate_qr = request.form.get('generate_qr') == 'yes'
        profile_name = request.form.get('profile')
        
        # validate inputs
        if not key:
            flash('Encryption key is required')
            return redirect(url_for('encrypt_page'))
        
        if profile_name:
            profile = get_profile(profile_name)
            if profile:
                algorithm = profile.get('algorithm', algorithm)
                generate_qr = profile.get('generate_qr', generate_qr)
        
        # initialize the appropriate cipher
        cipher = get_cipher(algorithm, key)
        
        if input_type == 'text':
            # text encryption
            plaintext = request.form.get('plaintext', '')
            if not plaintext:
                flash('No text provided for encryption')
                return redirect(url_for('encrypt_page'))
            
            # encrypt the text
            encrypted_data = cipher.encrypt(plaintext)
            
            # generate qr code pag narequested
            qr_path = None
            if generate_qr:
                qr_filename = f"qr_{secrets.token_hex(8)}.png"
                qr_path = os.path.join('qrcodes', qr_filename)
                qr_full_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
                generate_qr_code(encrypted_data, qr_full_path)
            
            return render_template('result.html', 
                                   title="Encryption Successful",
                                   description="Your data has been encrypted successfully.",
                                   message="Text encrypted successfully!",
                                   algorithm=algorithm,
                                   is_file=False,
                                   operation_type="encrypt",
                                   output=encrypted_data,
                                   qr_path=qr_path)
        
        elif input_type == 'file':
            # file encryption
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('encrypt_page'))
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No file selected')
                return redirect(url_for('encrypt_page'))
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # read file content
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                # encrypt file content
                encrypted_content = cipher.encrypt_file(file_content)
                
                # save encrypted file
                encrypted_filename = f"encrypted_{filename}"
                encrypted_path = os.path.join(app.config['DOWNLOAD_FOLDER'], encrypted_filename)
                
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_content)
                
                return render_template('result.html',
                                      title="File Encryption Successful",
                                      description="Your file has been encrypted successfully.",
                                      message="File encrypted successfully!",
                                      algorithm=algorithm,
                                      is_file=True,
                                      operation_type="encrypt",
                                      filename=filename,
                                      output_file=encrypted_filename)
            else:
                flash('File type not allowed')
                return redirect(url_for('encrypt_page'))
    
    except Exception as e:
        flash(f"Encryption failed: {str(e)}")
        logger.error(f"Encryption error: {str(e)}")
        return redirect(url_for('encrypt_page'))

@app.route('/decrypt')
def decrypt_page():
    profiles = get_profiles()
    return render_template('decrypt.html', profiles=profiles)

@app.route('/decrypt_data', methods=['GET', 'POST'])
def decrypt_data():
    if request.method == 'GET':
        
        return redirect(url_for('decrypt_page'))
    
    try:
        # get form data
        algorithm = request.form.get('algorithm', 'aes')
        key = request.form.get('key', '')
        input_type = request.form.get('input_type', 'text')
        profile_name = request.form.get('profile')
        
        # validate inputs
        if not key:
            flash('Decryption key is required')
            return redirect(url_for('decrypt_page'))
        
       
        if profile_name:
            profile = get_profile(profile_name)
            if profile:
                algorithm = profile.get('algorithm', algorithm)
        
        # initialize the appropriate cipher
        cipher = get_cipher(algorithm, key)
        
        if input_type == 'text':
            # text decryption
            ciphertext = request.form.get('ciphertext', '')
            if not ciphertext:
                flash('No encrypted text provided')
                return redirect(url_for('decrypt_page'))
            
            # decrypt the text
            try:
                decrypted_data = cipher.decrypt(ciphertext)
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")
                return redirect(url_for('decrypt_page'))
            
            return render_template('result.html',
                                  title="Decryption Successful",
                                  description="Your data has been decrypted successfully.",
                                  message="Text decrypted successfully!",
                                  algorithm=algorithm,
                                  is_file=False,
                                  operation_type="decrypt",
                                  output=decrypted_data)
        
        elif input_type == 'file':
            # file decryption
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('decrypt_page'))
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No file selected')
                return redirect(url_for('decrypt_page'))
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # read encrypted file content
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
            
            # decrypt file content
            try:
                decrypted_content = cipher.decrypt_file(encrypted_content)
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")
                return redirect(url_for('decrypt_page'))
            
            # save decrypted file
            decrypted_filename = f"decrypted_{filename.replace('encrypted_', '')}"
            decrypted_path = os.path.join(app.config['DOWNLOAD_FOLDER'], decrypted_filename)
            
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_content)
            
            return render_template('result.html',
                                  title="File Decryption Successful",
                                  description="Your file has been decrypted successfully.",
                                  message="File decrypted successfully!",
                                  algorithm=algorithm,
                                  is_file=True,
                                  operation_type="decrypt",
                                  filename=filename,
                                  output_file=decrypted_filename)
        
        elif input_type == 'qr':
            # qr code decryption
            if 'qr_file' not in request.files:
                flash('No QR code image uploaded')
                return redirect(url_for('decrypt_page'))
            
            qr_file = request.files['qr_file']
            
            if qr_file.filename == '':
                flash('No QR code selected')
                return redirect(url_for('decrypt_page'))
            
            qr_filename = secure_filename(qr_file.filename)
            qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
            qr_file.save(qr_path)
            
            # read qr code content
            encrypted_data = read_qr_code(qr_path)
            
            if not encrypted_data:
                flash('Could not read QR code or QR code does not contain valid data')
                return redirect(url_for('decrypt_page'))
            
            # decrypt the data from QR code
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
                
                # generate PDF with decrypted data
                pdf_filename = f"decrypted_document_{secrets.token_hex(6)}.pdf"
                pdf_path = os.path.join(app.config['DOWNLOAD_FOLDER'], pdf_filename)
                
                # generate the PDF
                generate_pdf(decrypted_data, pdf_path)
                
                return render_template('result.html',
                                      title="QR Code Decryption Successful",
                                      description="Your QR code has been decrypted successfully and converted to PDF.",
                                      message="QR code decrypted and converted to PDF successfully!",
                                      algorithm=algorithm,
                                      is_file=True,  # changed to true for file download
                                      operation_type="decrypt",
                                      filename="Decrypted Document",
                                      output_file=pdf_filename)
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")
                logger.error(f"QR decryption error: {str(e)}")
                return redirect(url_for('decrypt_page'))
    
    except Exception as e:
        flash(f"Decryption failed: {str(e)}")
        logger.error(f"Decryption error: {str(e)}")
        return redirect(url_for('decrypt_page'))

@app.route('/profiles')
def profiles_page():
    profiles = get_profiles()
    return render_template('profiles.html', profiles=profiles)

@app.route('/profiles/new', methods=['GET', 'POST'])
def new_profile():
    if request.method == 'POST':
        # profile creation logic
        profile_name = request.form.get('profile_name', '').strip()
        algorithm = request.form.get('algorithm', 'aes')
        generate_qr = request.form.get('generate_qr') == 'yes'
        compress = request.form.get('compress') == 'yes'
        
        # validate profile name
        if not profile_name:
            flash("Profile name cannot be empty.")
            return render_template('new_profile.html')
        
        if not is_valid_profile_name(profile_name):
            flash("Invalid profile name. Use 3-30 alphanumeric characters or underscores.")
            return render_template('new_profile.html')
        
        # check if profile already exists
        existing_profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(profile_name)}.json")
        if os.path.exists(existing_profile_path):
            flash(f"Profile '{profile_name}' already exists.")
            return render_template('new_profile.html')
        
        if save_profile(profile_name, generate_qr, compress, algorithm):
            flash(f"Profile '{profile_name}' saved successfully!")
            return redirect(url_for('profiles_page'))
        else:
            flash("Failed to save profile.")
    
    return render_template('new_profile.html')

@app.route('/profiles/edit/<name>', methods=['GET', 'POST'])
def edit_profile(name):
    profile = get_profile(name)
    
    if not profile:
        flash(f"Profile '{name}' not found.")
        return redirect(url_for('profiles_page'))
    
    if request.method == 'POST':
        new_name = request.form.get('profile_name', '').strip()
        generate_qr = request.form.get('generate_qr') == 'yes'
        compress = request.form.get('compress') == 'yes'
        
        # validate new name
        if not new_name:
            flash("Profile name cannot be empty.")
            return render_template('edit_profile.html', profile=profile)
        
        if not is_valid_profile_name(new_name):
            flash("Invalid profile name. Use 3-30 alphanumeric characters or underscores.")
            return render_template('edit_profile.html', profile=profile)
        
        # if name changed, check for conflicts
        if new_name != name:
            existing_profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(new_name)}.json")
            if os.path.exists(existing_profile_path):
                flash(f"Profile '{new_name}' already exists.")
                return render_template('edit_profile.html', profile=profile)
        
        # save profile with potential name change
        if save_profile(new_name, generate_qr, compress, profile.get('algorithm', 'aes'), old_name=name):
            if name != new_name:
                flash(f"Profile renamed from '{name}' to '{new_name}' successfully!")
            else:
                flash(f"Profile '{name}' updated successfully!")
            return redirect(url_for('profiles_page'))
        else:
            flash("Failed to update profile.")
    
    return render_template('edit_profile.html', profile=profile)

@app.route('/profiles/delete/<name>')
def delete_profile(name):
    profile_path = os.path.join(app.config['PROFILES_FOLDER'], f"{secure_filename(name)}.json")
    
    if os.path.exists(profile_path):
        try:
            os.remove(profile_path)
            logger.info(f"Profile deleted: {name}")
            flash(f"Profile '{name}' deleted successfully!")
        except Exception as e:
            logger.error(f"Error deleting profile {name}: {e}")
            flash(f"Error deleting profile: {str(e)}")
    else:
        flash(f"Profile '{name}' not found.")
    
    return redirect(url_for('profiles_page'))

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {e}")
        flash("Error downloading file.")
        return redirect(url_for('index'))

# error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File is too large. Maximum file size is 16MB.')
    return redirect(request.url)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Server Error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(405)
def method_not_allowed(error):
    logger.error(f"Method Not Allowed Error: {request.path}")
    if request.path == '/encrypt_data':
        return redirect(url_for('encrypt_page'))
    elif request.path == '/decrypt_data':
        return redirect(url_for('decrypt_page'))
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("Starting SecureCrypt application...")
    app.run(debug=True, host='0.0.0.0', port=5000)
    print("Application terminated.")