import pydicom 
from PIL import Image
import numpy as np
def convert_dcm_jpg(name):
    
    im = pydicom.dcmread(name)

    im = im.pixel_array.astype(float)

    rescaled_image = (np.maximum(im,0)/im.max())*255 # float pixels
    final_image = np.uint8(rescaled_image) # integers pixels

    final_image = Image.fromarray(final_image)
    final_image.save('non_Dicom_image.jpg')

    return final_image

convert_dcm_jpg('dicom_img.dcm')