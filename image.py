import base64
from PIL import Image


# Abrir la imagen
image = Image.open('Mavesa/13450E0F10_20230928_114758.jpg')

# Reducir la calidad de la imagen (ajusta el valor según tus necesidades)
image = image.convert('RGB')
image.save('imagen_comprimida.jpg', 'JPEG', quality=1)

# Convierte la imagen comprimida en Base64
with open('imagen_comprimida.jpg', 'rb') as image_file:
    image_data=(image_file.read())
    image_base64 = base64.b64encode(image_data).decode('utf-8')
    print(image_base64)

decoded_image_data = base64.b64decode(image_base64)

#print(decoded_image_data)

with open('imagen_comprimida2.jpg', 'wb') as new_image_file:
    new_image_file.write(decoded_image_data)