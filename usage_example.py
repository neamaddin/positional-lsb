from positional_lsb.pystego import PositionalLSBImage

if __name__ == '__main__':
    lsb_encode = PositionalLSBImage('img.jpg', 'Passw0rd')
    with open('requirements.txt', 'rb') as file:
        lsb_encode.encode_with_3des(file.read(), 'new.png')

    lsb_decode = PositionalLSBImage('new.png', 'Passw0rd')
    with open('1.txt', 'wb') as file:
        file.write(lsb_decode.decode_with_3des())

# if __name__ == '__main__':
#     lsb_encode = PositionalLSBVideo('video.mp4', 'Passw0rd')
#     lsb_encode.encode('requirements.txt', 'video')

#     lsb_decode = PositionalLSBVideo('video.avi', 'Passw0rd')
#     lsb_decode.decode('2.txt')
