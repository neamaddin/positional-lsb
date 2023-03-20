from positional_lsb.stego import PositionalLSBImage


if __name__ == '__main__':
    lsb_encode = PositionalLSBImage('img.jpg', 'Passw0rd')
    with open('test_file.docx', 'rb') as file:
        lsb_encode.encode_with_3des(file.read(), 'new.png')

    lsb_decode = PositionalLSBImage('new.png', 'Passw0rd')
    with open('output_file.docx', 'wb') as file:
        file.write(lsb_decode.decode_with_3des())
