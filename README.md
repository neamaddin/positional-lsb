# Positional LSB

[![tests](https://github.com/neamaddin/positional-lsb/actions/workflows/tests.yml/badge.svg)](https://github.com/neamaddin/positional-lsb/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/neamaddin/positional-lsb/branch/main/graph/badge.svg?token=ZO0TQ25F6C)](https://codecov.io/gh/neamaddin/positional-lsb)
[![python-versions](https://img.shields.io/static/v1?logo=python&label=python&message=3.10%20|%203.11&color=blue)](https://www.python.org/downloads/release/python-3100/)
[![GitHub](https://img.shields.io/github/license/neamaddin/positional-lsb)](https://github.com/neamaddin/positional-lsb/blob/master/LICENSE)

Пример использования:

```python 
from positional_lsb.stego import PositionalLSBImage


if __name__ == '__main__':
    lsb_encode = PositionalLSBImage('empty_image.[jpg, png, ...]', 'Passw0rd')
    with open('file_to_hide.*', 'rb') as file:
        lsb_encode.encode_with_3des(file.read(), 'new.png')

    lsb_decode = PositionalLSBImage('new.png', 'Passw0rd')
    with open('output_file.*', 'wb') as file:
        file.write(lsb_decode.decode_with_3des())

```

В данном примере показано приминение алгоритма с использование шифроваия 3DES

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
