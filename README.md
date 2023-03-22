# Positional LSB

[![tests](https://github.com/neamaddin/positional-lsb/actions/workflows/tests.yml/badge.svg)](https://github.com/neamaddin/positional-lsb/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/neamaddin/positional-lsb/branch/main/graph/badge.svg?token=ZO0TQ25F6C)](https://codecov.io/gh/neamaddin/positional-lsb)
[![python-versions](https://img.shields.io/static/v1?logo=python&label=python&message=3.10%20|%203.11&color=success)](https://pypi.org/project/positional-lsb/)
[![PyPI](https://img.shields.io/pypi/v/positional-lsb?color=success)](https://pypi.org/project/positional-lsb/)
[![GitHub](https://img.shields.io/pypi/l/positional-lsb?color=success")](https://github.com/neamaddin/positional-lsb/blob/master/LICENSE)

Positional LSB is a steganographic algorithm based on LSB. The algorithm is designed to overcome the lack of ease extracting data when LSB usage is detected. This implementation uses sequential writing of data into pseudo-random pixels of the image.

### Content

- [Requirements](#requirements)
- [Installation](#installation)
- [Example](#example)
  - [Encode](#encode)
  - [Decode](#decode)
- [Testing](#testing)
- [License](#license)

## Requirements

Python 3.10+<br>
The package has 2 required dependencies:
- [OpenCV](https://pypi.org/project/opencv-python/) for image manipulation.
- [PyCryptodome](https://pypi.org/project/pycryptodome/) for encryption.

## Installation

```sh
pip install positional-lsb
```

## Example

This package implements three options for using the algorithm:
- Without encryption
- With [3DES](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r1.pdf)
- With [AES](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)

> There are differences only in the called class method
> - `encode()` for encode without encryption
> - `encode_with_3des()` for encode with 3DES
> - `encode_with_aes()` for encode with AES
>
> And similarly for `decode` methods

When creating a `PositionalLSBImage` class object, as the first argument you need to specify the path to the image that will be used as a container, and the second argument (optional) is the password in the string format.

> The use of an algorithm without a password does not reduce the cryptographic strength to the level of the classical LSB, but it makes it easy to extract data if, like you use the package

### Encode

You need to create an instance of the PositionalLSBImage class and call the one kind of `encode` method and pass the data as the first argument and the name of the output image.

> The output image must be with `.png` extension, otherwise nothing will work
```python
from positional_lsb.stego import PositionalLSBImage

# get data in bytes
data = b'Positional LSB is cool!'

lsb_encode = PositionalLSBImage('empty_image.[jpg, png, bpm, ...]', 'Passw0rd')
lsb_encode.encode_with_3des(data, 'image_with_data.png')

```
### Decode

You need to create an instance of the PositionalLSBImage class and call the one kind of `decode` method, which returns the data in bytes.

```python
from positional_lsb.stego import PositionalLSBImage


lsb_decode = PositionalLSBImage('image_with_data.png', 'Passw0rd')
data = lsb_decode.decode_with_3des()

# do something with data
# ...

```
## Testing

[Tox](https://tox.wiki/en/latest/) is used to test this package.

> For run tests python 3.10 and 3.11 must be installed

To run tests, install and run tox with the following commands:
```sh
# install tox
pip install tox
# run tox
tox
```
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
