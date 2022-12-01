from dataclasses import dataclass
from hashlib import sha3_256
import time

from positional_lsb.pattern import Pattern
from positional_lsb.pystego import PositionalLSBImage


@dataclass
class Resolution:
    width: int
    height: int


def lead_time_for_pattern(pattern: Pattern) -> float:
    start = time.time()
    pattern.get_pattern()
    end = time.time()
    return end - start

def lead_time_by_data_volume(lsb_encode:PositionalLSBImage,
                             filename: str) -> float:
    start = time.time()
    with open(filename, 'rb') as file:
        lsb_encode.encode(file.read(), 'new.png')
    end = time.time()
    return end - start


image_resolutions = {
    'HD': Resolution(1280, 720),
    'FullHD': Resolution(1920, 1080),
    'QaudHD': Resolution(2560, 1440),
    'UltraHD': Resolution(3840, 2160)
}

DEFAULT_HASH = sha3_256(b'').digest()

for resolution_name, resolution in image_resolutions.items():
    execution_time = lead_time_for_pattern(
        Pattern(resolution.width, resolution.height, DEFAULT_HASH)
        )
    print(resolution_name, execution_time)

files = [ 'quarter_fill', 'half_fill', 'three_fourths_fill', 'full_filling']

lsb_encode_object = PositionalLSBImage('img.jpg', 'Passw0rd')
for file_path in files:
    execution_time = lead_time_by_data_volume(lsb_encode_object, file_path)
    print(file_path, execution_time)
