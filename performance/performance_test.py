from hashlib import sha3_256
import time
import sys
sys.path.append('../')

from pattern import Pattern
from pystego import PositionalLSBImage


def lead_time_for_pattern(pattern: Pattern) -> float:
    start = time.time()
    pattern.get_pattern()
    end = time.time()
    return end - start

def lead_time_by_data_volume(lsb_encode:PositionalLSBImage,
                             filename: str) -> float:
    start = time.time()
    lsb_encode.encode(filename, 'new.png')
    end = time.time()
    return end - start


image_resolutions = {
    'HD': (1280, 720),
    'FullHD': (1920, 1080),
    'QaudHD': (2560, 1440),
    'UltraHD': (3840, 2160)
}

default_hash = sha3_256(b'')

for resolution in image_resolutions:
    execution_time = lead_time_for_pattern(
        Pattern(image_resolutions[resolution][0],
                image_resolutions[resolution][1],
                default_hash)
        )
    print(resolution, execution_time)

files = [ 'quarter_fill', 'half_fill', 'three_fourths_fill', 'full_filling']

lsb_encode = PositionalLSBImage('img.jpg', 'Passw0rd')
for file in files:
    execution_time = lead_time_by_data_volume(lsb_encode, file)
    print(file, execution_time)
