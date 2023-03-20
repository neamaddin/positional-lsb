from hashlib import sha3_256

import pytest

from positional_lsb.pattern import Coordinates, Pattern, ImagePattern
from .conftest import get_test_data


SHA3_256_DEFAULT = sha3_256(b'').digest()
SEQUENCE_DATA = get_test_data('pattern_sequence.json')
PATTERN_DATA = get_test_data('pattern_data.json')


class TestPattern:
    pattern = Pattern(10, 10, SHA3_256_DEFAULT)

    @pytest.mark.parametrize(
        ('width', 'height'), [
             (10, 10),
             (100, 100),
             (1920, 1080),
        ]
    )
    def test_pr_create_and_mix_sequence(self, width, height):
        pattern = Pattern(width, height, SHA3_256_DEFAULT)
        sequence = pattern._create_and_mix_sequence()
        assert sequence == SEQUENCE_DATA[f'sequence_{width}x{height}']

    @pytest.mark.parametrize(
        ('index', 'coords'), [
            (53, Coordinates(4, 2)),
            (94, Coordinates(8, 3)),
            (25, Coordinates(1, 4)),
            (1, Coordinates(-1, 0))
        ]
    )
    def test_pr_index_to_coordinates_vertical(self, index, coords):
        assert self.pattern._index_to_coordinates_vertical(index) == coords

    @pytest.mark.parametrize(
        ('index', 'coords'), [
            (53, Coordinates(2, 4)),
            (94, Coordinates(3, 8)),
            (25, Coordinates(4, 1)),
            (1, Coordinates(0, -1))
        ]
    )
    def test_pr_index_to_coordinates_horizontal(self, index, coords):
        assert self.pattern._index_to_coordinates_horizontal(index) == coords

    def test_pr_index_to_coordinates(self):
        vertical_function = self.pattern._index_to_coordinates()
        vertical_conversion = self.pattern._index_to_coordinates_vertical
        another_pattern = Pattern(10, 10, SHA3_256_DEFAULT + b'\1')
        horizontal_conversion = another_pattern._index_to_coordinates_horizontal
        horizontal_function = another_pattern._index_to_coordinates()
        assert vertical_function == vertical_conversion
        assert horizontal_function == horizontal_conversion

    @pytest.mark.parametrize(
        ('width', 'height'), [
            (10, 10),
            (100, 100),
            (1920, 1080),
        ]
    )
    def test_pr_get_pattern(self, width, height):
        pattern = Pattern(width, height, SHA3_256_DEFAULT)
        sequence = pattern.get_pattern()
        processed_data = [
            Coordinates(x, y) for x, y
            in PATTERN_DATA[f'pattern_{width}x{height}']
        ]
        assert sequence == processed_data


class TestImagePattern:
    @pytest.mark.parametrize('path_for_image', ['img.jpg'], indirect=True)
    def test_init(self, mocker, path_for_image):
        mocker.patch('positional_lsb.pattern.Pattern.__init__')
        ImagePattern(path_for_image, SHA3_256_DEFAULT)
        Pattern.__init__.assert_called_with(1920, 1080, SHA3_256_DEFAULT)
