from typing import NamedTuple, List, Callable

import cv2


class Coordinates(NamedTuple):
    x: int
    y: int


CoordinatesList = List[Coordinates]


class Pattern:
    def __init__(self, image_width: int, image_height: int, sha3_hash: bytes):
        self.image_width: int = image_width
        self.image_height: int = image_height
        self.hash_int: int = int.from_bytes(sha3_hash, "big")
        self.pattern: CoordinatesList = []

    def _create_and_mix_sequence(self) -> list[int]:
        sequence = list(range(1, self.image_width * self.image_height + 1))
        index = len(sequence) - 1
        while index > 0:
            sequence[self.hash_int % index], sequence[index] = (
                sequence[index],
                sequence[self.hash_int % index],
            )
            index -= 1
        return sequence

    def _index_to_coordinates_vertical(self, index: int) -> Coordinates:
        x = index // self.image_height - 1
        y = index % self.image_height - 1
        return Coordinates(x, y)

    def _index_to_coordinates_horizontal(self, index: int) -> Coordinates:
        y = index // self.image_width - 1
        x = index % self.image_width - 1
        return Coordinates(x, y)

    def _index_to_coordinates(self) -> Callable[[int], Coordinates]:
        if self.hash_int % 2 == 1:
            return self._index_to_coordinates_horizontal
        return self._index_to_coordinates_vertical

    def get_pattern(self) -> CoordinatesList:
        idx_to_coords_type = self._index_to_coordinates()
        if not self.pattern:
            for index in self._create_and_mix_sequence():
                self.pattern.append(idx_to_coords_type(index))
        return self.pattern


class ImagePattern(Pattern):
    def __init__(self, image_path: str, sha3_hash: bytes):
        image = cv2.imread(image_path)
        image_width: int = len(image[0])
        image_height: int = len(image)
        super().__init__(image_width, image_height, sha3_hash)
