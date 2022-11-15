""" Generating files to check the dependence of the
speed of the algorithm on the size of the payload."""

fillment = {
    'full_filling': 777000,
    'three_fourths_fill': int(777000 * 0.75),
    'half_fill': int(777000 * 0.5),
    'quarter_fill': int(777000 * 0.25)
}

for file_name, bytes_number in fillment.items():
    with open(file_name, 'wb') as file:
        file.write(b'\xAA' * bytes_number)
