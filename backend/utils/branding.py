import colorgram

def extract_colors(image_path, num_colors=3):
    """
    Extracts a color palette from an image.
    Returns a dictionary with primary, secondary, and accent colors.
    """
    try:
        colors = colorgram.extract(image_path, num_colors)
        hex_colors = []
        for color in colors:
            rgb = color.rgb
            hex_colors.append('#{:02x}{:02x}{:02x}'.format(rgb.r, rgb.g, rgb.b))
        
        # Ensure we return at least 3 colors by padding if necessary
        while len(hex_colors) < 3:
            hex_colors.append(hex_colors[-1] if hex_colors else "#000000")
            
        return {
            "primary": hex_colors[0],
            "secondary": hex_colors[1],
            "accent": hex_colors[2]
        }
    except Exception as e:
        print(f"Error extracting colors: {e}")
        return {
            "primary": "#1a202c",
            "secondary": "#2d3748",
            "accent": "#4a5568"
        }
