from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size):
    # Create a new image with a white background
    image = Image.new('RGBA', (size, size), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a shield shape
    margin = size // 8
    points = [
        (margin, size//2),  # Left point
        (size//2, margin),  # Top point
        (size-margin, size//2),  # Right point
        (size//2, size-margin),  # Bottom point
    ]
    draw.polygon(points, fill=(33, 150, 243, 255))  # Blue color
    
    # Draw a checkmark
    check_color = (255, 255, 255, 255)  # White
    check_margin = size // 4
    check_points = [
        (check_margin, size//2),
        (size//3, size-check_margin),
        (size-check_margin, check_margin)
    ]
    draw.line(check_points, fill=check_color, width=size//8)
    
    return image

# Create icons directory if it doesn't exist
if not os.path.exists('images'):
    os.makedirs('images')

# Generate icons in different sizes
sizes = [16, 48, 128]
for size in sizes:
    icon = create_icon(size)
    icon.save(f'images/icon{size}.png')

print("Icons generated successfully!") 