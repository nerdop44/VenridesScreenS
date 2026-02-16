
import os
from PIL import Image

SERVER_PATH = '/home/nerdop/VenridesScreenS/app-tv'
ICON_PATH = os.path.join(SERVER_PATH, 'venrides_logo.png')
ANDROID_RES = os.path.join(SERVER_PATH, 'android/app/src/main/res')

MIPMAPS = {
    'mipmap-mdpi': 48,
    'mipmap-hdpi': 72,
    'mipmap-xhdpi': 96,
    'mipmap-xxhdpi': 144,
    'mipmap-xxxhdpi': 192
}

SPLASH_FOLDERS = [
    'drawable',
    'drawable-land-mdpi', 'drawable-land-hdpi', 'drawable-land-xhdpi', 'drawable-land-xxhdpi', 'drawable-land-xxxhdpi',
    'drawable-port-mdpi', 'drawable-port-hdpi', 'drawable-port-xhdpi', 'drawable-port-xxhdpi', 'drawable-port-xxxhdpi'
]

def generate_icons():
    if not os.path.exists(ICON_PATH):
        print(f"Icon not found at {ICON_PATH}")
        return

    img = Image.open(ICON_PATH)
    
    # Icons
    for folder, size in MIPMAPS.items():
        out_folder = os.path.join(ANDROID_RES, folder)
        if not os.path.exists(out_folder): os.makedirs(out_folder)
        img.resize((size, size), Image.Resampling.LANCZOS).save(os.path.join(out_folder, 'ic_launcher.png'))
        img.resize((size, size), Image.Resampling.LANCZOS).save(os.path.join(out_folder, 'ic_launcher_round.png'))
        print(f"Generated Icon {folder}")

    # Splashes - simplified: we centers the logo on a black background
    # Standard sizes for splashes vary, let's use 1024x1024 as a safe middle ground for many
    for folder in SPLASH_FOLDERS:
        out_folder = os.path.join(ANDROID_RES, folder)
        if not os.path.exists(out_folder): os.makedirs(out_folder)
        
        # Simple resize of logo as splash (Android will scale/center based on theme)
        # Note: Ideally splash is a separate design, but using logo is better than "other image"
        img.resize((512, 512), Image.Resampling.LANCZOS).save(os.path.join(out_folder, 'splash.png'))
        print(f"Generated Splash {folder}")

    # TV Banner (320x180)
    banner_folder = os.path.join(ANDROID_RES, 'drawable')
    if not os.path.exists(banner_folder): os.makedirs(banner_folder)
    
    # Create black background for banner
    banner_bg = Image.new('RGB', (320, 180), color=(0, 0, 0))
    # Resize logo to fit in banner (with padding)
    logo_for_banner = img.copy()
    logo_for_banner.thumbnail((280, 140), Image.Resampling.LANCZOS)
    # Center logo
    offset = ((320 - logo_for_banner.width) // 2, (180 - logo_for_banner.height) // 2)
    banner_bg.paste(logo_for_banner, offset)
    banner_bg.save(os.path.join(banner_folder, 'banner.png'))
    print("Generated TV Banner (320x180)")

if __name__ == '__main__':
    generate_icons()
