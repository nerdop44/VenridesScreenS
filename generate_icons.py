
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

    # Splashes - Center logo on Professional Navy Blue background to prevent distortion
    BG_COLOR = (0, 31, 63) # Lighter Professional Navy Blue
    
    for folder in SPLASH_FOLDERS:
        out_folder = os.path.join(ANDROID_RES, folder)
        if not os.path.exists(out_folder): os.makedirs(out_folder)
        
        # Determine orientation from folder name
        is_land = 'land' in folder
        size = (1280, 720) if is_land else (720, 1280)
        if folder == 'drawable': size = (1024, 1024) # Default square fallback

        splash_bg = Image.new('RGB', size, color=BG_COLOR)
        
        # Resize logo to fit nicely in the center (avoiding edges)
        logo_fit = img.copy()
        max_logo_w = int(size[0] * 0.75)
        max_logo_h = int(size[1] * 0.65)
        logo_fit.thumbnail((max_logo_w, max_logo_h), Image.Resampling.LANCZOS)
        
        # Center logo
        offset = ((size[0] - logo_fit.width) // 2, (size[1] - logo_fit.height) // 2)
        splash_bg.paste(logo_fit, offset, logo_fit if logo_fit.mode == 'RGBA' else None)
        splash_bg.save(os.path.join(out_folder, 'splash.png'))
        print(f"Generated Centered Splash {folder} ({size[0]}x{size[1]})")

    # TV Banner (320x180) - Must be solid and centered
    banner_folder = os.path.join(ANDROID_RES, 'drawable')
    if not os.path.exists(banner_folder): os.makedirs(banner_folder)
    
    banner_bg = Image.new('RGB', (320, 180), color=BG_COLOR)
    logo_for_banner = img.copy()
    logo_for_banner.thumbnail((290, 150), Image.Resampling.LANCZOS)
    offset = ((320 - logo_for_banner.width) // 2, (180 - logo_for_banner.height) // 2)
    banner_bg.paste(logo_for_banner, offset, logo_for_banner if logo_for_banner.mode == 'RGBA' else None)
    banner_bg.save(os.path.join(banner_folder, 'banner.png'))
    print("Generated Fixed TV Banner (320x180)")

if __name__ == '__main__':
    generate_icons()
