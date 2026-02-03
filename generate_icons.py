from PIL import Image
import os
import shutil

SOURCE_LOGO = "frontend-tv/venrides_logo.png"
ICON_SIZES = {
    "mipmap-mdpi": (48, 48),
    "mipmap-hdpi": (72, 72),
    "mipmap-xhdpi": (96, 96),
    "mipmap-xxhdpi": (144, 144),
    "mipmap-xxxhdpi": (192, 192)
}

PROJECTS = [
    "app-mobile/android/app/src/main/res",
    "app-tv/android/app/src/main/res"
]

def generate_icons():
    if not os.path.exists(SOURCE_LOGO):
        # Try finding it based on find_by_name results
        SOURCE_LOGO_ALT = "frontend-admin/public/venrides_logo.png"
        if os.path.exists(SOURCE_LOGO_ALT):
           img = Image.open(SOURCE_LOGO_ALT)
           print(f"Using logo from {SOURCE_LOGO_ALT}")
        else:
           print("Error: Logo not found")
           return
    else:
        img = Image.open(SOURCE_LOGO)

    # Convert to RGBA
    img = img.convert("RGBA")

    # Create a background-less version for foreground if needed, 
    # but for now we'll use the logo as foreground (it should be transparent PNG)
    
    # Ideally foregrounds are 108x108 dp for 48x48 icon (viewport is 72x72)
    # But scaling simply to the same size is a common quick fix, 
    # though technically foreground should be larger. 
    # Let's scale it slightly larger to fill adaptive circle if needed, 
    # or keep as is. Keeping as is is safer to avoid cropping.

    for project_res in PROJECTS:
        print(f"Processing project: {project_res}")
        for folder, size in ICON_SIZES.items():
            target_dir = os.path.join(project_res, folder)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            
            # Resize
            icon = img.resize(size, Image.Resampling.LANCZOS)
            
            # Save standard legacy icon
            icon.save(os.path.join(target_dir, "ic_launcher.png"), "PNG")
            
            # Save round icon
            icon.save(os.path.join(target_dir, "ic_launcher_round.png"), "PNG")
            
            # Save FOREGROUND icon for adaptive icons (Critical fix)
            icon.save(os.path.join(target_dir, "ic_launcher_foreground.png"), "PNG")
            
            print(f"Generated icons in {folder}")

if __name__ == "__main__":
    generate_icons()
