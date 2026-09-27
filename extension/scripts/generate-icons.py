"""
Generate extension icon PNG files at 16x16, 32x32, 48x48, and 128x128.
Saves them to public/, dist/, and their icons/ subdirectories.
"""
import os
import shutil
from PIL import Image, ImageDraw

def render_icon(target_size):
    scale = 16
    s = target_size * scale
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    pad = s * 0.05
    r = s * 0.22
    
    # Outer rounded square with modern vibrant security blue (#1a73e8)
    draw.rounded_rectangle([pad, pad, s - pad, s - pad], radius=r, fill=(26, 115, 232, 255))
    
    # Subtle inner border for larger sizes
    if target_size >= 48:
        border_pad = pad + s * 0.02
        draw.rounded_rectangle(
            [border_pad, border_pad, s - border_pad, s - border_pad],
            radius=r * 0.9,
            outline=(100, 160, 255, 255),
            width=int(s * 0.02)
        )
    
    cx = s / 2
    top_y = s * 0.20
    mid_y = s * 0.52
    bot_y = s * 0.82
    w = s * 0.30
    
    shield_pts = [
        (cx - w, top_y),
        (cx + w, top_y),
        (cx + w, mid_y),
        (cx, bot_y),
        (cx - w, mid_y)
    ]
    draw.polygon(shield_pts, fill=(255, 255, 255, 255))
    
    c1 = (cx - w * 0.45, top_y + (bot_y - top_y) * 0.45)
    c2 = (cx - w * 0.08, top_y + (bot_y - top_y) * 0.65)
    c3 = (cx + w * 0.50, top_y + (bot_y - top_y) * 0.28)
    
    line_w = int(s * (0.11 if target_size <= 32 else 0.09))
    draw.line([c1, c2, c3], fill=(26, 115, 232, 255), width=line_w, joint='curve')
    
    return img.resize((target_size, target_size), Image.Resampling.LANCZOS)

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets = [os.path.join(base_dir, 'public'), os.path.join(base_dir, 'dist')]
    
    for t in targets:
        os.makedirs(t, exist_ok=True)
        icons_subdir = os.path.join(t, 'icons')
        os.makedirs(icons_subdir, exist_ok=True)
        
        for sz in [16, 32, 48, 128]:
            icon = render_icon(sz)
            root_icon_path = os.path.join(t, f'icon-{sz}.png')
            sub_icon_path = os.path.join(icons_subdir, f'icon-{sz}.png')
            icon.save(root_icon_path, 'PNG')
            shutil.copyfile(root_icon_path, sub_icon_path)
            print(f'Saved {root_icon_path} & {sub_icon_path} ({sz}x{sz})')

if __name__ == '__main__':
    main()
