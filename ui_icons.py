"""
FolderLock - Modern Pixel-Perfect Icon Generator
Generates clean, centered vector icons using Pillow for CTkImage buttons.
Completely eliminates off-center unicode emoji alignment bugs.
"""

from PIL import Image, ImageDraw
import customtkinter as ctk


def create_sun_icon(size: int = 24) -> Image.Image:
    """Generates a perfectly centered warm amber sun icon for dark mode."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (245, 158, 11, 255)  # Amber-500
    cx, cy = size // 2, size // 2
    r = size // 5
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)

    # 8 Symmetrical rays
    ray_len = 3
    gap = r + 2
    # N, S, E, W
    d.line([cx, cy - gap - ray_len, cx, cy - gap], fill=color, width=2)
    d.line([cx, cy + gap, cx, cy + gap + ray_len], fill=color, width=2)
    d.line([cx - gap - ray_len, cy, cx - gap, cy], fill=color, width=2)
    d.line([cx + gap, cy, cx + gap + ray_len, cy], fill=color, width=2)
    # Diagonals
    d1 = int(gap * 0.707)
    d2 = int((gap + ray_len) * 0.707)
    d.line([cx - d2, cy - d2, cx - d1, cy - d1], fill=color, width=2)
    d.line([cx + d1, cy - d1, cx + d2, cy - d2], fill=color, width=2)
    d.line([cx - d2, cy + d2, cx - d1, cy + d1], fill=color, width=2)
    d.line([cx + d1, cy + d1, cx + d2, cy + d2], fill=color, width=2)
    return img


def create_moon_icon(size: int = 24, dark_color: bool = True) -> Image.Image:
    """
    Generates a crisp crescent moon icon.
    In light mode (dark_color=True), uses rich dark slate (#0f172a / #1e293b)
    for high contrast against light gray backgrounds.
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Dark slate for light mode (#1e293b), light slate for dark mode (#cbd5e1)
    color = (30, 41, 59, 255) if dark_color else (203, 213, 225, 255)
    cx, cy = size // 2, size // 2
    r = size // 3 + 1
    # Main moon circle
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
    # Cutout with offset transparent circle to form crescent
    d.ellipse([cx - r + 5, cy - r - 3, cx + r + 5, cy + r - 3], fill=(0, 0, 0, 0))
    return img


def create_eye_icon(show: bool = False, dark_theme: bool = True, size: int = 24) -> Image.Image:
    """Generates a centered eye / eye-off icon."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (203, 213, 225, 255) if dark_theme else (30, 41, 59, 255)
    cx, cy = size // 2, size // 2

    # Outer eye arc
    w = size // 2 - 2
    h = size // 4 + 1
    d.arc([cx - w, cy - h, cx + w, cy + h], start=0, end=180, fill=color, width=2)
    d.arc([cx - w, cy - h, cx + w, cy + h], start=180, end=360, fill=color, width=2)

    # Center pupil
    pr = 3
    d.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=color)

    # Slash line if show password
    if show:
        d.line([cx - w + 2, cy - h, cx + w - 2, cy + h], fill=color, width=2)

    return img


_sun_img = None
_moon_dark_img = None
_moon_light_img = None
_eye_closed_dark = None
_eye_closed_light = None
_eye_open_dark = None
_eye_open_light = None


def get_theme_image(is_dark: bool) -> ctk.CTkImage:
    global _sun_img, _moon_dark_img
    if _sun_img is None:
        _sun_img = create_sun_icon(24)
    if _moon_dark_img is None:
        _moon_dark_img = create_moon_icon(24, dark_color=True)

    # In dark mode show Sun (amber), in light mode show Moon (dark slate for high contrast)
    icon = _sun_img if is_dark else _moon_dark_img
    return ctk.CTkImage(light_image=icon, dark_image=icon, size=(16, 16))


def get_eye_image(is_open: bool) -> ctk.CTkImage:
    global _eye_closed_dark, _eye_closed_light, _eye_open_dark, _eye_open_light
    if _eye_closed_dark is None:
        _eye_closed_dark = create_eye_icon(show=False, dark_theme=True)
        _eye_closed_light = create_eye_icon(show=False, dark_theme=False)
        _eye_open_dark = create_eye_icon(show=True, dark_theme=True)
        _eye_open_light = create_eye_icon(show=True, dark_theme=False)

    if is_open:
        return ctk.CTkImage(light_image=_eye_open_light, dark_image=_eye_open_dark, size=(16, 16))
    else:
        return ctk.CTkImage(light_image=_eye_closed_light, dark_image=_eye_closed_dark, size=(16, 16))
