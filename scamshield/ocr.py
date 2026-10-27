"""Read text out of a screenshot (WhatsApp / SMS / email) with Tesseract.

Hindi needs the 'hin' language pack (packages.txt installs it on Streamlit Cloud).
"""

from __future__ import annotations

from PIL import Image, ImageOps


def available_langs() -> list[str]:
    try:
        import pytesseract

        return pytesseract.get_languages(config="")
    except Exception:
        return []


def image_to_text(img: Image.Image) -> str:
    import pytesseract

    langs = available_langs()
    lang = "eng+hin" if "hin" in langs else "eng"
    g = ImageOps.grayscale(img)
    if g.width < 1400:  # phone screenshots OCR much better upscaled
        scale = 1400 / g.width
        g = g.resize((int(g.width * scale), int(g.height * scale)), Image.LANCZOS)
    # Dark-mode screenshots: Tesseract prefers dark text on light background.
    if sum(g.resize((1, 1)).getdata()) < 110:
        g = ImageOps.invert(g)
    g = ImageOps.autocontrast(g)
    text = pytesseract.image_to_string(g, lang=lang, config="--psm 6")
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())
