#!/usr/bin/env python3
"""Check PDF geometry/text/fonts and render every page into four-page proof sheets.

Requires Poppler (pdfinfo, pdffonts, pdftotext, pdftoppm) and Python Pillow.
Output is disposable, below .build/review. Human inspection is still necessary.
"""
from pathlib import Path
import re
import subprocess
import unicodedata
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw

here = Path(__file__).resolve().parent
release = here.parent.parent / 'release'
out = here / '.build/review'
out.mkdir(parents=True, exist_ok=True)
chapter_count = len(re.findall(r'\\page\{', (here / 'en.tex').read_text()))
for edition in ('de', 'en', 'bg', 'de-en-bg'):
    pdf = release / f'voider-manual-{edition}.pdf'
    info = subprocess.check_output(['pdfinfo', str(pdf)], text=True)
    count = int(re.search(r'Pages:\s+(\d+)', info)[1])
    expected = chapter_count if edition != 'de-en-bg' else chapter_count * 3 + 1
    assert count == expected, (edition, count, expected, 'unintended page break')
    fonts = subprocess.check_output(['pdffonts', str(pdf)], text=True)
    assert 'Type 3' not in fonts, (edition, 'bitmap font')
    assert all(re.search(r'yes\s+yes\s+yes\s+\d+\s+\d+\s*$', line)
               for line in fonts.splitlines()[2:]), (edition, 'font not embedded/subset/Unicode')
    xml = subprocess.check_output(['pdftotext', '-bbox', str(pdf), '-'])
    root = ET.fromstring(xml)
    for n, page in enumerate(root.findall('.//{*}page'), 1):
        width, height = float(page.attrib['width']), float(page.attrib['height'])
        assert abs(width - 419.528) < 0.1 and abs(height - 595.276) < 0.1
        words = page.findall('.//{*}word')
        assert words and words[0].text == 'VOIDER', (edition, n, 'orphan continuation')
        for word in words:
            x0, y0, x1, y1 = (float(word.attrib[k]) for k in ('xMin', 'yMin', 'xMax', 'yMax'))
            assert 25 < x0 < x1 < width - 25 and 20 < y0 < y1 < height - 18, (edition, n, word.text)
            assert '\ufffd' not in (word.text or '')
    text = subprocess.check_output(['pdftotext', str(pdf), '-'], text=True)
    if edition in ('bg', 'de-en-bg'):
        assert all(word in text for word in ('Вашият', 'Сдвояване', 'проверки'))
        if 'ѝ' in (here / 'bg.tex').read_text():
            assert 'ѝ' in unicodedata.normalize('NFC', text)
    # Only remove this utility's own earlier rasters, including stale extra pages.
    for stale in list(out.glob(edition + '-[0-9]*.png')) + list(out.glob(edition + '-sheet-*.png')):
        stale.unlink()
    subprocess.run(['pdftoppm', '-r', '110', '-png', str(pdf), str(out / edition)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    pages = sorted(out.glob(edition + '-[0-9]*.png'))
    assert len(pages) == count
    for start in range(0, count, 4):
        w, h = Image.open(pages[0]).size
        sheet = Image.new('RGB', (w * 2, (h + 25) * 2), '#d7dde0')
        draw = ImageDraw.Draw(sheet)
        for i, page in enumerate(pages[start:start + 4]):
            x, y = (i % 2) * w, (i // 2) * (h + 25)
            draw.text((x + 8, y + 5), f'{edition} / page {start + i + 1}', fill='#0d2b37')
            sheet.paste(Image.open(page), (x, y + 25))
        sheet.save(out / f'{edition}-sheet-{start // 4 + 1:02}.png')
    print(f'{pdf.name}: {count} A5 pages; embedded Unicode Type 1 fonts; text bounds pass; all pages rendered')
