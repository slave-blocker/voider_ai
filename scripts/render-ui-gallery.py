#!/usr/bin/env python3
"""Make a browsable contact sheet from the real C++ 320x240 renderer."""
from pathlib import Path
import subprocess
from PIL import Image, ImageDraw
root=Path(__file__).resolve().parent.parent
out=root/'artifacts/ui-320x240'
subprocess.run([str(root/'build/voider-ui'),'--render-dir',str(out)],check=True)
html='<meta charset="utf-8"><title>Voider 320×240</title><style>body{background:#0d2b37;color:#fff;font:18px sans-serif}section{display:flex;flex-wrap:wrap;gap:16px}figure{margin:0}img{display:block;width:320px;height:240px}figcaption{padding:8px}a{color:#fff}</style>'
for lang in ('en','de','bg'):
    files=sorted((out/lang).glob('*.ppm'))
    sheet=Image.new('RGB',(1280,((len(files)+3)//4)*262),'#cccccc');draw=ImageDraw.Draw(sheet)
    for i,p in enumerate(files):
        im=Image.open(p);im.save(p.with_suffix('.png'))
        sheet.paste(im,((i%4)*320,(i//4)*262));draw.text(((i%4)*320+4,(i//4)*262+242),p.stem,fill='black')
    sheet.save(out/(lang+'-contact-sheet.png'))
    for start in range(0,len(files),36):
        part=Image.new('RGB',(1920,1572),'#cccccc');d=ImageDraw.Draw(part)
        for i,p in enumerate(files[start:start+36]):
            part.paste(Image.open(p),((i%6)*320,(i//6)*262));d.text(((i%6)*320+4,(i//6)*262+242),p.stem,fill='black')
        part.save(out/(lang+'-sheet-'+str(start//36)+'.png'))
    html+='<h1 id="'+lang+'">'+lang+'</h1><section>'+''.join('<figure><a href="'+lang+'/'+p.stem+'.txt"><img src="'+lang+'/'+p.stem+'.png"></a><figcaption>'+p.stem+'</figcaption></figure>' for p in files)+'</section>'
(out/'index.html').write_text(html)
