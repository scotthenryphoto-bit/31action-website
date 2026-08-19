from pathlib import Path
import json
ROOT=Path(__file__).parent; IMG=ROOT/'images'; valid={'.jpg','.jpeg','.png','.webp','.gif','.avif'}
def imgs(folder):
    if not folder.exists(): return []
    seen=set();out=[]
    for p in sorted(folder.iterdir(),key=lambda p:p.name.lower()):
        if p.is_file() and p.suffix.lower() in valid and p.name.lower() not in seen:
            seen.add(p.name.lower());out.append(p.relative_to(ROOT).as_posix())
    return out
data={c:imgs(IMG/c) for c in ['landing','sports','portraits','events','other']}
seen=set()
for c in ['sports','portraits','events','other']:
    unique=[]
    for path in data[c]:
        name=Path(path).name.lower()
        if name in seen: continue
        seen.add(name);unique.append(path)
    data[c]=unique
shoots=[]; recent=IMG/'recent-shoots'
if recent.exists():
    for folder in sorted([p for p in recent.iterdir() if p.is_dir()],key=lambda p:p.name.lower(),reverse=True):
        photos=imgs(folder)
        if photos: shoots.append({'id':folder.name,'title':folder.name.replace('_',' ').replace('-',' '),'photos':photos})
(ROOT/'assets/js/images.js').write_text('window.SITE_IMAGES = '+json.dumps(data,indent=2)+';\nwindow.SITE_SHOOTS = '+json.dumps(shoots,indent=2)+';\n',encoding='utf-8')
print('Updated image lists.',{k:len(v) for k,v in data.items()},'Recent shoots:',len(shoots))
