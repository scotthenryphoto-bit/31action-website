window.ActionPortfolio = {
  cropRect(item,mobile=false){
    const c=mobile?item?.crop_mobile:item?.crop_desktop;
    if(c?.excluded)return {excluded:true,x:0,y:0,w:100,h:100};

    if(c && Number.isFinite(+c.x) && Number.isFinite(+c.y)){
      const w=Math.max(5,Math.min(100,Number.isFinite(+c.w)?+c.w:100));
      const h=Math.max(5,Math.min(100,Number.isFinite(+c.h)?+c.h:100));
      return {
        excluded:false,
        x:Math.max(0,Math.min(100-w,+c.x)),
        y:Math.max(0,Math.min(100-h,+c.y)),
        w,h
      };
    }
    return {excluded:false,x:0,y:0,w:100,h:100};
  },

  renderExactCover(img,item,mobile=false){
    if(!img||!item)return Promise.resolve();
    const crop=this.cropRect(item,mobile);
    const container=img.parentElement;
    if(!container)return Promise.resolve();

    container.style.position='relative';
    container.style.overflow='hidden';
    container.style.background='#000';

    if(crop.excluded){
      img.style.visibility='hidden';
      return Promise.resolve();
    }
    img.style.visibility='';

    const apply=()=>{
      const nw=img.naturalWidth||0, nh=img.naturalHeight||0;
      const cw=container.clientWidth||0, ch=container.clientHeight||0;
      if(!nw||!nh||!cw||!ch)return;

      const sx=nw*(crop.x/100);
      const sy=nh*(crop.y/100);
      const sw=nw*(crop.w/100);
      const sh=nh*(crop.h/100);

      // FIT the entire selected crop inside the destination.
      // If aspect ratios differ, black bars remain instead of cutting more off.
      const scale=Math.min(cw/sw,ch/sh);
      const selectedW=sw*scale;
      const selectedH=sh*scale;

      const left=(cw-selectedW)/2 - sx*scale;
      const top=(ch-selectedH)/2 - sy*scale;

      img.style.position='absolute';
      img.style.maxWidth='none';
      img.style.maxHeight='none';
      img.style.width=(nw*scale)+'px';
      img.style.height=(nh*scale)+'px';
      img.style.left=left+'px';
      img.style.top=top+'px';
      img.style.objectFit='fill';
      img.style.objectPosition='initial';
      img.style.transform='none';
      img.style.transformOrigin='initial';
    };

    return new Promise(resolve=>{
      const done=()=>{apply();resolve()};
      if(img.complete && img.naturalWidth)done();
      else img.addEventListener('load',done,{once:true});

      if((img.getAttribute('src')||'')!==item.src)img.src=item.src;

      if(window.ResizeObserver){
        if(img.__exactCoverObserver)img.__exactCoverObserver.disconnect();
        img.__exactCoverObserver=new ResizeObserver(apply);
        img.__exactCoverObserver.observe(container);
      }
    });
  },

  applyCover(img,item,mobile=false){
    return this.renderExactCover(img,item,mobile);
  },


  cropFor(item,mode='slideshow',mobile=false){
    if(mode==='cover'){
      const c=mobile?item?.cover_crop_mobile:item?.cover_crop_desktop;
      if(c)return c;
    }
    return mobile?item?.crop_mobile:item?.crop_desktop;
  },

  renderCropInto(img,item,crop,allowBars=true){
    if(!img||!item)return Promise.reject(new Error('Missing crop image or item'));
    const container=img.parentElement;
    if(!container)return Promise.reject(new Error('Missing crop container'));

    const c=crop||{x:0,y:0,w:100,h:100,excluded:false};

    container.style.position='relative';
    container.style.overflow='hidden';
    container.style.background='#000';

    if(c.excluded){
      img.style.visibility='hidden';
      return Promise.resolve(false);
    }
    img.style.visibility='';

    const apply=()=>{
      const nw=img.naturalWidth||0;
      const nh=img.naturalHeight||0;

      // Some browsers report 0x0 on an absolutely-positioned slide while
      // its parent hero is already fully laid out. Fall back to the hero box.
      const hero=container.closest?.('.hero');
      const cr=container.getBoundingClientRect?.();
      const hr=hero?.getBoundingClientRect?.();

      const cw=
        container.clientWidth||
        Math.round(cr?.width||0)||
        hero?.clientWidth||
        Math.round(hr?.width||0)||
        0;

      const ch=
        container.clientHeight||
        Math.round(cr?.height||0)||
        hero?.clientHeight||
        Math.round(hr?.height||0)||
        0;

      if(!nw||!nh||!cw||!ch)return false;

      const x=Math.max(0,Math.min(100,Number(c.x)||0));
      const y=Math.max(0,Math.min(100,Number(c.y)||0));
      const w=Math.max(1,Math.min(100-x,Number(c.w)||100));
      const h=Math.max(1,Math.min(100-y,Number(c.h)||100));

      const sx=nw*x/100;
      const sy=nh*y/100;
      const sw=nw*w/100;
      const sh=nh*h/100;

      // Preserve the entire selected rectangle. This intentionally allows
      // black bars for vertical/tall crops instead of cutting the selection again.
      const scale=allowBars
        ? Math.min(cw/sw,ch/sh)
        : Math.max(cw/sw,ch/sh);

      const selectedW=sw*scale;
      const selectedH=sh*scale;
      const left=(cw-selectedW)/2-sx*scale;
      const top=(ch-selectedH)/2-sy*scale;

      img.style.position='absolute';
      img.style.display='block';
      img.style.maxWidth='none';
      img.style.maxHeight='none';
      img.style.width=(nw*scale)+'px';
      img.style.height=(nh*scale)+'px';
      img.style.left=left+'px';
      img.style.top=top+'px';
      img.style.margin='0';
      img.style.objectFit='fill';
      img.style.objectPosition='initial';
      img.style.transform='none';
      img.style.transformOrigin='initial';
      img.dataset.cropRendered='1';
      return true;
    };

    return new Promise((resolve,reject)=>{
      let attempts=0;
      let settled=false;

      const cleanup=()=>{
        img.removeEventListener('load',onLoad);
        img.removeEventListener('error',onError);
      };

      const tryApply=()=>{
        if(settled)return;
        if(apply()){
          settled=true;
          cleanup();
          resolve(true);
          return;
        }
        attempts++;
        if(attempts<90){
          requestAnimationFrame(tryApply);
        }else{
          settled=true;
          cleanup();
          reject(new Error('Crop destination never became measurable'));
        }
      };

      const onLoad=()=>requestAnimationFrame(tryApply);
      const onError=()=>{
        if(settled)return;
        settled=true;
        cleanup();
        reject(new Error('Image failed to load: '+(item.src||'')));
      };

      img.addEventListener('load',onLoad);
      img.addEventListener('error',onError);

      const wanted=String(item.src||'');
      if(!wanted){
        onError();
        return;
      }

      if((img.getAttribute('src')||'')!==wanted){
        img.src=wanted;
      }else if(img.complete&&img.naturalWidth){
        requestAnimationFrame(tryApply);
      }

      if(window.ResizeObserver){
        if(img.__cropObs)img.__cropObs.disconnect();
        img.__cropObs=new ResizeObserver(()=>apply());
        img.__cropObs.observe(container);
      }
    });
  },


  fallback: {
    sports: (window.SITE_IMAGES?.sports || []).map(x=>String(x).replace(/\\/g,'/')),
    portraits: (window.SITE_IMAGES?.portraits || []).map(x=>String(x).replace(/\\/g,'/')),
    events: (window.SITE_IMAGES?.events || []).map(x=>String(x).replace(/\\/g,'/')),
    other: (window.SITE_IMAGES?.other || []).map(x=>String(x).replace(/\\/g,'/'))
  },
  _legacy:null,
  async legacy(){
    if(this._legacy)return this._legacy;
    try{
      const d=await ActionAPI.legacyPortfolioSettings();
      this._legacy=d.items||[];
    }catch(e){this._legacy=[]}
    return this._legacy;
  },
  async allLocal(){
    const settings=await this.legacy(),byPath=new Map(settings.map(x=>[String(x.source_path).replace(/\\/g,'/'),x]));
    const rows=[];
    for(const originalCategory of ['sports','portraits','events','other']){
      (this.fallback[originalCategory]||[]).forEach((src,index)=>{
        const s=byPath.get(src)||{};
        rows.push({
          id:`local:${src}`,
          local:true,
          cloud:false,
          src,
          source_path:src,
          filename:src.split('/').pop(),
          original_category:originalCategory,
          category:s.category||originalCategory,
          hidden:!!s.hidden,
          is_cover:!!s.is_cover,
          home_enabled:!!s.home_enabled,
          sort_order:Number.isFinite(+s.sort_order)?+s.sort_order:index,
          crop_desktop:s.crop_desktop||null,
          crop_mobile:s.crop_mobile||null
        });
      });
    }
    return rows;
  },
  async cloud(category=null,home=false){
    try{
      const d=home?await ActionAPI.homePortfolio():await ActionAPI.portfolio(category||'');
      return (d.items||[]).map(x=>({...x,src:ActionAPI.base()+x.preview_url,cloud:true,local:false}));
    }catch(e){return[]}
  },
  dedupe(items){
    const seen=new Set(),out=[];
    for(const x of items){
      const key=`${x.category}|${String(x.filename||'').toLowerCase()}`;
      if(seen.has(key))continue;
      seen.add(key);out.push(x);
    }
    return out;
  },
  async items(category){
    const [locals,cloud]=await Promise.all([this.allLocal(),this.cloud(category)]);
    const localVisible=locals.filter(x=>!x.hidden&&x.category===category);
    const combined=[...cloud,...localVisible];
    combined.sort((a,b)=>{
      const ac=a.is_cover?1:0,bc=b.is_cover?1:0;
      if(ac!==bc)return bc-ac;
      if(a.cloud!==b.cloud)return a.cloud?-1:1;
      return (+a.sort_order||0)-(+b.sort_order||0);
    });
    return this.dedupe(combined);
  },
  async homeItems(){
    const [locals,cloud]=await Promise.all([this.allLocal(),this.cloud(null,true)]);
    const localHome=locals.filter(x=>!x.hidden&&x.home_enabled);
    const combined=[...cloud,...localHome];
    combined.sort((a,b)=>(+a.home_order||+a.sort_order||0)-(+b.home_order||+b.sort_order||0));
    return this.dedupe(combined);
  },
  async renderCategory(category, gridId='gallery-grid'){
    const grid=document.getElementById(gridId);if(!grid)return;
    const items=await this.items(category);
    grid.innerHTML=items.length?items.map((x,i)=>`<figure class="gallery-item"><img loading="lazy" src="${x.src}" alt="${x.alt_text||category+' photograph '+(i+1)}"></figure>`).join(''):'<div class="empty-state">No portfolio images are currently published in this category.</div>';
  }
};