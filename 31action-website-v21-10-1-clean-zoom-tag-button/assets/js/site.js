function webPath(p){return String(p||'').replace(/\\/g,'/')}
const menu=document.querySelector('.menu-btn'),nav=document.querySelector('.main-nav');
if(menu)menu.addEventListener('click',()=>nav.classList.toggle('open'));

const CROP_KEY='31action_crops_v3';
function savedCrops(){try{return JSON.parse(localStorage.getItem(CROP_KEY)||'{}')}catch(e){return{}}}
function allCrops(){return Object.assign({},window.IMAGE_CROPS||{},savedCrops())}
function cropFor(path){
  const c=allCrops()[path]||{},mobile=window.matchMedia('(max-width:620px)').matches;
  const v=(mobile?c.mobile:c.desktop)||c.desktop||c.mobile||{x:50,y:50};
  if(v&&Number.isFinite(+v.w)&&Number.isFinite(+v.h)) return {fit:'cover',rect:{x:+v.x,y:+v.y,w:+v.w,h:+v.h}};
  return {fit:c.fit||'cover',pos:(v&&Number.isFinite(+v.x))?v:{x:50,y:50}};
}
function applyCrop(img,path){
  const c=cropFor(path);img.style.objectFit=c.fit;
  if(c.rect){const cx=c.rect.x+c.rect.w/2,cy=c.rect.y+c.rect.h/2;img.style.objectPosition=`${cx}% ${cy}%`}
  else img.style.objectPosition=`${c.pos.x}% ${c.pos.y}%`;
}
function applyBackgroundCrop(el,path){
  const c=cropFor(path);el.style.backgroundRepeat='no-repeat';el.style.backgroundColor='#090909';
  if(c.rect){
    const w=Math.max(.01,Math.min(.9999,c.rect.w/100)),h=Math.max(.01,Math.min(.9999,c.rect.h/100));
    const px=(1-w)<.0001?50:(c.rect.x/100)/(1-w)*100,py=(1-h)<.0001?50:(c.rect.y/100)/(1-h)*100;
    el.style.backgroundSize=`${100/w}% auto`;el.style.backgroundPosition=`${px}% ${py}%`;
  }else{
    el.style.backgroundPosition=`${c.pos.x}% ${c.pos.y}%`;el.style.backgroundSize=c.fit==='contain'?'contain':'cover';
  }
}
function refreshCrops(){document.querySelectorAll('img[data-crop-src]').forEach(i=>applyCrop(i,i.dataset.cropSrc));document.querySelectorAll('[data-bg-crop-src]').forEach(e=>applyBackgroundCrop(e,e.dataset.bgCropSrc))}
window.addEventListener('resize',refreshCrops);window.addEventListener('storage',refreshCrops);setTimeout(refreshCrops,0);

// Hero slideshow with per-slide timing.
let heroTimer=null,heroIndex=0,heroSignature='';
function scheduleHero(){
  const slides=[...document.querySelectorAll('#slides .hero-slide')];
  if(slides.length<2)return;
  clearTimeout(heroTimer);
  const current=slides[heroIndex]||slides[0];
  const delay=Math.max(1000,Math.min(60000,Number(current.dataset.duration)||5200));
  heroTimer=setTimeout(()=>{
    slides[heroIndex]?.classList.remove('active');
    heroIndex=(heroIndex+1)%slides.length;
    slides[heroIndex]?.classList.add('active');
    scheduleHero();
  },delay);
}
function initHeroSlideshow(){
  const slides=[...document.querySelectorAll('#slides .hero-slide')];
  if(!slides.length)return false;
  const sig=slides.map(x=>(x.dataset.duration||'')+(x.querySelector('img')?.src||x.style.backgroundImage||'')).join('|');
  if(sig===heroSignature&&heroTimer)return true;
  heroSignature=sig;heroIndex=0;clearTimeout(heroTimer);heroTimer=null;
  slides.forEach((x,i)=>x.classList.toggle('active',i===0));
  scheduleHero();return true;
}
if(!initHeroSlideshow()){
 const r=document.getElementById('slides');if(r){const o=new MutationObserver(()=>{if(initHeroSlideshow())o.disconnect()});o.observe(r,{childList:true})}
}
window.addEventListener('hero:rebuilt',initHeroSlideshow);

// Full-photo lightbox: no cropping, keyboard arrows supported.
let lightbox=document.querySelector('.lightbox'),lightboxIndex=0,lightboxImages=[];
function ensureLightbox(){
  if(!lightbox){lightbox=document.createElement('div');lightbox.className='lightbox';document.body.appendChild(lightbox)}
  if(!lightbox.querySelector('.lightbox-prev')) lightbox.innerHTML='<button class="lightbox-close" aria-label="Close photo">×</button><button class="lightbox-prev" aria-label="Previous photo">‹</button><div class="lightbox-stage"><div class="lightbox-photo-wrap"><span class="lightbox-cart-badge">Added to Cart</span><img alt="Expanded photograph"></div><div class="lightbox-count" aria-live="polite"></div></div><button class="lightbox-next" aria-label="Next photo">›</button><aside class="lightbox-order" aria-label="Order this photo"><button class="lightbox-order-tab" type="button">Order This Photo</button><div class="lightbox-order-body"><div class="lightbox-order-file"></div><button class="lightbox-tag-photo" type="button">Tag This Photo</button><div class="lightbox-player-tags"></div><label>Product<select class="lightbox-product"></select></label><label>Quantity<input class="lightbox-qty" type="number" min="1" value="1"></label><button class="lightbox-add" type="button">Add to Cart</button><div class="lightbox-order-summary"></div></div></aside>';
  return lightbox;
}
function getLightboxImages(){return [...document.querySelectorAll('.gallery-item img,.sale-photo img')].filter(i=>i.offsetParent!==null)}
function moneyLb(v){try{return new Intl.NumberFormat('en-US',{style:'currency',currency:(window.STORE_CONFIG||{}).currency||'USD'}).format(v)}catch(e){return '$'+Number(v||0).toFixed(2)}}
function saleContext(source){
  const card=source?.closest('.sale-item'); if(!card)return null;
  const shootId=card.dataset.shootId||'',shootTitle=card.dataset.shootTitle||'',photoPath=card.dataset.photoPath||(source.getAttribute('src')||''),photoIndex=Number(card.dataset.photoIndex)||1,filename=card.dataset.filename||photoPath.split('/').pop(),photoId=card.dataset.photoId||'';
  return {card,shootId,shootTitle,photoPath,photoIndex,filename,photoId};
}
function lightboxCartSummary(ctx){
  if(!ctx||!window.Cart)return '';
  const items=Cart.forPhoto(ctx.shootId,ctx.photoPath); if(!items.length)return '';
  return '<strong>In your cart</strong>'+items.map(x=>`<div class="in-cart-line"><span>${x.productLabel}</span><span>×${x.quantity}</span></div>`).join('');
}
function updateLightboxOrder(source){
  const lb=ensureLightbox(),panel=lb.querySelector('.lightbox-order'),wrap=lb.querySelector('.lightbox-photo-wrap'),badge=lb.querySelector('.lightbox-cart-badge'),ctx=saleContext(source);
  lb._saleSource=source||null;lb._saleContext=ctx;
  if(!ctx||!window.STORE_CONFIG||!window.Cart){panel.classList.remove('available','expanded');wrap.classList.remove('in-cart');badge.style.display='none';return}
  panel.classList.add('available');
  const items=Cart.forPhoto(ctx.shootId,ctx.photoPath),select=panel.querySelector('.lightbox-product');
  const cardSelect=ctx.card.querySelector('.product-select'),selected=cardSelect?.value||select.value||STORE_CONFIG.products[0]?.id||'';
  select.innerHTML=STORE_CONFIG.products.map(p=>`<option value="${p.id}" ${p.id===selected?'selected':''}>${p.label} — ${moneyLb(p.price)}</option>`).join('');
  panel.querySelector('.lightbox-order-file').textContent=`Photo ${ctx.photoIndex} · ${ctx.filename}`;
  const sourceTags=ctx.card.querySelector('.photo-player-tags-display');
  panel.querySelector('.lightbox-player-tags').innerHTML=sourceTags && !sourceTags.hidden
    ? sourceTags.innerHTML
    : '';
  panel.querySelector('.lightbox-order-summary').innerHTML=lightboxCartSummary(ctx);
  wrap.classList.toggle('in-cart',items.length>0);badge.style.display=items.length?'block':'none';
  panel.querySelector('.lightbox-add').textContent=items.length?'Add Another':'Add to Cart';
}
function showLightbox(index){const lb=ensureLightbox();lightboxImages=getLightboxImages();if(!lightboxImages.length)return;lightboxIndex=(index+lightboxImages.length)%lightboxImages.length;const source=lightboxImages[lightboxIndex],img=lb.querySelector('img');img.src=source.currentSrc||source.src;img.alt=source.alt||'Expanded photograph';lb.querySelector('.lightbox-count').textContent=`${lightboxIndex+1} / ${lightboxImages.length}`;updateLightboxOrder(source);lb.classList.add('open');document.body.classList.add('lightbox-open')}
function closeLightbox(){if(!lightbox)return;lightbox.classList.remove('open');document.body.classList.remove('lightbox-open')}
function moveLightbox(delta){if(lightbox?.classList.contains('open'))showLightbox(lightboxIndex+delta)}
document.addEventListener('click',e=>{const img=e.target.closest('.gallery-item img,.sale-photo img');if(img){if(document.body.classList.contains('player-tag-mode')){e.preventDefault();e.stopPropagation();return}lightboxImages=getLightboxImages();showLightbox(lightboxImages.indexOf(img));return}if(!lightbox)return;
  if(e.target.closest('.lightbox-order-tab')){lightbox.querySelector('.lightbox-order').classList.toggle('expanded');return}
  if(e.target.closest('.lightbox-add')){const ctx=lightbox._saleContext;if(!ctx||!window.STORE_CONFIG||!window.Cart)return;const panel=lightbox.querySelector('.lightbox-order'),p=STORE_CONFIG.products.find(p=>p.id===panel.querySelector('.lightbox-product').value);if(!p)return;const q=Math.max(1,Number(panel.querySelector('.lightbox-qty').value)||1);Cart.add({shootId:ctx.shootId,shootTitle:ctx.shootTitle,photoIndex:ctx.photoIndex,photoPath:ctx.photoPath,filename:ctx.filename,productId:p.id,productLabel:p.label,price:p.price,requiresShipping:p.requiresShipping,quantity:q});updateLightboxOrder(lightbox._saleSource);return}
  if(e.target.closest('.lightbox-tag-photo')){
    const ctx=lightbox._saleContext;
    if(!ctx?.photoId || typeof window.startTagPlayer!=='function')return;
    closeLightbox();
    window.startTagPlayer();
    const card=ctx.card;
    if(window.tagSelectedPhotos){
      window.tagSelectedPhotos.add(String(ctx.photoId));
    }
    card?.classList.add('tag-selected');
    if(typeof window.updateTagSelectionUI==='function')window.updateTagSelectionUI();
    document.getElementById('tag-player-panel')?.scrollIntoView({behavior:'smooth',block:'start'});
    return;
  }
  if(e.target.closest('.lightbox-close'))closeLightbox();
  else if(e.target.closest('.lightbox-prev'))moveLightbox(-1);
  else if(e.target.closest('.lightbox-next'))moveLightbox(1);
  else if(e.target.closest('.lightbox-photo-wrap img'))closeLightbox();
  else if(e.target===lightbox)closeLightbox()});
window.addEventListener('cart:changed',()=>{if(lightbox?.classList.contains('open')&&lightbox._saleSource)updateLightboxOrder(lightbox._saleSource)});
window.refreshLightboxPlayerTags=()=>{if(lightbox?.classList.contains('open')&&lightbox._saleSource)updateLightboxOrder(lightbox._saleSource)};
document.addEventListener('keydown',e=>{if(!lightbox?.classList.contains('open'))return;if(e.key==='ArrowLeft'){e.preventDefault();moveLightbox(-1)}else if(e.key==='ArrowRight'){e.preventDefault();moveLightbox(1)}else if(e.key==='Escape'){e.preventDefault();closeLightbox()}});

const CART_KEY='31action_cart_v2';
window.Cart={
 get(){try{return JSON.parse(localStorage.getItem(CART_KEY)||'[]')}catch(e){return[]}},
 save(a){localStorage.setItem(CART_KEY,JSON.stringify(a));this.updateBadges();window.dispatchEvent(new CustomEvent('cart:changed',{detail:a}))},
 add(x){const a=this.get(),same=a.find(i=>i.shootId===x.shootId&&i.photoPath===x.photoPath&&i.productId===x.productId);if(same)same.quantity=(Number(same.quantity)||1)+(Number(x.quantity)||1);else a.push({...x,cartId:Date.now()+'-'+Math.random().toString(36).slice(2,8)});this.save(a)},
 remove(id){this.save(this.get().filter(x=>x.cartId!==id))},
 clear(){this.save([])},
 forPhoto(shootId,photoPath){return this.get().filter(x=>x.shootId===shootId&&x.photoPath===photoPath)},
 updateBadges(){const n=this.get().reduce((s,x)=>s+(Number(x.quantity)||1),0);document.querySelectorAll('.cart-count').forEach(el=>{el.textContent=n;el.hidden=n===0})}
};Cart.updateBadges();

const ORDER_KEY='31action_test_orders_v1';
window.TestOrders={get(){try{return JSON.parse(localStorage.getItem(ORDER_KEY)||'[]')}catch(e){return[]}},add(order){const a=this.get();a.unshift(order);localStorage.setItem(ORDER_KEY,JSON.stringify(a));window.dispatchEvent(new CustomEvent('orders:changed'))}};


// V19 mobile navigation behavior: close after selection, outside tap, Escape,
// or about 3 seconds after opening.
(function(){
  const btn=document.querySelector('.menu-btn');
  const nav=document.querySelector('.main-nav');
  if(!btn||!nav)return;

  let autoCloseTimer=null;

  function isOpen(){
    return nav.classList.contains('open') ||
           document.body.classList.contains('menu-open') ||
           btn.getAttribute('aria-expanded')==='true';
  }

  function closeMenu(){
    nav.classList.remove('open');
    document.body.classList.remove('menu-open');
    btn.setAttribute('aria-expanded','false');
    if(autoCloseTimer){clearTimeout(autoCloseTimer);autoCloseTimer=null}
  }

  function armAutoClose(){
    if(autoCloseTimer)clearTimeout(autoCloseTimer);
    autoCloseTimer=setTimeout(closeMenu,3000);
  }

  btn.addEventListener('click',()=>{
    setTimeout(()=>{ if(isOpen()) armAutoClose(); },0);
  });

  nav.querySelectorAll('a').forEach(a=>a.addEventListener('click',closeMenu));

  document.addEventListener('pointerdown',e=>{
    if(!isOpen())return;
    if(nav.contains(e.target)||btn.contains(e.target))return;
    closeMenu();
  });

  document.addEventListener('keydown',e=>{
    if(e.key==='Escape')closeMenu();
  });

  nav.addEventListener('pointerenter',()=>{
    if(autoCloseTimer){clearTimeout(autoCloseTimer);autoCloseTimer=null}
  });
  nav.addEventListener('pointerleave',()=>{
    if(isOpen())armAutoClose();
  });
})();
