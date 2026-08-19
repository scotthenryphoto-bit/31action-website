window.ActionSEO={
  pageKey(){
    const p=(location.pathname.split('/').pop()||'index.html').toLowerCase();
    const map={'index.html':'home','':'home','sports.html':'sports','portraits.html':'portraits','events.html':'events','other.html':'other','work.html':'portfolio','about.html':'about','contact.html':'contact','recent-shoots.html':'recent-shoots'};
    return map[p]||null;
  },
  setMeta(name,content,property=false){
    if(!content)return;
    let sel=property?`meta[property="${name}"]`:`meta[name="${name}"]`,el=document.querySelector(sel);
    if(!el){el=document.createElement('meta');el.setAttribute(property?'property':'name',name);document.head.appendChild(el)}
    el.setAttribute('content',content);
  },
  async apply(){
    try{
      const key=this.pageKey(); if(!key)return;
      const d=await ActionAPI.seo(),s=d.settings?.[key]; if(!s)return;
      if(s.title)document.title=s.title;
      this.setMeta('description',s.description);
      this.setMeta('og:title',s.social_title||s.title,true);
      this.setMeta('og:description',s.social_description||s.description,true);
      this.setMeta('og:type','website',true);
      this.setMeta('og:url',location.href.split('#')[0],true);
      this.setMeta('twitter:card','summary_large_image');
      this.setMeta('twitter:title',s.social_title||s.title);
      this.setMeta('twitter:description',s.social_description||s.description);
      let canon=document.querySelector('link[rel="canonical"]');
      if(!canon){canon=document.createElement('link');canon.rel='canonical';document.head.appendChild(canon)}
      canon.href=s.canonical||location.origin+location.pathname;
    }catch(e){}
  }
};document.addEventListener('DOMContentLoaded',()=>ActionSEO.apply());