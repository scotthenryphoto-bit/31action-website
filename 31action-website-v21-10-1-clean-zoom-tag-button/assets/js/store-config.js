window.STORE_CONFIG = {
  currency:"USD",
  products:[
    {id:"digital",label:"Digital Download",price:10.00,requiresShipping:false},
    {id:"print-4x6",label:"4 × 6 Print",price:8.00,requiresShipping:true},
    {id:"print-5x7",label:"5 × 7 Print",price:12.00,requiresShipping:true},
    {id:"print-8x10",label:"8 × 10 Print",price:20.00,requiresShipping:true},
    {id:"print-11x14",label:"11 × 14 Print",price:32.00,requiresShipping:true}
  ],
  digitalPackages:[
    {quantity:3,price:25,label:"Any 3 Digitals"},
    {type:"player_all",price:35,label:"All Photos of One Player",excludeTeamPhotos:true}
  ],
  shippingFlatRate:6.95, taxRate:0, paymentStatus:"not-connected"
};

window.ActionPricing = {
  async load() {
    try {
      const d = await ActionAPI.pricing();
      if (d && d.pricing) {
        if (Array.isArray(d.pricing.products)) STORE_CONFIG.products = d.pricing.products;
        if (Array.isArray(d.pricing.packages)) STORE_CONFIG.digitalPackages = d.pricing.packages;
        if (d.pricing.currency) STORE_CONFIG.currency = d.pricing.currency;
        window.dispatchEvent(new CustomEvent('pricing:loaded', {detail:d.pricing}));
        return d.pricing;
      }
    } catch (e) {}
    return null;
  }
};
