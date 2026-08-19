// 31 ACTION Cloudflare Worker starter. Admin writes require an ADMIN_TOKEN secret.
function unauthorized(){return new Response('Unauthorized',{status:401})}
function isAdmin(request, env){const h=request.headers.get('authorization')||'';return !!env.ADMIN_TOKEN && h===`Bearer ${env.ADMIN_TOKEN}`}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') return Response.json({ok:true, originals:!!env.ORIGINALS, previews:!!env.PREVIEWS, d1:!!env.DB});
    if (url.pathname.startsWith('/api/admin/upload-original/') && request.method === 'PUT') {
      if(!isAdmin(request,env)) return unauthorized();
      const key = decodeURIComponent(url.pathname.replace('/api/admin/upload-original/',''));
      if (!key) return new Response('Missing key',{status:400});
      await env.ORIGINALS.put(key, request.body, {httpMetadata:{contentType:request.headers.get('content-type')||'image/jpeg'}});
      return Response.json({ok:true,key});
    }
    if (url.pathname.startsWith('/api/admin/upload-preview/') && request.method === 'PUT') {
      if(!isAdmin(request,env)) return unauthorized();
      const key = decodeURIComponent(url.pathname.replace('/api/admin/upload-preview/',''));
      if (!key) return new Response('Missing key',{status:400});
      await env.PREVIEWS.put(key, request.body, {httpMetadata:{contentType:request.headers.get('content-type')||'image/jpeg'}});
      return Response.json({ok:true,key});
    }
    if (url.pathname.startsWith('/api/preview/') && request.method === 'GET') {
      const key=decodeURIComponent(url.pathname.replace('/api/preview/',''));
      const obj=await env.PREVIEWS.get(key); if(!obj)return new Response('Not found',{status:404});
      const headers=new Headers(); obj.writeHttpMetadata(headers); headers.set('etag',obj.httpEtag); headers.set('cache-control','public, max-age=86400');
      return new Response(obj.body,{headers});
    }
    return new Response('31 ACTION API — route not configured', {status:404});
  }
};
