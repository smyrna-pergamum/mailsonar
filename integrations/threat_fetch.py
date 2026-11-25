"""Explicit, read-only MISP/TAXII fetch. No evidence upload; no redirects."""
import argparse,json,getpass,urllib.request,urllib.parse,ssl
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

def fetch_page(url,mode,key):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.fragment: raise ValueError('Explicit HTTPS URL required')
    headers={'Accept':'application/taxii+json;version=2.1' if mode=='taxii' else 'application/json'}
    if key: headers['Authorization']=('Bearer '+key) if mode=='taxii' else key
    request=urllib.request.Request(url,headers=headers,method='GET')
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request,timeout=30) as response:
        raw=response.read(16*1024*1024+1)
        if len(raw)>16*1024*1024: raise ValueError('Response too large')
    data=json.loads(raw)
    return data
def fetch(url,mode,key,reader=fetch_page,max_pages=50,max_objects=100000):
    if mode!='taxii': return reader(url,mode,key)
    objects=[]; seen=set(); current=url
    for _ in range(max_pages):
        page=reader(current,mode,key)
        if not isinstance(page,dict) or not isinstance(page.get('objects'),list): raise ValueError('Invalid TAXII envelope')
        objects.extend(page['objects'])
        if len(objects)>max_objects: raise ValueError('TAXII object limit exceeded')
        if not page.get('more'): return {'objects':objects,'more':False}
        token=page.get('next')
        if not isinstance(token,str) or not token or len(token)>4096 or token in seen: raise ValueError('Invalid or repeated TAXII cursor')
        seen.add(token)
        parts=urllib.parse.urlsplit(url)
        query=[(k,v) for k,v in urllib.parse.parse_qsl(parts.query,keep_blank_values=True) if k!='next']
        query.append(('next',token))
        current=urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    raise ValueError('TAXII page limit exceeded; no incomplete result returned')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['misp','taxii']);p.add_argument('url');p.add_argument('output');a=p.parse_args();key=getpass.getpass('API key / bearer token (blank if none): ')
    data=fetch(a.url,a.mode,key)
    with open(a.output,'x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False)
