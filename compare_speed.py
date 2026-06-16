import socket, struct, time, urllib.request
URLS = [
    'http://speedtest.tele2.net/10MB.zip',
    'http://ipv4.download.thinkbroadband.com/10MB.zip',
    'http://speed.cloudflare.com/__down?bytes=10485760',
]

def direct(url):
    t=time.time(); total=0
    try:
        req=urllib.request.Request(url, headers={'User-Agent':'42IPwin-test'})
        with urllib.request.urlopen(req, timeout=20) as r:
            while True:
                b=r.read(65536)
                if not b: break
                total += len(b)
        dt=time.time()-t
        print('DIRECT', url, total, round(total*8/dt/1e6,2), 'Mbps', round(dt,2),'s')
    except Exception as e:
        print('DIRECT ERR', url, type(e).__name__, e)

def read_exact(sock,n):
    d=b''
    while len(d)<n:
        c=sock.recv(n-len(d))
        if not c: raise RuntimeError('closed')
        d+=c
    return d

def socks_get(url, proxy_host, proxy_port, user, pwd):
    from urllib.parse import urlparse
    p=urlparse(url); host=p.hostname; path=(p.path or '/') + (('?' + p.query) if p.query else '')
    t=time.time(); total=0
    try:
        s=socket.create_connection((proxy_host,proxy_port), timeout=10); s.settimeout(20)
        s.sendall(b'\x05\x01\x02'); print('method', read_exact(s,2))
        ub=user.encode(); pb=pwd.encode()
        s.sendall(b'\x01'+bytes([len(ub)])+ub+bytes([len(pb)])+pb); print('auth', read_exact(s,2))
        hb=host.encode(); s.sendall(b'\x05\x01\x00\x03'+bytes([len(hb)])+hb+struct.pack('!H', p.port or 80))
        head=read_exact(s,4); print('head', head)
        if head[1]!=0: raise RuntimeError(f'connect {head!r}')
        atyp=head[3]
        if atyp==1: read_exact(s,4)
        elif atyp==3: read_exact(s, read_exact(s,1)[0])
        elif atyp==4: read_exact(s,16)
        read_exact(s,2)
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: 42IPwin-test\r\n\r\n'.encode())
        header=False; buf=b''; status=b''
        while True:
            b=s.recv(65536)
            if not b: break
            if not header:
                buf += b
                pos=buf.find(b'\r\n\r\n')
                if pos>=0:
                    status=buf.split(b'\r\n',1)[0]
                    header=True; total += len(buf)-pos-4; buf=b''
            else: total += len(b)
        s.close(); dt=time.time()-t
        print('SOCKS', proxy_host, proxy_port, url, status.decode(errors='ignore'), total, round(total*8/dt/1e6,2),'Mbps',round(dt,2),'s')
    except Exception as e:
        print('SOCKS ERR', proxy_host, proxy_port, url, type(e).__name__, e)

for u in URLS: direct(u)
for node in [('169.214.190.43',10801,'user','T33Ew1H83cAm'),('210.183.143.207',10804,'user','g4BFweQV5lTu')]:
    for u in URLS: socks_get(u,*node)
