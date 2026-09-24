package proxy

import "sync"

// copyBufferSize est la taille de tampon qu'httputil.ReverseProxy alloue par
// défaut pour copier chaque corps de réponse.
const copyBufferSize = 32 * 1024

// bufferPool recycle les tampons de copie du reverse proxy. Sans BufferPool,
// httputil.ReverseProxy alloue 32 Kio par requête proxifiée : 320 Mo/s de
// déchets à 10 000 req/s, autant de travail pour le GC.
//
// Le pool stocke des *[copyBufferSize]byte et non des *[]byte : Put reconvertit
// la tranche reçue en pointeur de tableau sans rien allouer, alors que
// `pool.Put(&buffer)` faisait échapper sur le tas l'en-tête de tranche du
// paramètre (24 octets) à chaque requête proxifiée.
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{pool: sync.Pool{New: func() any {
		return new([copyBufferSize]byte)
	}}}
}

// Get satisfait httputil.BufferPool.
func (p *bufferPool) Get() []byte {
	return p.pool.Get().(*[copyBufferSize]byte)[:]
}

// Put satisfait httputil.BufferPool. Seuls les tampons de taille nominale sont
// recyclés.
func (p *bufferPool) Put(buffer []byte) {
	if cap(buffer) != copyBufferSize {
		return
	}
	p.pool.Put((*[copyBufferSize]byte)(buffer[:copyBufferSize]))
}
