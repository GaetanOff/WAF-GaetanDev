package proxy

import "sync"

// copyBufferSize est la taille de tampon qu'httputil.ReverseProxy alloue par
// défaut pour copier chaque corps de réponse.
const copyBufferSize = 32 * 1024

// bufferPool recycle les tampons de copie du reverse proxy. Sans BufferPool,
// httputil.ReverseProxy alloue 32 Kio par requête proxifiée : 320 Mo/s de
// déchets à 10 000 req/s, autant de travail pour le GC.
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{pool: sync.Pool{New: func() any {
		buffer := make([]byte, copyBufferSize)
		return &buffer
	}}}
}

// Get satisfait httputil.BufferPool.
func (p *bufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

// Put satisfait httputil.BufferPool. Seuls les tampons de taille nominale sont
// recyclés.
func (p *bufferPool) Put(buffer []byte) {
	if cap(buffer) != copyBufferSize {
		return
	}
	buffer = buffer[:copyBufferSize]
	p.pool.Put(&buffer)
}
