package cloudflare

import (
	"context"
	"net"
	"net/http"
	"net/netip"
)

const connectingIPHeader = "CF-Connecting-IP"

type realIPContextKey struct{}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceIP, err := remoteIP(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid remote address", http.StatusBadRequest)
			return
		}

		connectingIP := r.Header.Get(connectingIPHeader)
		if connectingIP == "" {
			next.ServeHTTP(w, withRealIP(r, sourceIP.String()))
			return
		}

		if !IsCloudflareIP(sourceIP) {
			http.Error(w, "forged CF-Connecting-IP header", http.StatusBadRequest)
			return
		}

		realIP, err := netip.ParseAddr(connectingIP)
		if err != nil {
			http.Error(w, "invalid CF-Connecting-IP header", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, withRealIP(r, realIP.String()))
	})
}

func RealIP(r *http.Request) string {
	if value, ok := r.Context().Value(realIPContextKey{}).(string); ok && value != "" {
		return value
	}

	ip, err := remoteIP(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip.String()
}

func IsCloudflareIP(ip netip.Addr) bool {
	for _, prefix := range cloudflareRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func withRealIP(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), realIPContextKey{}, ip)
	return r.WithContext(ctx)
}

func remoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return netip.ParseAddr(host)
}
