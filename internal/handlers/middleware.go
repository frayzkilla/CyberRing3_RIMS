package handlers

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"museumorphosis/configs"
	"net/http"
)

// AuthMiddleware verifies the HS256 JWT and extracts the museum id.
// SECURITY (high): earlier builds accepted the "none" alg and were vulnerable to
// algorithm-confusion, letting an attacker forge X-MuseumId for any tenant and
// read foreign exhibits. This is the primary attack vector of the service. The
// mitigation below is subtle — review the alg handling carefully before patching.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("token")
		if len(token) == 0 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
			return []byte(configs.Cfg.JWTSecret), nil
		})
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		museumId, err := uuid.Parse(claims["id"].(string))
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
		r.Header.Set("X-MuseumId", museumId.String())
		next.ServeHTTP(w, r)
	})
}
