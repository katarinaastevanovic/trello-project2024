package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	mux := http.NewServeMux()

	mux.Handle("/api/projects/add", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager"}))
	mux.Handle("/api/projects/{id}/members", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager"}))
	mux.Handle("/api/projects/all", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"}))
	mux.Handle("/api/projects/{id}", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"}))
	mux.Handle("/api/projects/{projectId}/members/all", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"})) //
	mux.Handle("/api/projects/{projectId}/members/{memberId}/remove", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager"}))
	mux.Handle("/api/projects/users", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"}))
	mux.Handle("/api/projects/{id}/tasks", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"}))
	mux.Handle("/api/projects/{username}", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager", "member"}))
	mux.Handle("/api/projects/{id}/delete", authMiddleware(reverseProxyURL("http://projects-service:8003"), []string{"manager"}))

	// Rute za Tasks Service (samo menadžer dodaje zadatke, član menja status)
	mux.Handle("/api/tasks/create", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager"}))
	mux.Handle("/api/tasks/status", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"member"}))
	mux.Handle("/api/tasks/{taskID}/members", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager"}))
	mux.Handle("/api/tasks/all", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager", "member"}))
	mux.Handle("/api/tasks/project/{projectId}", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager", "member"}))
	mux.Handle("/api/tasks/{taskId}/members", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager", "member"}))
	mux.Handle("/api/tasks/{taskID}/add-members", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager"}))
	mux.Handle("/api/tasks/{taskID}/members/{memberID}", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager"}))
	mux.Handle("/api/tasks/{taskID}/project/{projectID}/available-members", authMiddleware(reverseProxyURL("http://tasks-service:8002"), []string{"manager"}))
	// Rute za Users Service (brisanje naloga dostupno svima)
	mux.Handle("/api/users/auth/delete-account", authMiddleware(reverseProxyURL("http://users-service:8001"), []string{"manager", "member"}))
	mux.Handle("/api/users/users-profile", authMiddleware(reverseProxyURL("http://users-service:8001"), []string{"manager", "member"}))
	mux.Handle("/api/users/check-username", authMiddleware(reverseProxyURL("http://users-service:8001"), []string{"manager", "member"}))
	mux.Handle("/api/users/change-password", authMiddleware(reverseProxyURL("http://users-service:8001"), []string{"manager", "member"}))

	// Rute za Notifications Service (samo članovi mogu da vide notifikacije)
	mux.Handle("/api/notifications", authMiddleware(reverseProxyURL("http://notifications-service:8004"), []string{"member"}))
	mux.Handle("/api/notifications/read", authMiddleware(reverseProxyURL("http://notifications-service:8004"), []string{"member"}))
	mux.Handle("/api/notifications/delete", authMiddleware(reverseProxyURL("http://notifications-service:8004"), []string{"member"}))

	// Pokretanje servera
	http.ListenAndServe(":8000", mux)
}

// Reverse Proxy funkcija
func reverseProxyURL(target string) http.Handler {
	url, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(url)

	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Role, Manager-ID")
		return nil
	}

	proxy.Director = func(req *http.Request) {
		fmt.Println("Authorization header:", req.Header.Get("Authorization"))
		fmt.Println("Role header:", req.Header.Get("Role"))              // Proveri ako Role header postoji
		req.Header.Set("Authorization", req.Header.Get("Authorization")) // Prosleđivanje Authorization header-a
		req.Header.Set("Role", req.Header.Get("Role"))                   // Prosleđivanje Role header-a
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
	}

	return proxy
}
