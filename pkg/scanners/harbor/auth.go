package harbor

import "net/http"

func (s *harborScanner) auth(req *http.Request) {
	req.Header.Add("Accept", "application/json, */*")
	if s.username != "" && s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}
}
