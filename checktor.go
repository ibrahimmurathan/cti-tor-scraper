package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func Check_Tor(client *http.Client) bool {
	//Tor ağına güvenli şekilde çıkış kontrolü yapıyoruz
	respns, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		fmt.Println("Tor ağına bağlanırken hata oluştu:", err)
		return false
	}
	defer respns.Body.Close()
	body, _ := io.ReadAll(respns.Body)
	return strings.Contains(string(body), `"IsTor":true`)
}
