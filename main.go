package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp" // Ekran görüntüsü için
	"golang.org/x/net/proxy"       //Tor proxy desteği için
)

func main() {
	// Tor altyapısını hazırlama
	proxyAddr := "127.0.0.1:9150"
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Proxy dialer oluşturulamadı: %v", err)
	}

	contextDialer := dialer.(proxy.ContextDialer)
	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 60,
	}

	// Chromedp (Tor üzerinden çalışan Chromium yapılandırması)
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer(fmt.Sprintf("socks5://127.0.0.1:%d", 9150)), // Tor proxy
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-images", false),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("blink-settings", "imagesEnabled=true"),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel() // bu deferleri atıyoz ki takılı kalmasın

	// Log dosyasını oluşturma ve başlatma
	reportFile, err := os.OpenFile("scan_report.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Log dosyası açılamadı: %v", err)
	}
	defer reportFile.Close()
	fmt.Fprintf(reportFile, "\n--- Tarama Oturumu Başladı: %s ---\n", time.Now().Format("2006-01-02 15:04:05"))

	// Kullanıcıdan alınan dosya alıp satır temizleme
	var filepath string
	fmt.Print(".yaml dosyasının yolunu giriniz: ")
	fmt.Scanln(&filepath)
	filepath = strings.TrimSpace(filepath)

	userfile, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Dosya açılamadı: %v", err)
	}
	defer userfile.Close()

	linkCounter := 0
	scanner := bufio.NewScanner(userfile)
	for scanner.Scan() {
		oniurls := strings.TrimSpace(scanner.Text())
		if oniurls == "" || strings.HasPrefix(oniurls, "#") {
			continue
		}
		// En önemli yerlerden biri gizlilik kontrolü
		if !Check_Tor(client) {
			errMsg := "KRİTİK HATA: Tor bağlantısı koptu!"
			fmt.Println("\n[!!!]", errMsg)
			fmt.Fprintln(reportFile, errMsg)
			break
		}

		linkCounter++
		fmt.Printf("\n[%d] İşleniyor: %s\n", linkCounter, oniurls)

		// Burada HTTP isteği atılıp siteyi kontrol ediyoruz
		resp, err := client.Get(oniurls)
		if err != nil {
			msg := fmt.Sprintf("[%d] %s | DURUM: PASİF | HATA: %v", linkCounter, oniurls, err)
			fmt.Println("[!] Siteye ulaşılamadı.")
			fmt.Fprintln(reportFile, msg)
			continue
		}
		resp.Body.Close()

		// Chromedp ile Ekran Görüntüsü
		taskCtx, taskCancel := chromedp.NewContext(allocCtx)
		taskCtx, _ = context.WithTimeout(taskCtx, 60*time.Second) //Timeout süresi kötü net bağlantılar için uzun

		var buf []byte
		err = chromedp.Run(taskCtx,
			chromedp.EmulateViewport(1920, 1080),
			chromedp.Navigate(oniurls),
			chromedp.Sleep(11*time.Second),
			chromedp.CaptureScreenshot(&buf),
		)

		if err != nil {
			msg := fmt.Sprintf("[%d] %s | DURUM: AKTİF (SS HATASI) | HATA: %v", linkCounter, oniurls, err)
			fmt.Printf("[!] Ekran görüntüsü alınamadı: %v\n", err)
			fmt.Fprintln(reportFile, msg)
			taskCancel()
			continue
		}

		// Log dosyasına kaydetme
		safeName := fmt.Sprintf("%d_link.png", linkCounter)
		if err := os.WriteFile(safeName, buf, 0644); err != nil {
			msg := fmt.Sprintf("[%d] %s | DURUM: AKTİF | DOSYA HATASI: %v", linkCounter, oniurls, err)
			fmt.Fprintln(reportFile, msg)
		} else {
			msg := fmt.Sprintf("[%d] %s | DURUM: AKTİF | DOSYA: %s", linkCounter, oniurls, safeName)
			fmt.Printf("[✓] Başarıyla kaydedildi: %s\n", safeName)
			fmt.Fprintln(reportFile, msg)
		}

		taskCancel()
		time.Sleep(2 * time.Second)
	}
	fmt.Fprintf(reportFile, "--- Tarama Oturumu Tamamlandı: %s ---\n", time.Now().Format("15:04:05"))
}
