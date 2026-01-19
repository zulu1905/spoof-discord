package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func runSettingsGUI() {
	myApp := app.New()
	win := myApp.NewWindow("Sunucu Ayarları")
	
	// Giriş Kutuları
	addr := widget.NewEntry(); addr.SetText(currentCfg.Addr)
	port := widget.NewEntry(); port.SetText(currentCfg.Port)
	dns := widget.NewEntry(); dns.SetText(currentCfg.DNS)
	winSize := widget.NewEntry(); winSize.SetText(currentCfg.WinSize)
	shards := widget.NewEntry(); shards.SetText(currentCfg.CacheShards)
	extraArgs := widget.NewEntry(); extraArgs.SetText(currentCfg.ExtraArgs)

	dohUrl := widget.NewEntry()
	dohUrl.SetText(currentCfg.DohURL)


	splitMode := widget.NewSelect([]string{"sni", "chunk", "random"}, func(selected string) {
		if selected == "sni" {
			winSize.Disable()
		} else {
			winSize.Enable()
		}
	})


	if currentCfg.SplitMode == "" { currentCfg.SplitMode = "random" }
	splitMode.SetSelected(currentCfg.SplitMode)
	if splitMode.Selected != "sni" {
    winSize.Enable()
		} else {
		winSize.Disable()
		}


	doh := widget.NewCheck("DoH Aktif", func(checked bool) {
		if checked {
			dohUrl.Enable()
		} else {
			dohUrl.Disable()
		}
	})
	doh.SetChecked(currentCfg.UseDoh)
	if !currentCfg.UseDoh { dohUrl.Disable() }


	saveBtn := widget.NewButton("Ayarları Kaydet ve Uygula", func() {
		currentCfg.Addr = addr.Text
		currentCfg.Port = port.Text
		currentCfg.DNS = dns.Text
		currentCfg.WinSize = winSize.Text
		currentCfg.SplitMode = splitMode.Selected
		currentCfg.ExtraArgs = extraArgs.Text
		currentCfg.CacheShards = shards.Text
		currentCfg.UseDoh = doh.Checked
		currentCfg.DohURL = dohUrl.Text
		saveSettings()
		win.Close()
	})
	saveBtn.Importance = widget.HighImportance


	resetBtn := widget.NewButton("Fabrika Ayarlarına Dön", func() {
		addr.SetText("127.0.0.1")
		port.SetText("2345")
		dns.SetText("94.140.14.14")
		winSize.SetText("15")
		shards.SetText("32")
		extraArgs.SetText("")
		splitMode.SetSelected("chunk")
		doh.SetChecked(true)
		dohUrl.SetText("https://dns.adguard-dns.com/dns-query")
		dohUrl.Enable()
		winSize.Disable()
	})


	content := container.NewVBox(
		widget.NewLabelWithStyle("YAPILANDIRMA PANELİ", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("IP:"), addr,
		widget.NewLabel("Port:"), port,
		widget.NewLabel("DNS:"), dns,
		widget.NewLabel("DoH URL (Otomatik):"), dohUrl,
		widget.NewLabel("HTTPS Split Mode:"), splitMode,
		widget.NewLabel("WinSize (Chunk Size):"), winSize,
		widget.NewLabel("Cache:"), shards,
		widget.NewLabel("Ekstra Parametreler:"), extraArgs,
		doh,
		widget.NewSeparator(),
		saveBtn,
		resetBtn,
	)

	win.SetContent(container.NewPadded(content))
	win.Resize(fyne.NewSize(520, 0)) 
	win.SetFixedSize(true)
	win.CenterOnScreen()
	win.ShowAndRun()
}