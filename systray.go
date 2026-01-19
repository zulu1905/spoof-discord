package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"sync"
	"crypto/md5"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows/registry"
)

//go:embed ProxyON.ico
var iconProxyOn []byte
//go:embed ProxyOFF.ico
var iconProxyOff []byte
//go:embed System-ProxyON.ico
var iconSystemProxyOn []byte // Yeni eklenen ikon
//go:embed version.dll
var dllData []byte
//go:embed spoofdpi.exe
var spoofExeData []byte

var (
	mStatus               *systray.MenuItem
	mInfoItems            []*systray.MenuItem
	mProxyToggle          *systray.MenuItem
	mDiscord              *systray.MenuItem
	workDir               string
	startupName           = "SpoofDPI for Discord"
	mutexHandle           uintptr
	localAppData          string 
	discordPath           string 
	
	spoofMutex          sync.Mutex
	discordInjectMutex  sync.Mutex
	lastDiscordInject   time.Time
	discordCooldown     = 3 * time.Second
	confPath    string
	lastModTime time.Time
	guardianCmd *exec.Cmd
)
var isDownloading = false

func init() {
    rawPath := os.Getenv("LOCALAPPDATA")
    localAppData = GetShortPathName(rawPath) 
    
    workDir = filepath.Join(localAppData, "SPOOFDPI")
    _ = os.MkdirAll(workDir, 0755)
}

const APP_MUTEX_ID = "Global\\SPOOFDPI_PRO_SUPER_UNIQUE_9922_KEY"

type Config struct {
	Addr 			string
	Port 			string
	DNS 			string
	SplitMode 		string
	WinSize 		string
	CacheShards 	string
	ExtraArgs 		string
	DohURL 			string
	UseDoh 			bool
	SystemProxy 	bool
}

var currentCfg = Config{
	Addr: "127.0.0.1", Port: "2345", DNS: "94.140.14.14", SplitMode: "chunk", WinSize: "15", CacheShards: "32", UseDoh: true, DohURL: "https://dns.adguard-dns.com/dns-query", ExtraArgs: "", 
}
var guiCmd *exec.Cmd

// --- MUTEX KONTROLÜ ---
func checkMutex() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex := kernel32.NewProc("CreateMutexW")
	namePtr, _ := syscall.UTF16PtrFromString(APP_MUTEX_ID)
	
	ret, _, err := procCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(namePtr)))
	if ret == 0 { return }
	if err != nil && err.(syscall.Errno) == 183 {
		os.Exit(0)
	}
	mutexHandle = ret
}

func silentExec(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

var (
	modwininet                         = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption              = modwininet.NewProc("InternetSetOptionW")
)

const (
	INTERNET_OPTION_REFRESH           = 37
	INTERNET_OPTION_SETTINGS_CHANGED  = 39
)

func updateWinSettings(enable bool) {
	if enable {
		proxyFull := fmt.Sprintf("http://%s:%s", currentCfg.Addr, currentCfg.Port)
		
		runSilentCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
		runSilentCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyFull, "/f")
		runSilentCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "<local>", "/f")
		launchGuardian()
	} else {
		runSilentCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
		stopGuardian()
	}

	procInternetSetOption.Call(0, 31, 0, 0)
	procInternetSetOption.Call(0, 37, 0, 0)
}


func saveSettings() {
	// 1. JSON Kaydı (Programın kendi ayarları)
	path := filepath.Join(workDir, "config.json")
	tempCfg := currentCfg
	tempCfg.SystemProxy = false 
	data, _ := json.MarshalIndent(tempCfg, "", "  ")
	_ = os.WriteFile(path, data, 0644)
	
	syncDiscordFiles()
}

func loadSettings() {
    path := filepath.Join(workDir, "config.json")
    file, err := os.ReadFile(path)
    if err == nil {
        _ = json.Unmarshal(file, &currentCfg)
    }
    
    currentCfg.SystemProxy = false 
    updateWinSettings(false)
}

func initApp() {
    _ = os.MkdirAll(workDir, 0755)
    spoofDest := filepath.Join(workDir, "spoofdpi.exe")
    
    h := md5.New()
    h.Write(spoofExeData)
    embeddedHash := hex.EncodeToString(h.Sum(nil))

    existingHash := getFileHash(spoofDest)

    if existingHash != embeddedHash {
        err := os.WriteFile(spoofDest, spoofExeData, 0755)
        if err != nil {
            fmt.Println("KRİTİK HATA: spoofdpi.exe yazılamadı ->", err)
        }
    }
}

func killProcessByName(name string) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil { return }
	defer windows.CloseHandle(snapshot)
	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshot, &procEntry); err != nil { return }
	for {
		if strings.EqualFold(windows.UTF16ToString(procEntry.ExeFile[:]), name) {
			hProc, _ := windows.OpenProcess(windows.PROCESS_TERMINATE, false, procEntry.ProcessID)
			_ = windows.TerminateProcess(hProc, 0)
			_ = windows.CloseHandle(hProc)
		}
		if err := windows.Process32Next(snapshot, &procEntry); err != nil { break }
	}
}

func syncDiscordFiles() {
    dPath := findDiscordPath()
    if dPath == "" { return }
    
    discordPath = GetShortPathName(dPath)
	discordDir := filepath.Dir(discordPath)
	dllPath := filepath.Join(discordDir, "version.dll")
	iniPath := filepath.Join(discordDir, "drover.ini")
	fileInfo, err := os.Stat(dllPath)
	if os.IsNotExist(err) || (err == nil && fileInfo.Size() != int64(len(dllData))) {
		_ = os.WriteFile(dllPath, dllData, 0644)
	}
	newIniContent := fmt.Sprintf("[drover]\nproxy = http://%s:%s", currentCfg.Addr, currentCfg.Port)
	oldData, err := os.ReadFile(iniPath)
	if err != nil || string(oldData) != newIniContent {
		_ = os.WriteFile(iniPath, []byte(newIniContent), 0644)
	}
}

func startService() {
	killProcessByName("spoofdpi.exe")
	time.Sleep(500 * time.Millisecond)
	exePath := filepath.Join(workDir, "spoofdpi.exe")
	_ = os.WriteFile(exePath, spoofExeData, 0755)
	listenAddr := fmt.Sprintf("%s:%s", currentCfg.Addr, currentCfg.Port)
	args := []string{}
	if currentCfg.UseDoh {
		args = append(args, "--dns-mode", "https")
		if currentCfg.DohURL != "" {
			args = append(args, "--dns-https-url", currentCfg.DohURL)
		}
	} else {
		dnsAddr := currentCfg.DNS
		if !strings.Contains(dnsAddr, ":") {
			dnsAddr += ":53"
		}
		args = append(args, "--dns-mode", "udp", "--dns-addr", dnsAddr)
	}
	args = append(args, "--listen-addr", listenAddr)
	chunkSize := currentCfg.WinSize
	if chunkSize == "" || chunkSize == "0" { chunkSize = "15" }
	splitMode := currentCfg.SplitMode
	if splitMode == "" { splitMode = "random" }
	
	args = append(args, "--https-split-mode", splitMode)
	if splitMode != "sni" {
		chunkSize := currentCfg.WinSize
		if chunkSize == "" || chunkSize == "0" { chunkSize = "15" }
		args = append(args, "--https-chunk-size", chunkSize)
	}

	cmd := exec.Command(exePath, args...)
	cmd.Dir = workDir
	applySilencer(cmd)
	err := cmd.Start()
	if err != nil {
		showNotification("Başlatılamadı", err.Error())
		return
	}
	go func() {
		err := cmd.Wait()
		if err != nil {
			fmt.Println("SpoofDPI durdu:", err)
		}
	}()
	}
func isAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil { return false }
	defer k.Close()
	_, _, err = k.GetStringValue(startupName)
	return err == nil
}
func getFileHash(path string) string {
	f, err := os.Open(path)
	if err != nil { return "" }
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil { return "" }
	return hex.EncodeToString(h.Sum(nil))
}
func ensureInWorkDir() {
	currentExe, _ := os.Executable()
	targetPath := filepath.Join(workDir, "Spoof-Discord.exe")
	if strings.EqualFold(currentExe, targetPath) {
		return
	}
	if _, err := os.Stat(targetPath); err == nil {
		hash1 := getFileHash(currentExe)
		hash2 := getFileHash(targetPath)
		if hash1 != "" && hash1 == hash2 {
			return 
		}
	}
	data, err := os.ReadFile(currentExe)
	if err == nil {
		_ = os.WriteFile(targetPath, data, 0755)
	}
}
func main() {
	for i, arg := range os.Args {
		if arg == "--guardian" && i+1 < len(os.Args) {
			runGuardianMode(os.Args[i+1])
			return 
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "--gui" {
		loadSettings()
		runSettingsGUI()
		return
	}
	checkMutex()
	initApp()
	loadSettings()	
	syncDiscordFiles()	
	updateWinSettings(false)
	
	go startService()
//---------------------------------------------------------------
	go func() {
		time.Sleep(1 * time.Second)
		
		dPath := findDiscordPath()
		if dPath != "" {
			discordPath = dPath
			syncDiscordFiles()
			//runDiscordProxy()
		}
	}()
//------------------------------------------------------------------
	systray.Run(onReady, onExit)
}

func bringToFront(windowTitle string) bool {
	user32 := syscall.NewLazyDLL("user32.dll")
	findWindow := user32.NewProc("FindWindowW")
	showWindow := user32.NewProc("ShowWindow")
	setForeground := user32.NewProc("SetForegroundWindow")

	tPtr, _ := syscall.UTF16PtrFromString(windowTitle)
	hwnd, _, _ := findWindow.Call(0, uintptr(unsafe.Pointer(tPtr)))
	
	if hwnd != 0 {
		showWindow.Call(hwnd, 9) 
		setForeground.Call(hwnd)
		return true
	}
	return false
}
func launchGuardian() {
	if guardianCmd != nil && guardianCmd.Process != nil {
		return 
	}

	exePath, _ := os.Executable()
	pid := fmt.Sprintf("%d", os.Getpid())
	
	guardianCmd = exec.Command(exePath, "--guardian", pid)
	guardianCmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, 
	}
	_ = guardianCmd.Start() 
}
func stopGuardian() {
	if guardianCmd != nil && guardianCmd.Process != nil {
		_ = guardianCmd.Process.Kill()
		guardianCmd = nil
	}
}
func runGuardianMode(parentPidStr string) {
	var parentPid uint32
	fmt.Sscanf(parentPidStr, "%d", &parentPid)

	for {
		exists := false
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err == nil {
			var procEntry windows.ProcessEntry32
			procEntry.Size = uint32(unsafe.Sizeof(procEntry))
			if err := windows.Process32First(snapshot, &procEntry); err == nil {
				for {
					if procEntry.ProcessID == parentPid {
						exists = true
						break
					}
					if err := windows.Process32Next(snapshot, &procEntry); err != nil {
						break
					}
				}
			}
			windows.CloseHandle(snapshot)
		}
		if !exists {
			cleanupProxyAndExit()
		}

		time.Sleep(1 * time.Second)
	}
}
func cleanupProxyAndExit() {
	runSilentCommand("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	modwininet := windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption := modwininet.NewProc("InternetSetOptionW")
	procInternetSetOption.Call(0, 31, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	procInternetSetOption.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
		os.Exit(0)
}

func onReady() {
	mStatus = systray.AddMenuItem("⏳ Kontrol Ediliyor...", "")
	systray.AddSeparator()
	for i := 0; i < 6; i++ {
		item := systray.AddMenuItem("", "")
		item.Disable()
		mInfoItems = append(mInfoItems, item)
	}
	systray.AddSeparator()
		mStartUp := systray.AddMenuItem("", "")
	if isAutoStartEnabled() {
		mStartUp.SetTitle("🚀 Başlangıçtan Kaldır")
	} else {
		mStartUp.SetTitle("🚀 Başlangıca Ekle")
	}
	systray.AddSeparator()
	mSettings := systray.AddMenuItem("⚙️ Ayarları Düzenle", "")
	mProxyToggle = systray.AddMenuItem("❌ Sistem Proxy Kapalı", "")
	systray.AddSeparator()
	installedList := getInstalledBrowsers()

if len(installedList) > 0 {
    mBrowsers := systray.AddMenuItem("🌐 Tarayıcıyı Proxy ile Başlat", "")
    for _, b := range installedList {
        item := mBrowsers.AddSubMenuItem(b.Name, "")
        
go func(menuItem *systray.MenuItem, info BrowserInfo) {
    for range menuItem.ClickedCh {
        launchAnyBrowser(info, currentCfg.Addr, currentCfg.Port, "") 
    }
}(item, b)
    }
}
	mDiscord = systray.AddMenuItem("💬 Discord'u Başlat ", "")
	mDiscord.Hide() 

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("❌ Kapat", "")

	updateUI()
go func() {
    path := findDiscordPath()
    if path != "" {
        discordPath = path
        syncDiscordFiles()
        mDiscord.SetTitle("💬 Discord'u Başlat")
        mDiscord.Show()
    } else {
        mDiscord.SetTitle("📥 Discord'u İndir ve Kur")
        mDiscord.Show()
    }
}()

go func() {
    for {
        updateUI()
                if !isDownloading {
            dPath := findDiscordPath()
            if dPath != "" {
                discordPath = dPath
                mDiscord.SetTitle("💬 Discord'u Başlat")
                mDiscord.Enable()
            } else {
                mDiscord.SetTitle("📥 Discord'u İndir ve Kur")
                mDiscord.Enable()
            }
        }
        
        time.Sleep(10 * time.Second)
    }
}()

		go func() {
		for {
			select {
			case <-mStartUp.ClickedCh:
			toggleAutoStart(mStartUp)
			case <-mSettings.ClickedCh:
			if bringToFront("Sunucu Ayarları") {
				continue
			}
			exePath, _ := os.Executable()
			guiCmd = exec.Command(exePath, "--gui")
			guiCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    
    go func() {
        _ = guiCmd.Run()
        loadSettings()
        startService()
        updateUI()
    }()
			case <-mStatus.ClickedCh:
				if !isSpoofDPIRunning() { startService(); updateUI() }
			case <-mProxyToggle.ClickedCh:
				currentCfg.SystemProxy = !currentCfg.SystemProxy
				updateWinSettings(currentCfg.SystemProxy)
				updateUI()
			case <-mDiscord.ClickedCh:
			if isDownloading { continue }
			dPath := findDiscordPath()
    
			if dPath != "" {
				discordPath = dPath
				go runDiscordProxy()
			} else {
			go func() {
				mDiscord.Disable()
				downloadAndSetupDiscord(mDiscord)
			}()
		}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
func findDiscordPath() string {
	discordFlavors := []string{"Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment"}
	for _, flavor := range discordFlavors {
		if path := checkDiscordInDir(filepath.Join(localAppData, flavor)); path != "" {
			return path
		}
	}
	var drives []string
	lpBuffer := make([]uint16, 254)
	n, _ := windows.GetLogicalDriveStrings(uint32(len(lpBuffer)), &lpBuffer[0])
	curr := 0
	for i := 0; i < int(n); i++ {
		if lpBuffer[i] == 0 {
			if i > curr {
				drives = append(drives, string(windows.UTF16ToString(lpBuffer[curr:i])))
			}
			curr = i + 1
		}
	}
	for _, drive := range drives {
		searchRoots := []string{
			drive,
			filepath.Join(drive, "Programlar"),
		}
		for _, root := range searchRoots {
			if _, err := os.Stat(root); err != nil {
				continue
			}
			entries, _ := os.ReadDir(root)
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				nameLower := strings.ToLower(e.Name())
				if strings.Contains(nameLower, "discord") {
					fullPath := filepath.Join(root, e.Name())
					if _, err := os.Stat(filepath.Join(fullPath, "Update.exe")); err == nil {
						candidate := checkDiscordInDir(fullPath)
						if candidate != "" {
							return candidate
						}
					}
				}
			}
		}
	}

	return ""
}
func GetShortPathName(longPath string) string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetShortPathNameW")
	lpszLongPath, _ := windows.UTF16PtrFromString(longPath)
	nSize, _, _ := proc.Call(uintptr(unsafe.Pointer(lpszLongPath)), 0, 0)
	if nSize == 0 { return longPath }
	buff := make([]uint16, nSize)
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(lpszLongPath)), uintptr(unsafe.Pointer(&buff[0])), nSize)
	if ret == 0 { return longPath }
	return windows.UTF16ToString(buff)
}
func downloadFile(path string, targetUrl string) error {
	psCode := `
	Add-Type -AssemblyName PresentationFramework
	$xaml = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
			Title="Discord Setup" Height="140" Width="380" WindowStartupLocation="CenterScreen" 
			ResizeMode="NoResize" WindowStyle="None" Background="#2f3136" AllowsTransparency="True" Topmost="True">
		<Border CornerRadius="12" BorderBrush="#5865f2" BorderThickness="2" Background="#2f3136">
			<StackPanel VerticalAlignment="Center">
				<TextBlock Text="Discord Güvenli İndiriliyor..." Foreground="White" FontSize="15" FontWeight="Bold" HorizontalAlignment="Center" Margin="0,0,0,12"/>
				<ProgressBar Height="12" Width="300" IsIndeterminate="True" Background="#4f545c" Foreground="#5865f2"/>
				<TextBlock Text="Lütfen bekleyiniz, bağlantı kuruluyor..." Foreground="#b9bbbe" FontSize="10" HorizontalAlignment="Center" Margin="0,5,0,0"/>
			</StackPanel>
		</Border>
	</Window>
"@
	$window = [Windows.Markup.XamlReader]::Load([System.Xml.XmlReader]::Create([System.IO.StringReader]$xaml))
	$window.ShowDialog()
	`
	cmd := exec.Command("powershell", "-Command", psCode)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
	proxyAddr := fmt.Sprintf("http://%s:%s", currentCfg.Addr, currentCfg.Port)
	pURL, _ := url.Parse(proxyAddr)
	transport := &http.Transport{Proxy: http.ProxyURL(pURL)}
	client := &http.Client{Transport: transport, Timeout: time.Second * 30} // Bağlantı için kısa timeout
	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", targetUrl, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
		
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
				time.Sleep(2 * time.Second)
	}
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		if cmd.Process != nil { _ = cmd.Process.Kill() }
		return fmt.Errorf("baglanti kurulamadi")
	}
	defer resp.Body.Close()
	out, err := os.Create(path)
	if err != nil {
		if cmd.Process != nil { _ = cmd.Process.Kill() }
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if cmd.Process != nil { _ = cmd.Process.Kill() }
	return err
}
func downloadAndSetupDiscord(mDiscord *systray.MenuItem) {
	if isDownloading { return }
	isDownloading = true
	mDiscord.Disable()
	defer func() { isDownloading = false; mDiscord.Enable() }()

	url := "https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64"
	homeDir, _ := os.UserHomeDir()
		findSetup := func() string {
		roots := []string{
			filepath.Join(homeDir, "Downloads"),
			filepath.Join(homeDir, "Videos"),
			filepath.Join(homeDir, "Desktop"),
		}
		var bestMatch string
		var latestTime time.Time
		for _, root := range roots {
			files, _ := os.ReadDir(root)
			pathsToSearch := []string{root}
			for _, f := range files {
				if f.IsDir() { pathsToSearch = append(pathsToSearch, filepath.Join(root, f.Name())) }
			}
			for _, searchPath := range pathsToSearch {
				dirFiles, _ := os.ReadDir(searchPath)
				for _, df := range dirFiles {
					if !df.IsDir() {
						name := strings.ToLower(df.Name())
						if strings.Contains(name, "discordsetup") && strings.HasSuffix(name, ".exe") {
							fInfo, err := df.Info()
							if err == nil && fInfo.Size() > 50000000 {
								if fInfo.ModTime().After(latestTime) {
									latestTime = fInfo.ModTime()
									bestMatch = filepath.Join(searchPath, df.Name())
								}
							}
						}
					}
				}
			}
		}
		return bestMatch
	}
	mDiscord.SetTitle("🔍 Dosya Aranıyor...")
	targetSetup := findSetup()
	if targetSetup == "" {
		mDiscord.SetTitle("📥 İndiriliyor...")
		targetSetup = filepath.Join(homeDir, "Downloads", "DiscordSetup.exe")
		
		err := downloadFile(targetSetup, url)
		if err != nil {
			mDiscord.SetTitle("❌ İndirme Hatası")
			return
		}
	}
	mDiscord.SetTitle("⚙️ Kuruluyor...")
	_ = exec.Command(targetSetup).Start()
	for i := 0; i < 60; i++ {
		time.Sleep(3 * time.Second)
		dPath := findDiscordPath()
		if dPath != "" {
			discordPath = dPath
			syncDiscordFiles()
			mDiscord.SetTitle("💬 Discord'u Başlat")
			return
		}
	}
}
func showNotification(title, message string) {
	script := fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('%s', '%s')", message, title)
	cmd := exec.Command("powershell", "-Command", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	
	_ = cmd.Run()
}
func copyDir(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(src, path)
		targetPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(targetPath, data, info.Mode())
	})
}
func runDiscordProxy() {
    if discordPath == "" || !fileExists(discordPath) {
        newPath := findDiscordPath()
        if newPath == "" {
            showNotification("Hata", "Discord konumu bulunamadı! Lütfen Discord'un kurulu olduğundan emin olun.")
            return
        }
        discordPath = GetShortPathName(newPath)
    }
    killProcessByName("Discord.exe")
    time.Sleep(300 * time.Millisecond)    
    discordDir := filepath.Dir(discordPath)
    dllPath := filepath.Join(discordDir, "version.dll")
    iniPath := filepath.Join(discordDir, "drover.ini")
		iniContentString := fmt.Sprintf("[drover]\nproxy = http://%s:%s", currentCfg.Addr, currentCfg.Port)
	fileInfo, err := os.Stat(dllPath)
	shouldWriteDLL := false

	if os.IsNotExist(err) {
		shouldWriteDLL = true
	} else if err == nil {
		if fileInfo.Size() != int64(len(dllData)) {
			shouldWriteDLL = true
		}
	}
	if shouldWriteDLL {
		_ = os.WriteFile(dllPath, dllData, 0644)
	}
	oldIniData, err := os.ReadFile(iniPath)
	if err != nil || string(oldIniData) != iniContentString {
		_ = os.WriteFile(iniPath, []byte(iniContentString), 0644)
	}
discordDir = filepath.Dir(discordPath)
uPath := filepath.Join(filepath.Dir(discordDir), "Update.exe")
updateExePath := GetShortPathName(uPath)
	vbsPath := filepath.Join(workDir, "launch_discord.vbs")
vbsContent := fmt.Sprintf("Set objShell = CreateObject(\"Shell.Application\")\nobjShell.ShellExecute \"%s\", \"--processStart Discord.exe\", \"\", \"open\", 1", updateExePath)
shouldWriteVBS := false
existingVBS, err := os.ReadFile(vbsPath)
if err != nil || string(existingVBS) != vbsContent {
    shouldWriteVBS = true
}
if shouldWriteVBS {
    err = os.WriteFile(vbsPath, []byte(vbsContent), 0644)
    if err != nil {
        showNotification("Hata", "VBS oluşturulamadı: "+err.Error())
        return
    }
}
	cmd := exec.Command("wscript.exe", vbsPath)
	err = cmd.Run()
	if err != nil {
		showNotification("Hata", "VBS çalıştırılamadı: "+err.Error())
	}
}
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
func checkDiscordInDir(baseDir string) string {
	updatePath := filepath.Join(baseDir, "Update.exe")
	if _, err := os.Stat(updatePath); err != nil {
		return ""
	}
	entries, _ := os.ReadDir(baseDir)
	var latestVer string
	var foundedPath string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "app-") {
			candidate := filepath.Join(baseDir, e.Name(), "Discord.exe")
			if _, err := os.Stat(candidate); err == nil {
				if e.Name() > latestVer {
					latestVer = e.Name()
					foundedPath = candidate
				}
			}
		}
	}
	return foundedPath
}
func isSpoofDPIRunning() bool {
	const TH32CS_SNAPPROCESS = 0x00000002
		snapshot, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)
	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return false
	}
	for {
		exeName := windows.UTF16ToString(procEntry.ExeFile[:])
		if strings.ToLower(exeName) == "spoofdpi.exe" {
			return true
		}
		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}
	return false
}
func updateUI() {
    if mStatus == nil { return }
    isRunning := isSpoofDPIRunning()

    if isRunning {
        mStatus.SetTitle("🟢 STATUS: Online")
        if currentCfg.SystemProxy {
            mProxyToggle.SetTitle("✅ Sistem Proxy Aktif")
            systray.SetIcon(iconSystemProxyOn)
        } else {
            mProxyToggle.SetTitle("❌ Sistem Proxy Kapalı")
            systray.SetIcon(iconProxyOn)
        }
    } else {
        mStatus.SetTitle("🔴 STATUS: Offline")
        if currentCfg.SystemProxy {
            currentCfg.SystemProxy = false
            updateWinSettings(false)
        }
        mProxyToggle.SetTitle("❌ Sistem Proxy Kapalı")
        systray.SetIcon(iconProxyOff)
    }
    infoLabels := []string{
        "📍 ADDR: " + currentCfg.Addr,
        "🔌 PORT: " + currentCfg.Port,
        "🌐 DNS: " + currentCfg.DNS,
        "🔒 DOH: " + map[bool]string{true: "Aktif", false: "Pasif"}[currentCfg.UseDoh],
		"⚡ SplitMOD: " + currentCfg.SplitMode,
        "📏 Chunk-Size: " + currentCfg.WinSize,
        "📦 Shards: " + currentCfg.CacheShards,
    }
    for i, label := range infoLabels {
        if i < len(mInfoItems) { mInfoItems[i].SetTitle(label) }
	}
}
func toggleAutoStart(mItem *systray.MenuItem) {
	const registryKey = "SpoofDPI for Discord"
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil { return }
	defer k.Close()

	targetPath := filepath.Join(workDir, "Spoof-Discord.exe")
	_, _, err = k.GetStringValue(registryKey)
	if err == nil { 
		_ = k.DeleteValue(registryKey)
		mItem.SetTitle("🚀 Başlangıca Ekle")
	} else { 
			ensureInWorkDir()
		_ = k.SetStringValue(registryKey, `"`+targetPath+`"`)
		mItem.SetTitle("🚀 Başlangıçtan Kaldır")
	}
}
func runSilentCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmd.Run()
}
type BrowserInfo struct {
	Name string
	Path string
	ID   string

}

func getInstalledBrowsers() []BrowserInfo {
	local := os.Getenv("LOCALAPPDATA")
	prog := os.Getenv("ProgramFiles")
	progX86 := os.Getenv("ProgramFiles(x86)")
	allPossible := []BrowserInfo{
		{"Google Chrome", filepath.Join(prog, `Google\Chrome\Application\chrome.exe`), "chrome"},
		{"Google Chrome", filepath.Join(progX86, `Google\Chrome\Application\chrome.exe`), "chrome_x86"},
		{"Google Chrome", filepath.Join(local, `Google\Chrome\Application\chrome.exe`), "chrome_local"},
		{"Microsoft Edge", filepath.Join(progX86, `Microsoft\Edge\Application\msedge.exe`), "edge"},
		{"Microsoft Edge", filepath.Join(prog, `Microsoft\Edge\Application\msedge.exe`), "edge_sys"},
		{"Firefox", filepath.Join(prog, `Mozilla Firefox\firefox.exe`), "firefox"},
		{"Firefox", filepath.Join(progX86, `Mozilla Firefox\firefox.exe`), "firefox_x86"},
		{"Firefox", filepath.Join(local, `Mozilla Firefox\firefox.exe`), "firefox_local"},
		{"Opera GX", filepath.Join(local, `Programs\Opera GX\launcher.exe`), "opera_gx"},
		{"Opera GX", filepath.Join(prog, `Opera GX\launcher.exe`), "opera_gx_sys"},
		{"Opera GX", filepath.Join(local, `Programs\Opera GX\opera.exe`), "opera_gx_exe"},
		{"Opera", filepath.Join(local, `Programs\Opera\launcher.exe`), "opera"},
		{"Opera", filepath.Join(prog, `Opera\launcher.exe`), "opera_sys"},
		{"Opera", filepath.Join(progX86, `Opera\launcher.exe`), "opera_x86"},
		{"Brave Browser", filepath.Join(prog, `BraveSoftware\Brave-Browser\Application\brave.exe`), "brave"},
		{"Brave Browser", filepath.Join(progX86, `BraveSoftware\Brave-Browser\Application\brave.exe`), "brave_x86"},
		{"Brave Browser", filepath.Join(local, `BraveSoftware\Brave-Browser\Application\brave.exe`), "brave_local"},
		{"Vivaldi", filepath.Join(local, `Vivaldi\Application\vivaldi.exe`), "vivaldi"},
		{"Vivaldi", filepath.Join(prog, `Vivaldi\Application\vivaldi.exe`), "vivaldi_sys"},
		{"Yandex Browser", filepath.Join(local, `Yandex\YandexBrowser\Application\browser.exe`), "yandex"},
		{"Yandex Browser", filepath.Join(prog, `Yandex\YandexBrowser\Application\browser.exe`), "yandex_sys"},
	}
	installed := []BrowserInfo{}
	seen := make(map[string]bool)
	for _, b := range allPossible {
		if _, err := os.Stat(b.Path); err == nil {
			// Aynı isimdeki tarayıcıyı sadece bir kez ekle (Örn: Hem x64 hem x86 varsa ilk bulduğunu alır)
			if !seen[b.Name] {
				installed = append(installed, b)
				seen[b.Name] = true
			}
		}
	}
	return installed
}
func launchAnyBrowser(b BrowserInfo, addr string, port string, targetUrl string) {
	uniqueID := time.Now().Format("150405") 
	tempDir := filepath.Join(os.TempDir(), "spoof_p_"+b.ID+"_"+uniqueID)
	_ = os.MkdirAll(tempDir, 0755)
	if targetUrl == "" { targetUrl = "about:blank" }
	var cmd *exec.Cmd
	if strings.Contains(strings.ToLower(b.Name), "firefox") {
		userJSPath := filepath.Join(tempDir, "user.js")
		prefsContent := fmt.Sprintf(
			"user_pref(\"network.proxy.type\", 1);\n"+
			"user_pref(\"network.proxy.http\", \"%[1]s\");\n"+
			"user_pref(\"network.proxy.http_port\", %[2]s);\n"+
			"user_pref(\"network.proxy.ssl\", \"%[1]s\");\n"+
			"user_pref(\"network.proxy.ssl_port\", %[2]s);\n"+
			"user_pref(\"network.proxy.share_proxy_settings\", true);\n"+
			"user_pref(\"network.proxy.socks_remote_dns\", true);\n"+
			"user_pref(\"browser.shell.checkDefaultBrowser\", false);\n"+
			"user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");\n"+ // Karşılama ekranını engeller
			"user_pref(\"startup.homepage_welcome_url\", \"\");\n"+
			"user_pref(\"startup.homepage_welcome_url.additional\", \"\");\n"+
			"user_pref(\"browser.messaging-system.whatsNewPanel.enabled\", false);\n"+ // "Neler Yeni" panelini kapatır
			"user_pref(\"browser.uitour.enabled\", false);\n"+ // Tur rehberini kapatır
			"user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);\n"+ // Veri toplama onayını kapatır
			"user_pref(\"trailhead.firstrun.branches\", \"nofirstrun\");\n",
			addr, port,
		)
		_ = os.WriteFile(userJSPath, []byte(prefsContent), 0644)
		cmd = exec.Command(b.Path, "-profile", tempDir, "-no-remote", "-new-instance", targetUrl)
	} else {
		cmd = exec.Command(b.Path, 
			fmt.Sprintf("--proxy-server=http://%s:%s", addr, port),
			fmt.Sprintf("--user-data-dir=%s", tempDir),
			"--no-first-run",
			"--no-default-browser-check",
			"--disable-fre",
			"--new-window",
			targetUrl,
		)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}
func onExit() {
    if guiCmd != nil && guiCmd.Process != nil {
        _ = guiCmd.Process.Kill()
    }
    updateWinSettings(false)
    _ = silentExec("taskkill", "/F", "/IM", "spoofdpi.exe", "/T").Run()
    if mutexHandle != 0 {
        syscall.CloseHandle(syscall.Handle(mutexHandle))
    }
    os.Exit(0)
}
	