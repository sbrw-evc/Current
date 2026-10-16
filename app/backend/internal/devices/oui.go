package devices

import (
	"bufio"
	"context"
	"encoding/csv"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OUIURL is the IEEE registry of MAC address blocks.
const OUIURL = "https://standards-oui.ieee.org/oui/oui.csv"

// builtinOUI is a small fallback for the vendors seen most in offices and
// homes, used until (or without) the IEEE registry.
var builtinOUI = map[string]string{
	"00:0c:42": "MikroTik", "48:8f:5a": "MikroTik", "64:d1:54": "MikroTik", "b8:69:f4": "MikroTik",
	"dc:2c:6e": "MikroTik", "18:fd:74": "MikroTik", "2c:c8:1b": "MikroTik", "c4:ad:34": "MikroTik",
	"74:4d:28": "MikroTik", "d4:01:c3": "MikroTik", "00:1b:21": "Intel", "3c:22:fb": "Apple", "f0:18:98": "Apple",
	"a4:83:e7": "Apple", "bc:d0:74": "Apple", "8c:85:90": "Apple", "f4:f5:d8": "Google", "3c:5a:b4": "Google",
	"00:1a:11": "Google", "e4:5f:01": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
	"28:6c:07": "Xiaomi", "64:09:80": "Xiaomi", "78:11:dc": "Xiaomi", "50:ec:50": "Xiaomi", "8c:79:f5": "Samsung",
	"5c:49:7d": "Samsung", "f4:7b:09": "Samsung", "00:15:5d": "Microsoft Hyper-V", "00:50:56": "VMware",
	"52:54:00": "QEMU / KVM", "08:00:27": "VirtualBox", "02:42:ac": "Docker", "ac:84:c6": "TP-Link",
	"50:c7:bf": "TP-Link", "98:da:c4": "TP-Link", "60:32:b1": "TP-Link", "f4:f2:6d": "TP-Link", "24:5a:4c": "Ubiquiti",
	"74:ac:b9": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "78:8a:20": "Ubiquiti", "00:1d:aa": "DrayTek", "50:ff:20": "Keenetic",
	"e8:37:7a": "Zyxel", "00:13:49": "Zyxel", "00:1e:13": "Cisco", "00:26:0b": "Cisco", "70:10:5c": "Cisco",
	"00:0b:86": "Aruba", "94:b4:0f": "Aruba", "3c:a8:2a": "HP", "00:25:b3": "HP", "14:18:77": "Dell", "f8:bc:12": "Dell",
	"00:1f:12": "Juniper", "28:8a:1c": "Juniper", "00:e0:fc": "Huawei", "48:46:fb": "Huawei", "00:09:0f": "Fortinet",
	"90:6c:ac": "Fortinet", "a8:f9:4b": "Eltex", "18:31:bf": "ASUS", "04:d9:f5": "ASUS", "00:11:32": "Synology",
	"24:5e:be": "QNAP", "9c:8e:cd": "Amcrest", "c0:56:27": "Belkin", "44:65:0d": "Amazon", "fc:65:de": "Amazon",
	"a0:02:dc": "Amazon", "b0:be:76": "TP-Link", "d8:3a:dd": "Raspberry Pi", "00:17:88": "Philips Hue",
	"ec:fa:bc": "Espressif", "24:0a:c4": "Espressif", "84:f3:eb": "Espressif", "bc:ff:4d": "Espressif",
	"70:ee:50": "Netatmo", "18:b4:30": "Nest", "64:16:66": "Nest", "00:04:20": "Logitech (Harmony)", "c8:3a:6b": "Roku",
	"b0:a7:37": "Roku", "40:b0:76": "ASUS", "00:24:e4": "Withings", "a4:77:33": "Google", "54:60:09": "Google",
	"ac:63:be": "Amazon", "00:fc:8b": "Amazon", "70:3a:cb": "Google", "f0:b4:29": "Xiaomi", "7c:49:eb": "Xiaomi",
	"98:fa:9b": "LG", "a8:23:fe": "LG", "00:e0:4c": "Realtek", "00:1c:42": "Parallels", "0c:47:c9": "Amazon",
	"e0:d5:5e": "Gigabyte", "1c:69:7a": "Elitegroup", "60:a4:4c": "ASUS", "d0:50:99": "ASRock", "00:23:24": "Apple",
	"40:a6:b7": "Hikvision", "c0:51:7e": "Hikvision", "4c:bd:8f": "Hikvision", "e0:50:8b": "Dahua", "3c:ef:8c": "Dahua",
	"00:12:fb": "Samsung", "cc:2d:e0": "Routerboard (MikroTik)",
}

// OUI names the vendor of a MAC address: the built-in list, then the IEEE
// registry downloaded into the data directory (refreshed every 30 days).
type OUI struct {
	mu   sync.RWMutex
	m    map[string]string
	path string // "" = no download
	log  *slog.Logger
	// Client downloads the registry (tests replace it).
	Client *http.Client
	URL    string
}

// NewOUI returns the lookup; dir is where oui.tsv is kept ("" = built-in only).
func NewOUI(dir string, log *slog.Logger) *OUI {
	if log == nil {
		log = slog.Default()
	}
	o := &OUI{m: map[string]string{}, log: log, URL: OUIURL, Client: &http.Client{Timeout: 2 * time.Minute}}
	for k, v := range builtinOUI {
		o.m[k] = v
	}
	if dir != "" {
		o.path = filepath.Join(dir, "oui.tsv")
		o.load()
	}
	return o
}

// RandomMAC reports a locally administered (randomised, private Wi-Fi) address.
func RandomMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	for _, c := range strings.ToLower(mac[:2]) {
		switch {
		case c >= '0' && c <= '9':
			b = b<<4 | byte(c-'0')
		case c >= 'a' && c <= 'f':
			b = b<<4 | byte(c-'a'+10)
		default:
			return false
		}
	}
	return b&0x02 != 0
}

// Vendor of a normalised MAC ("" when unknown, "Random MAC" for a private one).
func (o *OUI) Vendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	o.mu.RLock()
	v := o.m[strings.ToLower(mac[:8])]
	o.mu.RUnlock()
	if v == "" && RandomMAC(mac) {
		return "Random MAC"
	}
	return v
}

func (o *OUI) load() {
	f, err := os.Open(o.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	o.mu.Lock()
	defer o.mu.Unlock()
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "\t")
		if ok && v != "" {
			o.m[k] = v
		}
	}
}

// ParseOUICSV reads the IEEE CSV (Registry, Assignment, Organization Name, …).
func ParseOUICSV(r io.Reader) map[string]string {
	out := map[string]string{}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(row) >= 3 && len(row[1]) == 6 {
			h := strings.ToLower(row[1])
			name := strings.TrimSpace(row[2])
			if len(name) > 120 {
				name = name[:120]
			}
			out[h[0:2]+":"+h[2:4]+":"+h[4:6]] = name
		}
	}
	return out
}

// Refresh downloads the registry when the saved copy is older than 30 days.
func (o *OUI) Refresh(ctx context.Context) {
	if o.path == "" {
		return
	}
	if st, err := os.Stat(o.path); err == nil && time.Since(st.ModTime()) < 30*24*time.Hour {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "UmbrellaFlow")
	resp, err := o.Client.Do(req)
	if err != nil {
		o.log.Info("OUI registry not downloaded; MAC vendors use the built-in list", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		o.log.Info("OUI registry not downloaded; MAC vendors use the built-in list", "status", resp.StatusCode)
		return
	}
	rows := ParseOUICSV(resp.Body)
	if len(rows) == 0 {
		return
	}
	if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
		o.log.Warn("OUI registry not saved", "err", err)
		return
	}
	tmp := o.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		o.log.Warn("OUI registry not saved", "err", err)
		return
	}
	w := bufio.NewWriter(f)
	for k, v := range rows {
		_, _ = w.WriteString(k + "\t" + strings.ReplaceAll(v, "\t", " ") + "\n")
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return
	}
	f.Close()
	if err := os.Rename(tmp, o.path); err != nil {
		return
	}
	o.mu.Lock()
	for k, v := range rows {
		o.m[k] = v
	}
	o.mu.Unlock()
	o.log.Info("OUI registry loaded", "vendors", len(rows))
}
