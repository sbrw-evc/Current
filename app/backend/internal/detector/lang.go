package detector

// Event titles follow the installation language (general settings): "ru"
// or "en"; anything else is "ru", the default language of a new
// installation.

const (
	LangRU = "ru"
	LangEN = "en"
)

// text is a string in both languages.
type text struct{ ru, en string }

func (t text) in(lang string) string {
	if lang == LangEN {
		return t.en
	}
	return t.ru
}

func normLang(lang string) string {
	if lang == LangEN {
		return LangEN
	}
	return LangRU
}

// defaultTitles: title templates of the kinds, used when a rule has no
// title of its own.
var defaultTitles = map[Kind]text{
	KindLinkUtilization: {
		"Загрузка канала ${interface} (${direction}) на ${exporter} — ${value_text}",
		"Link utilization ${interface} (${direction}) on ${exporter}: ${value_text}",
	},
	KindLinkCommit: {
		"95-й перцентиль ${interface} на ${exporter} — ${p95_text} при коммите ${commit_text}",
		"95th percentile of ${interface} on ${exporter}: ${p95_text} with a commit of ${commit_text}",
	},
	KindDDoSVolumetric: {
		"Объёмная атака на ${dst_ip}: ${value_text}",
		"Volumetric attack on ${dst_ip}: ${value_text}",
	},
	KindDDoSSyn: {
		"SYN flood на ${dst_ip}: ${value_text} SYN без ACK",
		"SYN flood on ${dst_ip}: ${value_text} SYN without ACK",
	},
	KindTrafficAnomaly: {
		"Аномалия трафика ${group}: ${value_text} при норме ${expected_text}",
		"Traffic anomaly ${group}: ${value_text}, expected ${expected_text}",
	},
	KindTrafficDrop: {
		"Провал трафика ${group}: ${value_text} при норме ${expected_text}",
		"Traffic drop ${group}: ${value_text}, expected ${expected_text}",
	},
	KindExporterSilent: {
		"Нет потоков от экспортёра ${exporter} ${value_text}",
		"No flows from exporter ${exporter} for ${value_text}",
	},
	KindCustom: {
		"${rule}: ${group} — ${value_text}",
		"${rule}: ${group}: ${value_text}",
	},
}

// titleTemplate returns the title template of a rule in lang. A rule title
// equal to the kind default in either language counts as the default:
// earlier versions saved the Russian default into the rules.
func titleTemplate(r Rule, lang string) string {
	def, ok := defaultTitles[r.Kind]
	if r.Title == "" || ok && (r.Title == def.ru || r.Title == def.en) {
		return def.in(lang)
	}
	return r.Title
}

var (
	unitsBPS    = text{"бит/с|кбит/с|Мбит/с|Гбит/с|Тбит/с", "bit/s|kbit/s|Mbit/s|Gbit/s|Tbit/s"}
	unitsPPS    = text{"пак/с|тыс. пак/с|млн пак/с|млрд пак/с", "pps|kpps|Mpps|Gpps"}
	unitMinutes = text{"мин", "min"}
	allTraffic  = text{"весь трафик", "all traffic"}
	testEvent   = text{"Тестовое событие Umbrella Flow", "Umbrella Flow test event"}
)
