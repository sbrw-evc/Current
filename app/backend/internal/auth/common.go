package auth

import (
	"strings"
	"unicode"
)

// commonPasswords are the most used passwords of public breach corpora (lower case). A password
// is rejected when it is one of them, or one of them with digits and symbols added around it.
var commonPasswords = func() map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Fields(`
password passw0rd p@ssw0rd p@ssword pa$$word passwort motdepasse contrasena parol parol123
qwerty qwertyuiop qwertz azerty asdfgh asdfghjkl zxcvbn zxcvbnm qazwsx 1qaz2wsx 1q2w3e4r 1q2w3e
qweasd qweasdzxc qwe123 zaq12wsx zaq1xsw2 abc123 abcd1234 abcdef abcdefg abcdefgh
123456 1234567 12345678 123456789 1234567890 0987654321 987654321 111111 000000 123123 121212 112233
654321 666666 696969 777777 888888 999999 555555 7777777 11111111 123321 159753 147258369 1122334455
iloveyou letmein welcome welcome1 admin administrator root toor master monkey dragon football baseball
shadow superman batman sunshine princess starwars trustno1 freedom whatever michael jennifer
charlie jordan hunter killer soccer hockey ranger buster thomas tigger robert daniel ginger
access login changeme default secret test tester testing guest user demo qwerty123 password1
summer winter spring autumn january february december monday friday
hello hello123 loveme lovely flower cookie cheese computer internet google samsung apple microsoft
windows linux ubuntu oracle cisco mikrotik zabbix grafana umbrella company corporate office
privet privet123 parolchik qwerty12345 ytrewq йцукен йцукенг пароль привет любовь солнце
`) {
		out[p] = true
	}
	return out
}()

// keyboardRows are the strings whose fragments make a sequence password.
var keyboardRows = []string{
	"abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
	"йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
}

// IsCommonPassword reports passwords that are guessed first: a common password with digits and
// symbols added around it, the user name with a few characters added, one repeated character or a
// keyboard or alphabet sequence.
func IsCommonPassword(password, username string) bool {
	p := strings.ToLower(password)
	core := strings.TrimFunc(p, func(r rune) bool { return !unicode.IsLetter(r) })
	if commonPasswords[p] || (core != "" && commonPasswords[core]) || commonPasswords[strings.TrimRightFunc(p, notLetterOrDigit)] {
		return true
	}
	if u := strings.ToLower(strings.TrimSpace(username)); len([]rune(u)) >= 3 {
		if name, _, _ := strings.Cut(u, "@"); core == u || core == name || strings.Contains(p, name) && len([]rune(p))-len([]rune(name)) <= 4 {
			return true
		}
	}
	runes := []rune(p)
	if len(runes) > 0 && strings.Count(p, string(runes[0])) == len(runes) {
		return true
	}
	for _, row := range keyboardRows {
		if strings.Contains(row, p) || strings.Contains(reverse(row), p) {
			return true
		}
	}
	return false
}

func notLetterOrDigit(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
