// The same check as the server's (model.IsCommonPassword): the most used passwords with digits and
// symbols added around them, the user name with a few characters added, one repeated character and
// keyboard or alphabet sequences.
const COMMON = new Set(
  `password passw0rd p@ssw0rd p@ssword pa$$word passwort motdepasse contrasena parol parol123
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
privet privet123 parolchik qwerty12345 ytrewq йцукен йцукенг пароль привет любовь солнце`.split(/\s+/),
)

const ROWS = [
  'abcdefghijklmnopqrstuvwxyz',
  '0123456789',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1234567890',
  'йцукенгшщзхъ',
  'фывапролджэ',
  'ячсмитьбю',
  'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
]

const rev = (s: string) => [...s].reverse().join('')

export function isCommonPassword(password: string, username: string): boolean {
  const p = password.toLowerCase()
  if (!p) return false
  const core = p.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '')
  if (COMMON.has(p) || (core && COMMON.has(core)) || COMMON.has(p.replace(/[^\p{L}\p{N}]+$/u, ''))) return true
  const u = username.trim().toLowerCase()
  if ([...u].length >= 3) {
    const name = u.split('@')[0]
    if (core === u || core === name || (p.includes(name) && [...p].length - [...name].length <= 4)) return true
  }
  const chars = [...p]
  if (chars.every((c) => c === chars[0])) return true
  return ROWS.some((row) => row.includes(p) || rev(row).includes(p))
}
