/*
 * Каталог профилей и его горячая перезагрузка.
 *
 * Снимок неизменяем и подменяется целиком: правка одного профиля не должна
 * оставлять контур в состоянии «половина старого, половина нового». Ошибка
 * разбора или компиляции любого профиля отвергает всё поколение, а действующий
 * набор при этом не трогают -- как у modsec с его apply_failed.
 *
 * Компиляция схем живёт не здесь. Пакет config читает файлы и проверяет форму
 * профиля; во что превращается спецификация -- дело internal/schema, и знать об
 * этом загрузчику незачем. Связь между ними -- интерфейс Compiler: снимок без
 * скомпилированного контракта наружу не выходит, поэтому неразбираемая спека
 * отвергает поколение так же, как опечатка в profile.yaml.
 *
 * Отпечаток -- имя, размер и mtime файлов. Читать содержимое раз в секунду ради
 * сравнения незачем: профиль правят руками либо подменяют каталогом целиком.
 */

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const profileFile = "profile.yaml"

/*
 * Compiled -- то, чем инспектор проверяет. Для пакета config это непрозрачная
 * величина: он умеет её получить, положить в снимок и отдать наружу.
 */
type Compiled interface {
	Names() []string
}

type Compiler interface {
	Compile(*Snapshot) (Compiled, error)
}

type Snapshot struct {
	Gen         int64
	Fingerprint string

	byName   map[string]*Profile
	names    []string
	limits   Limits
	compiled Compiled
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	if name == "" {
		name = DefaultName
	}

	p, ok := s.byName[name]

	return p, ok
}

func (s *Snapshot) Names() []string {
	if s == nil {
		return nil
	}

	return s.names
}

// Limits -- общая на процесс секция. Профили обязаны объявлять её одинаково,
// это проверяется при загрузке.
func (s *Snapshot) Limits() Limits {
	if s == nil {
		return Limits{}
	}

	return s.limits
}

func (s *Snapshot) Compiled() Compiled {
	if s == nil {
		return nil
	}

	return s.compiled
}

// All -- профили в лексическом порядке имён.
func (s *Snapshot) All() []*Profile {
	if s == nil {
		return nil
	}

	out := make([]*Profile, 0, len(s.names))

	for _, name := range s.names {
		out = append(out, s.byName[name])
	}

	return out
}

type Store struct {
	mu  sync.Mutex
	dir string
	// base -- каталог образа, с которого store начал. Там живёт профиль пробы
	// (ProbeName): поколение контроллера его не везёт, а read() достаёт
	// оттуда, когда читает другой каталог.
	base     string
	log      *slog.Logger
	compiler Compiler
	cur      atomic.Pointer[Snapshot]
	gen      atomic.Int64
}

func LoadProfiles(dir string, compiler Compiler, log *slog.Logger) (*Store, error) {
	s := &Store{dir: dir, base: dir, log: log, compiler: compiler}

	snap, err := s.read()
	if err != nil {
		return nil, err
	}

	s.cur.Store(snap)

	return s, nil
}

func (s *Store) Current() *Snapshot { return s.cur.Load() }

// Dir -- каталог, по которому сейчас читают. Нужен раскатке: она кладёт новое
// поколение рядом и переключает сюда.
func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

/*
 * ReloadFrom переключает каталог и читает его целиком. Провал не трогает ни
 * действующий снимок, ни каталог: поколение, которое не разобралось, не должно
 * оставлять контур ни с половиной профилей, ни без них.
 */
func (s *Store) ReloadFrom(dir string) error {
	s.mu.Lock()
	prev := s.dir
	s.dir = dir
	s.mu.Unlock()

	snap, err := s.read()
	if err != nil {
		s.mu.Lock()
		s.dir = prev
		s.mu.Unlock()

		return err
	}

	s.cur.Store(snap)

	return nil
}

// Reload перечитывает каталог, если изменился отпечаток. Первое значение --
// была ли подмена.
func (s *Store) Reload() (bool, error) {
	fp, err := fingerprint(s.Dir())
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == fp {
		return false, nil
	}

	snap, err := s.read()
	if err != nil {
		return false, err
	}

	s.cur.Store(snap)

	return true, nil
}

func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			changed, err := s.Reload()
			if err != nil {
				// Битое поколение не подменяет действующее: инспектор
				// продолжает проверять по последнему исправному набору.
				s.log.Error("profiles reload failed", "error", err.Error())

				continue
			}

			if changed {
				snap := s.Current()
				s.log.Info("profiles reloaded",
					"gen", snap.Gen,
					"profiles", snap.Names(),
					"fingerprint", snap.Fingerprint,
				)
			}
		}
	}
}

func (s *Store) read() (*Snapshot, error) {
	dir := s.Dir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}

	snap := &Snapshot{byName: map[string]*Profile{}}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		p, err := readProfile(dir, e.Name())
		if err != nil {
			return nil, err
		}

		if p == nil {
			continue
		}

		snap.byName[e.Name()] = p
		snap.names = append(snap.names, e.Name())
	}

	/*
	 * Проба (ProbeName) живёт в образе: в каталоге контроллера такого имени
	 * нет, и поколение её не везёт. Healthcheck ходит с ней всегда, поэтому
	 * дерево поколения дополняется пробой из базового каталога. Провал пробы
	 * поколение не роняет: без неё инспектор работает, а проба покраснеет и
	 * скажет почему.
	 */
	if _, ok := snap.byName[ProbeName]; !ok && s.base != dir {
		p, err := readProfile(s.base, ProbeName)
		if err != nil {
			s.log.Warn("probe profile skipped", "base", s.base, "error", err.Error())
		} else if p != nil {
			snap.byName[ProbeName] = p
			snap.names = append(snap.names, ProbeName)
		}
	}

	if _, ok := snap.byName[DefaultName]; !ok {
		return nil, fmt.Errorf("profiles: %s is missing in %s", DefaultName, dir)
	}

	sort.Strings(snap.names)

	if err := commonLimits(snap); err != nil {
		return nil, err
	}

	if s.compiler != nil {
		compiled, err := s.compiler.Compile(snap)
		if err != nil {
			return nil, err
		}

		snap.compiled = compiled
	}

	fp, err := fingerprint(dir)
	if err != nil {
		return nil, err
	}

	snap.Fingerprint = fp
	snap.Gen = s.gen.Add(1)

	return snap, nil
}

/*
 * readProfile читает один профиль каталога вместе с его документами. Нет
 * файла -- нет профиля (nil без ошибки): подкаталог без profile.yaml -- не
 * профиль, а что-то рядом.
 */
func readProfile(dir, name string) (*Profile, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name, profileFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("profiles: %w", err)
	}

	p, err := ParseProfile(name, raw)
	if err != nil {
		return nil, err
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	if err := attachDocuments(p, filepath.Join(dir, name)); err != nil {
		return nil, err
	}

	return p, nil
}

/*
 * attachDocuments подключает тексты спецификаций. Файл называется по имени
 * объекта содержимого -- schema-<source>, -- и это то же имя, что стоит в
 * профиле: второе имя у одного документа разъехалось бы при первом
 * переименовании.
 */
func attachDocuments(p *Profile, dir string) error {
	if p.Mode == ModeOff {
		return nil
	}

	p.Documents = map[string][]byte{}

	for _, source := range p.Sources() {
		path := filepath.Join(dir, SchemaFilePrefix+source)

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("profile %s: schema %q: %w", p.Name, source, err)
		}

		if len(raw) == 0 {
			return fmt.Errorf("profile %s: schema %q is empty", p.Name, source)
		}

		p.Documents[source] = raw
	}

	return nil
}

/*
 * commonLimits сводит секцию limits профилей в одну. Она описывает процесс --
 * сколько памяти уходит на кеш и какое тело он вообще берёт в разбор, -- и два
 * разных ответа на этот вопрос в одном процессе означали бы, что настройка не
 * значит ничего.
 */
func commonLimits(snap *Snapshot) error {
	first := ""

	for _, name := range snap.names {
		p := snap.byName[name]

		if first == "" {
			first, snap.limits = name, p.Limits

			continue
		}

		if p.Limits != snap.limits {
			return fmt.Errorf("profiles %s and %s declare different limits: "+
				"the section describes the process, not the profile", first, name)
		}
	}

	return nil
}

/*
 * fingerprint -- имя, размер и mtime всех файлов каталога. Содержимое не
 * читается: этого достаточно, чтобы увидеть правку, и дёшево настолько, что
 * опрос раз в секунду не виден в профиле процесса.
 */
func fingerprint(dir string) (string, error) {
	sum := sha256.New()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		_, _ = sum.Write([]byte(filepath.ToSlash(rel)))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(strconv.FormatInt(info.Size(), 10)))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(strconv.FormatInt(info.ModTime().UnixNano(), 10)))
		_, _ = sum.Write([]byte{0})

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("profiles: %w", err)
	}

	return hex.EncodeToString(sum.Sum(nil)), nil
}
