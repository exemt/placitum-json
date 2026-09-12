/*
 * Конфигурация из переменных окружения.
 *
 * Всё, что можно проверить до первого сообщения, проверяется здесь: инспектор,
 * который тихо пропускает трафик из-за опечатки в пути к профилям, хуже не
 * запустившегося. Поэтому Load() возвращает ошибку, а не значение по умолчанию,
 * на каждом нераспознанном значении.
 */

package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	DataDir     string

	// ReloadEvery -- период опроса отпечатка каталога профилей. Ноль
	// выключает опрос: поколение приезжает из KV, и на ноде без контроллера
	// профили правят вручную с рестартом.
	ReloadEvery time.Duration

	// Пул воркеров и очередь перед ним -- это и есть admission control:
	// отменить идущий разбор нельзя, поэтому единственная возможная проверка
	// бюджета -- на входе.
	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string

	ReserveMS   int
	MinBudgetMS int

	RedisURL string

	/*
	 * GeoAddr -- gRPC-адрес кодера гео внутри контура (host:port): из него
	 * резолвятся анонсированная подсеть и номер автономной системы для
	 * инициаторов с write: net|asn. Пусто -- такие строки не срабатывают,
	 * остальное работает как обычно.
	 * GeoTimeout -- сколько ждать кодер на промахе; ожидание синхронное и
	 * в бюджете сообщения.
	 */
	GeoAddr    string
	GeoTimeout time.Duration
	/*
	 * GeoNegMax -- потолок отрицательного кэша резолвера: сколько адресов,
	 * о которых кодер ничего не знает, помнить, чтобы не спрашивать снова.
	 * На потолке кэш вытесняется, а не сбрасывается целиком. 0 -- умолчание
	 * резолвера.
	 */
	GeoNegMax int

	Versions []int
	LogLevel slog.Level

	// Пульс присутствия на WAF_STATUS. Тот же период, что у агента.
	HeartbeatEvery time.Duration
}

// RedisTimeout ограничивает чтение объекта обменника по локатору. Значение
// заведомо меньше типичного дедлайна: тело, приехавшее после того, как модуль
// перестал ждать, не нужно никому.
const RedisTimeout = 20 * time.Millisecond

func Load() (*Config, error) {
	c := &Config{
		Servers:     splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:     env("WAF_JSON_SUBJECT", "waf.req.json"),
		Name:        env("WAF_JSON_NAME", "json"),
		ProfilesDir: env("WAF_JSON_PROFILES", "./profiles"),
		DataDir:     env("WAF_JSON_DATA", ""),
		GeoAddr:     env("WAF_JSON_GEO_ADDR", ""),
	}

	c.Queue = env("WAF_JSON_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_JSON_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	/*
	 * Глубина очереди -- произведение числа воркеров на запас в четыре
	 * сообщения. Очередь длиннее этого не ускоряет никого: сообщение,
	 * дождавшееся своей очереди, к тому времени уже потеряет бюджет и будет
	 * отброшено вторым порогом. inspector.conf и WAF_JSON_QUEUE_DEPTH
	 * перекрывают расчёт.
	 */
	q := queueSettings{
		/*
		 * 256, а не производная от числа воркеров: это число задаёт не только
		 * свою очередь, но и буфер подписки клиента NATS (queue_max + workers
		 * + 2), а буфер меряется темпом прихода на паузу, которую горутина
		 * доставки может пропустить, -- не тем, сколько воркеров за ней стоит.
		 * Прежние workers*8 давали 16 сообщений, это ~2 мс терпения на 10 000
		 * сообщений в секунду, и сообщения терялись молча на обычном дрожании.
		 */
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_JSON_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		// Своего состояния в Redis у json нет: internal в блоке redis -- ошибка.
		if ferr := noInternalRedis(c.ConfPath, file); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	// Общий обменник -- url блока redis в inspector.conf, REDIS_URL перекрывает.
	c.RedisURL = exchangeRedis(file)

	if q.Max, err = envIntIfSet("WAF_JSON_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_JSON_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_JSON_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_JSON_RESERVE_MS", 2); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_JSON_MIN_BUDGET_MS", 2); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_JSON_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_JSON_LOG", "info")); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_JSON_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_JSON_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDurationOrZero("WAF_JSON_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_JSON_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_JSON_RESERVE_MS and WAF_JSON_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_JSON_VERSIONS is empty")
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_JSON_PROFILES: %w", err)
	}

	c.ProfilesDir = abs

	if c.DataDir == "" {
		c.DataDir = abs + ".applied"
	}

	data, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("WAF_JSON_DATA: %w", err)
	}

	c.DataDir = data

	return nil
}

// Supports сообщает, берётся ли инспектор обрабатывать эту версию схемы.
// Незнакомая версия -- это ответ с причиной, а не молчание: молчание для модуля
// неотличимо от перегрузки и стоит ему полного дедлайна.
func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

// envDurationOrZero отличается от envDuration ровно нулём: "0" здесь --
// осмысленное значение «не опрашивать», а не ошибка.
func envDurationOrZero(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

/*
 * Стартовый порог журнала: словарь error_log nginx без emerg
 * (internal/loglevel). Поколение из KV переставляет порог живьём, переменная
 * действует до первого поколения с блоком settings.
 */
func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_JSON_LOG: %w", err)
	}

	return level, nil
}
