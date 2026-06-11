package authn

import (
	"context"
	"time"

	"github.com/mojocn/base64Captcha"
	"github.com/redis/go-redis/v9"
)

const (
	captchaKeyPrefix = "mxid:captcha:"
	captchaTTL       = 5 * time.Minute
)

// CaptchaResponse is the API response for captcha generation.
type CaptchaResponse struct {
	CaptchaID    string `json:"captcha_id"`
	CaptchaImage string `json:"captcha_image"`
}

// redisCaptchaStore implements base64Captcha.Store backed by Redis.
type redisCaptchaStore struct {
	rdb *redis.Client
}

func (s *redisCaptchaStore) Set(id string, value string) error {
	return s.rdb.Set(context.Background(), captchaKeyPrefix+id, value, captchaTTL).Err()
}

func (s *redisCaptchaStore) Get(id string, clear bool) string {
	key := captchaKeyPrefix + id
	val, err := s.rdb.Get(context.Background(), key).Result()
	if err != nil {
		return ""
	}
	if clear {
		s.rdb.Del(context.Background(), key)
	}
	return val
}

func (s *redisCaptchaStore) Verify(id, answer string, clear bool) bool {
	stored := s.Get(id, clear)
	if stored == "" {
		return false
	}
	return stored == answer
}

// CaptchaService handles captcha generation and verification.
type CaptchaService struct {
	captcha *base64Captcha.Captcha
}

// NewCaptchaService creates a new captcha service backed by Redis.
func NewCaptchaService(rdb *redis.Client) *CaptchaService {
	store := &redisCaptchaStore{rdb: rdb}
	driver := base64Captcha.NewDriverDigit(80, 240, 5, 0.7, 80)
	captcha := base64Captcha.NewCaptcha(driver, store)
	return &CaptchaService{captcha: captcha}
}

// Generate creates a new captcha and returns the ID and base64 image.
func (s *CaptchaService) Generate() (*CaptchaResponse, error) {
	id, b64s, _, err := s.captcha.Generate()
	if err != nil {
		return nil, err
	}
	return &CaptchaResponse{
		CaptchaID:    id,
		CaptchaImage: b64s,
	}, nil
}

// Verify checks if the provided answer matches the captcha.
func (s *CaptchaService) Verify(id, answer string) bool {
	return s.captcha.Verify(id, answer, true)
}

