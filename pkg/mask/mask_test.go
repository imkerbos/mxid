package mask

import "testing"

func TestPhone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"123", "***"},
		{"13812345678", "138****5678"},
		{"138 1234 5678", "138****5678"},
		{"138-1234-5678", "138****5678"},
		{"+8613812345678", "+861****5678"},
		{"+86 138 1234 5678", "+861****5678"},
	}
	for _, c := range cases {
		if got := Phone(c.in); got != c.want {
			t.Errorf("Phone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"no-at-sign", "***"},
		{"@nolocal.com", "***"},
		{"a@b.com", "a*@b.com"},
		{"ab@b.com", "a*@b.com"},
		{"kerbos@gmail.com", "k****s@gmail.com"},
		{"a.b.c@example.org", "a***c@example.org"},
		{"张三@example.cn", "张*@example.cn"},
	}
	for _, c := range cases {
		if got := Email(c.in); got != c.want {
			t.Errorf("Email(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIDCard(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "***"},
		{"12345", "***"},
		{"110101199001011234", "110101********1234"},
		{"NotSeventeenChars", "***"},
	}
	for _, c := range cases {
		if got := IDCard(c.in); got != c.want {
			t.Errorf("IDCard(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{" ", ""},
		{"张", "*"},
		{"张三", "张*"},
		{"欧阳娜娜", "欧***"},
		{"Alice", "A****"},
	}
	for _, c := range cases {
		if got := Name(c.in); got != c.want {
			t.Errorf("Name(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
