package omniauth

type RawInfo map[string]any

type Auth struct {
	ID      string
	Name    string
	Email   string
	Picture string

	RawInfo RawInfo
}
