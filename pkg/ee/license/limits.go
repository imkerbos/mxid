package license

// CE edition limits. Apply when no valid EE license is active — that includes
// an EXPIRED license: on expiry the instance reverts to CE limits, but existing
// data is grandfathered (gates block only NEW creation beyond the cap, never
// delete). EE has no built-in cap (a license may still set MaxUsers).
const (
	// CEMaxUsers caps the total user count in CE. 0 would mean unlimited.
	CEMaxUsers = 100
)

// UserCap returns the effective max user count for the current edition: the EE
// license's MaxUsers when active (0 = unlimited), else the CE cap. A return of
// 0 means unlimited.
func (m *Manager) UserCap() int {
	if m != nil && m.valid {
		return m.MaxUsers() // EE: license value, 0 = unlimited
	}
	return CEMaxUsers // CE / expired
}
