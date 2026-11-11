package core

import "time"

// NowFunc is the clock used by the core (timestamps, template [[date]]).
// Tests override it for deterministic behavior.
var NowFunc = func() time.Time { return time.Now() }

func timeNow() time.Time { return NowFunc() }
