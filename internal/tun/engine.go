package tun

// Engine is the T1 userspace loop: classify → DecideT1 → optional DropLog counter.
// It never opens /dev/net/tun; callers feed synthetic or captured buffers in tests.
type Engine struct {
	Drops *Counter
}

// NewEngine returns a T1 engine with an empty tun-sourced counter.
func NewEngine() *Engine {
	return &Engine{Drops: NewCounter()}
}

// Handle runs one packet through T1 policy. size for accounting prefers IP TotalN.
func (e *Engine) Handle(buf []byte, mark uint32, uid int) (Action, Classified, error) {
	cl, err := ClassifyIPPacket(buf, mark, uid)
	if err != nil {
		// Non-UDP / short / unknown: treat as unsupported without counting.
		return ActionUnsupported, cl, err
	}
	act := DecideT1(cl.Packet)
	if act == ActionDropLog && e != nil && e.Drops != nil {
		n := cl.TotalN
		if n <= 0 {
			n = len(buf)
		}
		e.Drops.Record(n)
	}
	return act, cl, nil
}
