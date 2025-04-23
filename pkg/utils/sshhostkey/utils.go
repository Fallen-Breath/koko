package sshhostkey

import "io"

type dummyReadWriter struct{}

func (n *dummyReadWriter) Read(p []byte) (int, error) {
	return 0, nil
}

func (n *dummyReadWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

var _ io.ReadWriter = &dummyReadWriter{}

type CallbackCallGuard interface {
	OnEnter()
	OnExit()
}

type emptyCallbackCallGuard struct{}

func (cg emptyCallbackCallGuard) OnEnter() {
}

func (cg emptyCallbackCallGuard) OnExit() {
}

var _ CallbackCallGuard = &emptyCallbackCallGuard{}

type callbackCallGuardImpl struct {
	onEnter func()
	onExit  func()
}

func (cg *callbackCallGuardImpl) OnEnter() {
	cg.onEnter()
}

func (cg *callbackCallGuardImpl) OnExit() {
	cg.onExit()
}

var _ CallbackCallGuard = &callbackCallGuardImpl{}

func CreateCallbackCallGuard(onEnter func(), onExit func()) CallbackCallGuard {
	return &callbackCallGuardImpl{
		onEnter: onEnter,
		onExit:  onExit,
	}
}
