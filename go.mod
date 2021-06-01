module github.com/hujun-open/etherconn

go 1.14

replace github.com/hujun-open/xdp => /root/gomodules/src/xdp

require (
	github.com/hujun-open/xdp v0.0.0
	github.com/google/gopacket v1.1.19
	github.com/hujun-open/myaddr v0.0.0-20200628224706-46a60dd3e36b
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/sys v0.0.0-20210525143221-35b2ab0089ea
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
