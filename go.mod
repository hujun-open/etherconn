module github.com/hujun-open/etherconn

go 1.14

// replace github.com/asavie/xdp => ../xdp

require (
	// github.com/asavie/xdp v0.3.3
	github.com/asavie/xdp v0.3.4-0.20211113171712-711132ccc429
	github.com/google/gopacket v1.1.19
	github.com/hujun-open/myaddr v0.0.0-20200628224706-46a60dd3e36b
	github.com/safchain/ethtool v0.0.0-20201023143004-874930cb3ce0
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/sys v0.0.0-20210525143221-35b2ab0089ea
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
