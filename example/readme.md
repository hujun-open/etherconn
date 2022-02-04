This is an example traffic sending/recving tool using etherconn, it uses SharedEtherConn and SharingRUDPConn, with option of using RawSocketRelay or XDPRelay.

* example using RawSocketRelay
    * sending: `tt -m sender -si eth1 -eng raw`
    * recving: `tt -m recv -ri eth1 -eng raw`

* example using XDPRelay: 
    * sending: `tt -m sender -si eth1 -eng etherxdp`
    * recving: `tt -m recv -ri eth1 -eng etherxdp `

