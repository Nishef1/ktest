package smartproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWindscribeLocalOnlyRejectsForeignExits(t *testing.T) {
	if _, err := New(Config{
		RejectExits: true,
		Upstreams: []Upstream{{Name:"foreign", Exit:true, Addr:"127.0.0.1:10002"}},
	}); err == nil { t.Fatal("started foreign exit in Windscribe local-only mode") }
	p, err := New(Config{RejectExits:true, Upstreams:[]Upstream{
		{Name:"packet cutter", Send:func(net.Conn,[]byte)error{return nil}},
		{Name:"local ByeDPI", Addr:"127.0.0.1:12001", LocalBypass:true},
	}})
	if err != nil { t.Fatal(err) }
	if err:=p.Add(Upstream{Name:"Aether", Exit:true, Addr:"127.0.0.1:12002"});err==nil {
		t.Fatal("dynamically added forbidden foreign exit")
	}
	if p.HasVerifiedExit() { t.Fatal("foreign exit was registered") }
	if !p.HasLocalBypass() {t.Fatal("local ByeDPI disappeared")}
	if len(p.Stats())!=2 {t.Fatalf("unexpected upstream count %d",len(p.Stats()))}
}

func TestWindscribeLocalBootstrapNeverSelectsDirectOrForeign(t *testing.T) {
	l, err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil {t.Fatal(err)}
	defer l.Close()
	targets:=make(chan string, 2)
	done:=make(chan struct{})
	go func(){
		defer close(done)
		for {
			c,err:=l.Accept()
			if err!=nil{return}
			go func(){
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3*time.Second))
				buf:=make([]byte,3)
				if _,err:=io.ReadFull(c,buf);err!=nil{return}
				if _,err:=c.Write([]byte{5,0});err!=nil{return}
				hdr:=make([]byte,4)
				if _,err:=io.ReadFull(c,hdr);err!=nil{return}
				if hdr[3]!=1{return}
				a:=make([]byte,6)
				if _,err:=io.ReadFull(c,a);err!=nil{return}
				targets<-net.IP(a[:4]).String()
				if binary.BigEndian.Uint16(a[4:])!=443{return}
				_,_ = c.Write([]byte{5,0,0,1,127,0,0,1,0,0})
				_,_=io.Copy(io.Discard,c)
			}()
		}
	}()
	defer func(){_ = l.Close();<-done}()
	p,err:=New(Config{Upstreams:[]Upstream{
		{Name:"direct",Rank:0},
		{Name:"unverified foreign",Exit:true,Addr:"127.0.0.1:19999",Rank:1},
		{Name:"local ByeDPI",LocalBypass:true,Addr:l.Addr().String(),Rank:3},
	}})
	if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second);defer cancel()
	c,err:=p.DialWindscribeLocal(ctx,"198.51.100.23","443")
	if err!=nil{t.Fatal(err)}
	_ = c.Close()
	select{
	case h:=<-targets:if h!="198.51.100.23"{t.Fatal(h)}
	case <-time.After(time.Second):t.Fatal("local SOCKS did not get target")
	}
	p.mu.Lock();pin:=p.bootstrapPinned;p.mu.Unlock()
	if pin!="local ByeDPI"{t.Fatalf("wrong session pin %q",pin)}
}

func TestWindscribeNoLocalBypassReturnsErrorWithoutDial(t *testing.T){
	p,err:=New(Config{Upstreams:[]Upstream{
		{Name:"direct",Rank:0},
		{Name:"external SOCKS",Addr:"127.0.0.1:20003",Exit:true,AIEligible:true},
	}})
	if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
	c,err:=p.DialWindscribeLocal(ctx,"198.51.100.23","443")
	if c!=nil {c.Close();t.Fatal("unsafe route")}
	if err==nil || !strings.Contains(err.Error(),"no local IP-preserving"){t.Fatalf("wrong error %v",err)}
}
