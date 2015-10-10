package msocks

import (
	"errors"
	"io"
	"net"

	"time"

	"github.com/xiaokangwang/goproxy/sutils"
	"fmt"
	
	"encoding/json"
	
)

import "os/exec"
import "io/ioutil"
import "strings"
import "strconv"
import "os"



func getusegev()int64{
cmd:=exec.Command("ip", "-s", "link", "show", "venet0")
stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	b,_:=ioutil.ReadAll(stdout)
	bs:=string(b)
	
	bss:=strings.Split(bs,"\n")
	bsstrx:=strings.Trim(bss[3]," ")
	bssttx:=strings.Trim(bss[5]," ")
	bsstrxb:=strings.Split(bsstrx," ")[0]
	bssttxb:=strings.Split(bssttx," ")[0]
	bsstrxbii, _ := strconv.Atoi(bsstrxb)
	bsstrxbi:=int64(bsstrxbii)
	bssttxbii, _ := strconv.Atoi(bssttxb)
	bssttxbi:=int64(bssttxbii)
	
	fmt.Println(bs,bss,bsstrxb,bssttxb) 
	return bsstrxbi+bssttxbi
}

type Dsync struct{
Numsync int64

Lastch int64

Lastdayuse int64

Lastreset int64
	}

func usegedisksync(){
	if _, err := os.Stat("syncstat.json"); err == nil {
	var disksyncp Dsync
	if numsync==0{
		fd,_:=os.Open("syncstat.json")
		fmt.Printf("read sync prof")
		b,_:=ioutil.ReadAll(fd)
		json.Unmarshal(b,disksyncp)
		lastdayuse=disksyncp.Lastdayuse
		lastreset=disksyncp.Lastreset
		//lastch=disksyncp.Lastch
		numsync=disksyncp.Numsync+1
		fd.Close()
		fmt.Print(disksyncp)
		}else{
		fd,_:=os.Create("syncstat.json")
		//var disksyncp Dsync
		disksyncp.Lastdayuse=lastdayuse
		disksyncp.Lastreset=lastreset
		//disksyncp.Lastch=lastch
		disksyncp.Numsync=numsync+1
		numsync+=1
		b, _ := json.Marshal(disksyncp)
		fd.Write(b)
		fd.Close()
		fmt.Print(disksyncp)
			}
	}else{
		fd,_:=os.Create("syncstat.json")
		fmt.Printf("Create sync prof")
		var disksyncp Dsync
		disksyncp.Numsync=1
		numsync=1
		disksyncp.Lastdayuse=getusegev()
		disksyncp.Lastreset=time.Now().Unix()
		//disksyncp.Lastch=time.Now().Unix()
		b, _ := json.Marshal(disksyncp)
		fd.Write(b)
		fd.Close()
		}
	}
var numsync int64

var lastch int64

var lastdayuse int64

var lastreset int64

func untilok(limit int64){
	usegedisksync()
	fmt.Println("untilok")
	nowt := time.Now().Unix()
	
	if nowt-40<lastch{
		fmt.Println("lstc skip")
		return
		}
	
	if lastreset+86400<=nowt{
		lastreset=nowt
		lastdayuse=getusegev()
		fmt.Println("refresh skip",lastdayuse,lastreset)
		return
		}
	
	currusege := getusegev()-lastdayuse
	
	if currusege >= limit {
		fmt.Println("limit reach",(86400-(nowt-lastreset)))
		time.Sleep(time.Duration((86400-(nowt-lastreset)))*time.Second)
		return
		}
	fmt.Println("limit checkok",currusege)
	lastch=nowt
	}

type MsocksServer struct {
	*SessionPool
	userpass map[string]string
	dialer   sutils.Dialer
}

func NewServer(auth map[string]string, dialer sutils.Dialer) (ms *MsocksServer, err error) {
	if dialer == nil {
		err = errors.New("empty dialer")
		log.Error("%s", err)
		return
	}
	ms = &MsocksServer{
		dialer:      dialer,
		SessionPool: CreateSessionPool(nil),
	}

	if auth != nil {
		ms.userpass = auth
	}
	return
}

func (ms *MsocksServer) on_auth(stream io.ReadWriteCloser) (err error) {
	f, err := ReadFrame(stream)
	if err != nil {
		return
	}

	ft, ok := f.(*FrameAuth)
	if !ok {
		return ErrUnexpectedPkg
	}

	log.Notice("auth with username: %s, password: %s.", ft.Username, ft.Password)
	if ms.userpass != nil {
		password1, ok := ms.userpass[ft.Username]
		if !ok || (ft.Password != password1) {
			fb := NewFrameResult(ft.Streamid, ERR_AUTH)
			buf, err := fb.Packed()
			_, err = stream.Write(buf.Bytes())
			if err != nil {
				return err
			}
			return ErrAuthFailed
		}
	}

	fb := NewFrameResult(ft.Streamid, ERR_NONE)
	buf, err := fb.Packed()
	if err != nil {
		return
	}

	_, err = stream.Write(buf.Bytes())
	if err != nil {
		return
	}

	log.Info("auth passed.")
	return
}

func (ms *MsocksServer) Handler(conn net.Conn) {
	log.Notice("connection come from: %s => %s.", conn.RemoteAddr(), conn.LocalAddr())

	ti := time.AfterFunc(AUTH_TIMEOUT*time.Second, func() {
		log.Notice(ErrAuthFailed.Error(), conn.RemoteAddr())
		conn.Close()
	})
	err := ms.on_auth(conn)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	ti.Stop()

	sess := NewSession(conn)
	sess.next_id = 1
	sess.dialer = ms.dialer
	ms.Add(sess)
	defer ms.Remove(sess)
	sess.Run()

	log.Notice("server session %d quit: %s => %s.",
		sess.LocalPort(), conn.RemoteAddr(), conn.LocalAddr())
}

func (ms *MsocksServer) Serve(listener net.Listener) (err error) {
	var conn net.Conn

	for {	
		
		untilok(6000000000)
		
		conn, err = listener.Accept()
		if err != nil {
			log.Error("%s", err)
			continue
		}
		go func() {
			defer conn.Close()
			ms.Handler(conn)
		}()
	}
	return
}
