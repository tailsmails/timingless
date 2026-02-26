//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

// to compile v -prod -gc boehm -skip-unused -d no_backtrace -d no_debug -cc clang -cflags "-O2 -fPIE -fno-stack-protector -fno-ident -fno-common -fvisibility=hidden" -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,--gc-sections -Wl,--build-id=none" timingless.v -o timingless && strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version --remove-section=.note.ABI-tag --remove-section=.note.gnu.build-id --remove-section=.note.android.ident --remove-section=.eh_frame --remove-section=.eh_frame_hdr timingless

module main

import net
import rand
import time
import os
import sync

struct Bucket {
mut:
	mu       &sync.Mutex = sync.new_mutex()
	tokens   int
	max      int
	rate     int
	last     time.Time = time.now()
	real_up  u64
	real_dn  u64
	pad_up   u64
	pad_dn   u64
	reqs     u64
	pads     u64
	circuits u64
	active   int
}

fn new_bucket(rate_kbps int) &Bucket {
	r := rate_kbps * 1024
	return &Bucket{
		tokens: r,
		max:    r,
		rate:   r
	}
}

@[direct_array_access]
fn (mut b Bucket) refill() {
	now := time.now()
	ms := (now - b.last).milliseconds()
	if _unlikely_(ms <= 0) {
		return
	}
	b.tokens += int(i64(b.rate) * ms / 1000)
	if _unlikely_(b.tokens > b.max) {
		b.tokens = b.max
	}
	b.last = now
}

@[direct_array_access]
fn (mut b Bucket) take(n int, is_cover bool) int {
	b.mu.@lock()
	defer { b.mu.unlock() }
	b.refill()
	
	if is_cover {
		avail := b.tokens - (b.max / 2)
		if _unlikely_(avail <= 0) {
			return 0
		}
		give := if n < avail { n } else { avail }
		b.tokens -= give
		return give
	}
	
	if _unlikely_(b.tokens <= 0) {
		return 0
	}
	give := if n < b.tokens { n } else { b.tokens }
	b.tokens -= give
	return give
}

fn (mut b Bucket) stat_real(up u64, dn u64) {
	b.mu.@lock()
	b.real_up += up
	b.real_dn += dn
	b.mu.unlock()
}

fn (mut b Bucket) stat_pad(up u64, dn u64) {
	b.mu.@lock()
	b.pad_up += up
	b.pad_dn += dn
	b.mu.unlock()
}

fn (mut b Bucket) inc_reqs() {
	b.mu.@lock()
	b.reqs++
	b.mu.unlock()
}

fn (mut b Bucket) inc_pads() {
	b.mu.@lock()
	b.pads++
	b.mu.unlock()
}

fn (mut b Bucket) inc_circuits() {
	b.mu.@lock()
	b.circuits++
	b.mu.unlock()
}

fn (mut b Bucket) conn_add() {
	b.mu.@lock()
	b.active++
	b.mu.unlock()
}

fn (mut b Bucket) conn_rm() {
	b.mu.@lock()
	b.active--
	b.mu.unlock()
}

fn (mut b Bucket) snapshot() (u64, u64, u64, u64, u64, u64, u64, int) {
	b.mu.@lock()
	defer { b.mu.unlock() }
	return b.real_up, b.real_dn, b.pad_up, b.pad_dn, b.reqs, b.pads, b.circuits, b.active
}

fn tor(host string, port int) !&net.TcpConn {
	mut c := net.dial_tcp('127.0.0.1:9050')!
	c.write([u8(5), 1, 0])!
	mut g := []u8{len: 2}
	c.read(mut g)!
	if _unlikely_(g[0] != 5 || g[1] != 0) {
		c.close() or {}
		return error('auth')
	}
	mut r := [u8(5), 1, 0, 3, u8(host.len)]
	r << host.bytes()
	r << u8(port >> 8)
	r << u8(port & 0xff)
	c.write(r)!
	mut rsp := []u8{len: 256}
	c.read(mut rsp)!
	if _unlikely_(rsp[1] != 0) {
		c.close() or {}
		return error('refused')
	}
	return c
}

@[direct_array_access]
fn relay(mut client net.TcpConn, mut remote net.TcpConn, mut bk Bucket) {
	bk.conn_add()
	defer { bk.conn_rm() }
	client.set_read_timeout(200 * time.millisecond)
	remote.set_read_timeout(200 * time.millisecond)
	mut buf := []u8{len: 4096}
	mut idle := 0
	
	for {
		mut active := false
		n1 := client.read(mut buf) or { 0 }
		if _likely_(n1 > 0) {
			allowed := bk.take(n1, false)
			if _likely_(allowed > 0) {
				remote.write(buf[..allowed]) or { return }
				bk.stat_real(u64(allowed), 0)
			}
			if _unlikely_(allowed < n1) {
				time.sleep(50 * time.millisecond)
				mut off := allowed
				for off < n1 {
					a := bk.take(n1 - off, false)
					if _unlikely_(a <= 0) {
						time.sleep(50 * time.millisecond)
						continue
					}
					remote.write(buf[off..off + a]) or { return }
					bk.stat_real(u64(a), 0)
					off += a
				}
			}
			active = true
		}
		
		n2 := remote.read(mut buf) or { 0 }
		if _likely_(n2 > 0) {
			allowed := bk.take(n2, false)
			if _likely_(allowed > 0) {
				client.write(buf[..allowed]) or { return }
				bk.stat_real(0, u64(allowed))
			}
			if _unlikely_(allowed < n2) {
				time.sleep(50 * time.millisecond)
				mut off := allowed
				for off < n2 {
					a := bk.take(n2 - off, false)
					if _unlikely_(a <= 0) {
						time.sleep(50 * time.millisecond)
						continue
					}
					client.write(buf[off..off + a]) or { return }
					bk.stat_real(0, u64(a))
					off += a
				}
			}
			active = true
		}
		
		if _likely_(active) {
			idle = 0
		} else {
			idle++
			if _unlikely_(idle > 1500) {
				return
			}
		}
	}
}

@[direct_array_access]
fn cover_thread(id int, mut bk Bucket) {
	hosts := ['www.wikipedia.org', 'en.wikipedia.org', 'duckduckgo.com', 'www.torproject.org', 'www.eff.org']
	
	for {
		host := hosts[rand.intn(hosts.len) or { 0 }]
		mut c := tor(host, 80) or {
			time.sleep(1 * time.second)
			continue
		}
		
		c.set_read_timeout(2000 * time.millisecond)
		c.set_write_timeout(2000 * time.millisecond)
		
		mut rb := []u8{len: 4096}
		
		for _ in 0 .. 20 {
			req := 'GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\n\r\n'.bytes()
			mut sent := 0
			mut req_failed := false
			
			for sent < req.len {
				a := bk.take(req.len - sent, true)
				if _unlikely_(a <= 0) {
					time.sleep(50 * time.millisecond)
					continue
				}
				c.write(req[sent..sent + a]) or { req_failed = true; break }
				bk.stat_pad(u64(a), 0)
				sent += a
			}
			
			if req_failed { break }
			bk.inc_pads()
			
			mut idle := 0
			for {
				rn := c.read(mut rb) or { 0 }
				if rn > 0 {
					idle = 0
					mut consumed := 0
					for consumed < rn {
						ca := bk.take(rn - consumed, true)
						if _unlikely_(ca <= 0) {
							time.sleep(50 * time.millisecond)
							continue
						}
						bk.stat_pad(0, u64(ca))
						consumed += ca
					}
				} else {
					idle++
					if idle > 2 {
						break
					}
				}
			}
		}
		c.close() or {}
	}
}

fn rotator(mut bk Bucket) {
	for {
		wait := rand.int_in_range(120, 600) or { 300 }
		time.sleep(wait * time.second)
		mut c := net.dial_tcp('127.0.0.1:9051') or { continue }
		c.write('AUTHENTICATE ""\r\n'.bytes()) or {
			c.close() or {}
			continue
		}
		mut b := []u8{len: 256}
		c.read(mut b) or {
			c.close() or {}
			continue
		}
		c.write('SIGNAL NEWNYM\r\n'.bytes()) or {
			c.close() or {}
			continue
		}
		c.read(mut b) or {
			c.close() or {}
			continue
		}
		if b.bytestr().contains('250') {
			bk.inc_circuits()
		}
		c.close() or {}
	}
}

fn monitor(mut bk Bucket) {
	mut last_total := u64(0)
	for {
		time.sleep(10 * time.second)
		rup, rdn, pup, pdn, reqs, pads, circuits, active := bk.snapshot()
		
		real := rup + rdn
		pad := pup + pdn
		total := real + pad
		
		delta := total - last_total
		rate := delta / 10
		last_total = total
		
		pct := if total > 0 { f64(pad) * 100.0 / f64(total) } else { 0.0 }
		println('  [stat] rate=${fmtb(rate)}/s real=${fmtb(real)} pad=${fmtb(pad)} noise=${pct:.0}% conn=${active} reqs=${reqs} cover=${pads} circuits=${circuits}')
	}
}

@[direct_array_access]
fn handle(mut c net.TcpConn, mut bk Bucket) {
	defer { c.close() or {} }
	mut buf := []u8{len: 512}
	n := c.read(mut buf) or { return }
	if _unlikely_(n < 1 || buf[0] != 5) { return }
	c.write([u8(5), 0]) or { return }
	nr := c.read(mut buf) or { return }
	if _unlikely_(nr < 7 || buf[1] != 1) { return }
	
	mut host := ''
	mut port := 0
	mut off := 0
	
	match buf[3] {
		0x01 {
			if _unlikely_(nr < 10) { return }
			host = '${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}'
			off = 8
		}
		0x03 {
			dl := int(buf[4])
			if _unlikely_(nr < 5 + dl + 2) { return }
			host = buf[5..5 + dl].bytestr()
			off = 5 + dl
		}
		else { return }
	}
	
	port = int(u32(buf[off]) << 8 | u32(buf[off + 1]))
	mut remote := tor(host, port) or { return }
	defer { remote.close() or {} }
	c.write([u8(5), 0, 0, 1, 0, 0, 0, 0, 0, 0]) or { return }
	bk.inc_reqs()
	relay(mut c, mut remote, mut bk)
}

fn fmtb(b u64) string {
	if b < 1024 { return '${b}B' }
	if b < 1048576 { return '${f64(b) / 1024:.1}K' }
	if b < 1073741824 { return '${f64(b) / 1048576:.1}M' }
	return '${f64(b) / 1073741824:.2}G'
}

fn main() {
	mut bw := 15
	mut streams := 15
	a := os.args[1..]
	mut i := 0
	for i < a.len {
		if _unlikely_(a[i] == '-bw' && i + 1 < a.len) {
			i++
			bw = a[i].int()
		}
		if _unlikely_(a[i] == '-s' && i + 1 < a.len) {
			i++
			streams = a[i].int()
		}
		i++
	}

	println('timingless 1.1')
	println('  listen:  127.0.0.1:8889')
	println('  tor:     127.0.0.1:9050')
	println('  target:  ${bw} KB/s constant')
	println('  streams: ${streams}')
	println('')

	mut bk := new_bucket(bw)

	for s in 0 .. streams {
		spawn cover_thread(s, mut bk)
	}
	spawn rotator(mut bk)
	spawn monitor(mut bk)

	mut l := net.listen_tcp(.ip, '127.0.0.1:8889') or {
		eprintln('bind failed: ${err}')
		return
	}
	println('ready')
	for {
		mut c := l.accept() or { continue }
		spawn handle(mut c, mut bk)
	}
}