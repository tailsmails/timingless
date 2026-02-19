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
		tokens: r
		max:    r
		rate:   r
	}
}

fn (mut b Bucket) refill() {
	now := time.now()
	elapsed := now - b.last
	ms := elapsed.milliseconds()
	if ms <= 0 {
		return
	}
	add := int(i64(b.rate) * ms / 1000)
	b.tokens += add
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = now
}

fn (mut b Bucket) take(n int, is_cover bool) int {
	b.mu.@lock()
	defer { b.mu.unlock() }
	b.refill()
	if is_cover {
		allowed := b.tokens / 2
		if allowed <= 0 {
			return 0
		}
		give := if n < allowed { n } else { allowed }
		b.tokens -= give
		return give
	}
	if b.tokens <= 0 {
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

const covers = [
	'www.wikipedia.org', 'www.bbc.com', 'www.reuters.com',
	'www.github.com', 'www.kernel.org', 'www.gnu.org',
	'www.python.org', 'www.mozilla.org', 'www.eff.org',
	'www.archive.org', 'stackoverflow.com', 'news.ycombinator.com',
	'www.nytimes.com', 'arstechnica.com', 'www.wired.com',
]

const cover_paths = ['/', '/news', '/about', '/help', '/blog',
	'/docs', '/faq', '/sitemap.xml', '/robots.txt',
	'/search?q=weather', '/search?q=news']

fn tor(host string, port int) !&net.TcpConn {
	mut c := net.dial_tcp('127.0.0.1:9050')!
	c.write([u8(5), 1, 0])!
	mut g := []u8{len: 2}
	c.read(mut g)!
	if g[0] != 5 || g[1] != 0 {
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
	if rsp[1] != 0 {
		c.close() or {}
		return error('refused')
	}
	return c
}

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
		if n1 > 0 {
			allowed := bk.take(n1, false)
			if allowed > 0 {
				remote.write(buf[..allowed]) or { return }
				bk.stat_real(u64(allowed), 0)
			}
			if allowed < n1 {
				time.sleep(50 * time.millisecond)
				remain := n1 - allowed
				mut off := 0
				for off < remain {
					a := bk.take(remain - off, false)
					if a <= 0 {
						time.sleep(50 * time.millisecond)
						continue
					}
					remote.write(buf[allowed + off..allowed + off + a]) or { return }
					bk.stat_real(u64(a), 0)
					off += a
				}
			}
			active = true
		}
		n2 := remote.read(mut buf) or { 0 }
		if n2 > 0 {
			allowed := bk.take(n2, false)
			if allowed > 0 {
				client.write(buf[..allowed]) or { return }
				bk.stat_real(0, u64(allowed))
			}
			if allowed < n2 {
				time.sleep(50 * time.millisecond)
				remain := n2 - allowed
				mut off := 0
				for off < remain {
					a := bk.take(remain - off, false)
					if a <= 0 {
						time.sleep(50 * time.millisecond)
						continue
					}
					client.write(buf[allowed + off..allowed + off + a]) or { return }
					bk.stat_real(0, u64(a))
					off += a
				}
			}
			active = true
		}
		if active {
			idle = 0
		} else {
			idle++
			if idle > 1500 {
				return
			}
		}
	}
}

fn cover_thread(id int, mut bk Bucket) {
	for {
		_ := bk.take(0, true)
		host := covers[rand.intn(covers.len) or { 0 }]
		path := cover_paths[rand.intn(cover_paths.len) or { 0 }]
		mut c := tor(host, 80) or {
			time.sleep(5 * time.second)
			continue
		}
		req := 'GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n'.bytes()
		mut sent := 0
		for sent < req.len {
			chunk := if req.len - sent > 512 { 512 } else { req.len - sent }
			a := bk.take(chunk, true)
			if a <= 0 {
				time.sleep(100 * time.millisecond)
				continue
			}
			c.write(req[sent..sent + a]) or { break }
			bk.stat_pad(u64(a), 0)
			sent += a
		}
		bk.inc_pads()
		c.set_read_timeout(500 * time.millisecond)
		mut rb := []u8{len: 2048}
		for {
			rn := c.read(mut rb) or { break }
			if rn <= 0 {
				break
			}
			mut consumed := 0
			for consumed < rn {
				left := rn - consumed
				a := bk.take(left, true)
				if a <= 0 {
					time.sleep(100 * time.millisecond)
					continue
				}
				bk.stat_pad(0, u64(a))
				consumed += a
			}
		}
		c.close() or {}
		wait := rand.int_in_range(500, 3000) or { 1000 }
		time.sleep(wait * time.millisecond)
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
			println('  [circuit] rotated')
		}
		c.close() or {}
	}
}

fn monitor(mut bk Bucket) {
	start := time.now()
	for {
		time.sleep(10 * time.second)
		rup, rdn, pup, pdn, reqs, pads, circuits, active := bk.snapshot()
		real := rup + rdn
		pad := pup + pdn
		total := real + pad
		pct := if total > 0 { f64(pad) * 100.0 / f64(total) } else { 0.0 }
		el := time.since(start)
		rate := if el.seconds() > 0 { total / u64(el.seconds()) } else { u64(0) }
		println('  [stat] rate=${fmtb(rate)}/s real=${fmtb(real)} pad=${fmtb(pad)} noise=${pct:.0}% conn=${active} reqs=${reqs} cover=${pads} circuits=${circuits}')
	}
}

fn handle(mut c net.TcpConn, mut bk Bucket) {
	defer { c.close() or {} }
	mut buf := []u8{len: 512}
	n := c.read(mut buf) or { return }
	if n < 1 || buf[0] != 5 {
		return
	}
	c.write([u8(5), 0]) or { return }
	nr := c.read(mut buf) or { return }
	if nr < 7 || buf[1] != 1 {
		return
	}
	mut host := ''
	mut port := 0
	mut off := 0
	match buf[3] {
		0x01 {
			if nr < 10 {
				return
			}
			host = '${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}'
			off = 8
		}
		0x03 {
			dl := int(buf[4])
			if nr < 5 + dl + 2 {
				return
			}
			host = buf[5..5 + dl].bytestr()
			off = 5 + dl
		}
		else { return }
	}
	port = int(buf[off]) << 8 | int(buf[off + 1])
	mut remote := tor(host, port) or { return }
	defer { remote.close() or {} }
	c.write([u8(5), 0, 0, 1, 0, 0, 0, 0, 0, 0]) or { return }
	bk.inc_reqs()
	relay(mut c, mut remote, mut bk)
}

fn fmtb(b u64) string {
	if b < 1024 {
		return '${b}B'
	}
	if b < 1048576 {
		return '${f64(b) / 1024:.1}K'
	}
	if b < 1073741824 {
		return '${f64(b) / 1048576:.1}M'
	}
	return '${f64(b) / 1073741824:.2}G'
}

fn main() {
	mut bw := 15
	mut streams := 3
	a := os.args[1..]
	mut i := 0
	for i < a.len {
		if a[i] == '-bw' && i + 1 < a.len {
			i++
			bw = a[i].int()
		}
		if a[i] == '-s' && i + 1 < a.len {
			i++
			streams = a[i].int()
		}
		if a[i] == '-h' {
			println('usage: timingless [-bw KB/s] [-s streams]')
			println('  -bw  constant bandwidth target (default 15)')
			println('  -s   cover stream count (default 3)')
			return
		}
		i++
	}

	println('timingless 1.0')
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
